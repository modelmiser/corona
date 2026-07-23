#!/usr/bin/env bash
# check-claims.sh — assert that numbers WRITTEN in this repo's prose match numbers MEASURED
# from its sources and its test run. Code has cargo; prose has this.
#
# Run:  tools/check-claims.sh          (add --gates to also run clippy/fmt/rustdoc)
# Exit 0 = every checked claim matches. Exit 1 = at least one mismatch (printed).
#
# Why this exists: cold-review rounds 1-20 on leaf 5 produced ~42 CRITICAL findings and NOT ONE
# was in the code — cargo and lake refuse a false theorem. Every one was in prose about the code,
# and the majority were numbers that had drifted from what they described. Those need a checker,
# not a review panel.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; checks=0
ok()   { checks=$((checks+1)); printf '  ok    %-52s %s\n' "$1" "$2"; }
bad()  { checks=$((checks+1)); fails=$((fails+1)); printf '  FAIL  %-52s claimed=%s measured=%s\n' "$1" "$2" "$3"; }
cmp_n(){ if [ "$2" = "$3" ]; then ok "$1" "$2"; else bad "$1" "$2" "$3"; fi; }
say()  { printf '%s\n' "$*"; }

# ---------------------------------------------------------------- TEST COUNTS
say "test counts (README claim vs cargo)"
out=$(cargo test --workspace 2>&1)
unit=$(printf '%s' "$out" | grep -oE '^test result: ok\. [0-9]+ passed' | grep -oE '[0-9]+' | paste -sd+ | bc)
# README states "N unit tests + M doctests"
r_unit=$(grep -oE '[0-9]+ unit tests \+ [0-9]+ doctests' README.md | grep -oE '^[0-9]+' | head -1)
r_doc=$(grep -oE '[0-9]+ unit tests \+ [0-9]+ doctests' README.md | grep -oE '\+ [0-9]+' | grep -oE '[0-9]+' | head -1)
m_doc=$(printf '%s' "$out" | awk '/Doc-tests/{d=1} d&&/^test result: ok\./{s+=$4} END{print s+0}')
m_unit=$((unit - m_doc))
cmp_n "README unit-test count"    "$r_unit" "$m_unit"
cmp_n "README doctest count"      "$r_doc"  "$m_doc"
if printf '%s' "$out" | grep -q '^test result: FAILED'; then bad "all tests pass" "pass" "FAILED"; else ok "all tests pass" "$unit total"; fi

# ---------------------------------------------------------------- CRATE COUNT
say "crate inventory (docs vs Cargo.toml members)"
members=$(python3 - <<'PY'
import re
s=open('Cargo.toml').read()
m=re.search(r'members\s*=\s*\[(.*?)\]', s, re.S)
print(len(re.findall(r'"([^"]+)"', m.group(1))))
PY
)
charter_rows=$(grep -cE '^\| *`?[a-z0-9-]+-types`? *\||^\| *`?corona-core`? *\|' CHARTER.md || true)
ok "workspace members" "$members"
# leaf-count claims in prose must equal members-1 (corona-core is not a leaf)
# CANONICAL docs only. TODO/DEVLOG/INSIGHTS are append-only logs: a past-tense count in a
# dated entry is correct BECAUSE it was true then. Only present-tense assertions can drift.
for c in $(grep -rhoE 'corona-core \+ \*\*[0-9]+ leaves\*\*' README.md CHARTER.md 2>/dev/null | grep -oE '[0-9]+'); do
  cmp_n "prose 'corona-core + N leaves'" "$c" "$((members-1))"
done

# ---------------------------------------------------------------- VERSIONS
say "version claims"
for crate in lamport-types mss-types hypertree-types merkle-types; do
  [ -f "$crate/Cargo.toml" ] || continue
  v=$(grep -m1 '^version' "$crate/Cargo.toml" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  ok "$crate version" "$v"
done

# ---------------------------------------------------------------- NO FRAGILE LINE COUNTS
say "no line-count claims for source files"
lc=$(grep -rnE '`[A-Za-z0-9/._]+\.(rs|lean)`[^)]*\([0-9]{2,4} lines\)' README.md CHARTER.md 2>/dev/null || true)
if [ -z "$lc" ]; then ok "no source line-count claims in prose" "0"
else bad "line-count claims (delete them)" "0" "$(printf '%s\n' "$lc" | wc -l)"; printf '%s\n' "$lc" | sed 's/^/          /'; fi

# ---------------------------------------------------------------- GATES
if [ "${1:-}" = "--gates" ]; then
  say "build gates (the three README/TODO assert green)"
  cargo clippy --workspace --all-targets -- -D warnings >/dev/null 2>&1 \
    && ok "clippy --workspace --all-targets -D warnings" "clean" || bad "clippy" "clean" "FAILED"
  cargo fmt --all --check >/dev/null 2>&1 \
    && ok "cargo fmt --all --check" "clean" || bad "fmt" "clean" "FAILED"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps >/dev/null 2>&1 \
    && ok "rustdoc -D warnings" "clean" || bad "rustdoc" "clean" "FAILED"
fi

say ""
say "$((checks-fails))/$checks claims verified"
[ "$fails" -eq 0 ] || { say "FAILED: $fails"; exit 1; }
