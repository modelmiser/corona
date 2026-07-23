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

# Snapshot the lockfile BEFORE cargo runs. `cargo test` rewrites Cargo.lock to match the
# manifests, so a manifest/lock divergence is REPAIRED by the time a later check could see it.
# Caught by watching the manifest-vs-lock check below fail on purpose: it didn't (round 6).
lock_pre=$(mktemp); trap 'rm -f "$lock_pre"' EXIT
[ -f Cargo.lock ] && cp Cargo.lock "$lock_pre"

# ---------------------------------------------------------------- TEST COUNTS
say "test counts (README claim vs cargo)"
out=$(cargo test --workspace 2>&1); rc=$?
unit=$(printf '%s' "$out" | grep -oE '^test result: ok\. [0-9]+ passed' | grep -oE '[0-9]+' | paste -sd+ | bc)
suites=$(printf '%s' "$out" | grep -cE '^test result: ' || true)
# README states "N unit tests + M doctests"
r_unit=$(grep -oE '[0-9]+ unit tests \+ [0-9]+ doctests' README.md | grep -oE '^[0-9]+' | head -1)
r_doc=$(grep -oE '[0-9]+ unit tests \+ [0-9]+ doctests' README.md | grep -oE '\+ [0-9]+' | grep -oE '[0-9]+' | head -1)
m_doc=$(printf '%s' "$out" | awk '/Doc-tests/{d=1} d&&/^test result: ok\./{s+=$4} END{print s+0}')
m_unit=$((unit - m_doc))
cmp_n "README unit-test count"    "$r_unit" "$m_unit"
cmp_n "README doctest count"      "$r_doc"  "$m_doc"
# Round 6 (2026-07-23): this was `grep -q '^test result: FAILED'` and NOTHING else — so it
# reported `ok` on a workspace that DOES NOT COMPILE, because a compile error never emits that
# line, `$?` was discarded, and `set -uo pipefail` carries no `-e`. The one check asserting the
# code works was the one check that survived the code not existing. Judge on cargo's EXIT
# STATUS, and require the run to have produced suites at all: a zero-suite run is not a pass.
if [ "$rc" -ne 0 ]; then
  bad "all tests pass" "exit 0" "cargo exit $rc"
  printf '%s\n' "$out" | grep -E '^error(\[|:)' | head -5 | sed 's/^/          /'
elif printf '%s' "$out" | grep -q '^test result: FAILED'; then bad "all tests pass" "pass" "FAILED"
elif [ "$suites" -eq 0 ]; then bad "all tests pass" ">0 suites" "0 suites ran"
else ok "all tests pass" "$unit in $suites suites"; fi

# ---------------------------------------------------------------- CRATE COUNT
say "crate inventory (docs vs Cargo.toml members)"
member_names=$(python3 - <<'PY'
import re
s=open('Cargo.toml').read()
m=re.search(r'members\s*=\s*\[(.*?)\]', s, re.S)
print('\n'.join(sorted(re.findall(r'"([^"]+)"', m.group(1)))))
PY
)
members=$(printf '%s\n' "$member_names" | grep -c .)
# Round 6: this was `ok "workspace members" "$members"` — a ONE-ARGUMENT call that prints a
# number and compares it to nothing. Four more like it sat in the version loop below: five of
# the nineteen "verified claims" could not fail, i.e. 26% of the headline figure was a print
# statement. Compare something: every declared member must be a directory with a manifest.
missing=$(for m in $member_names; do [ -f "$m/Cargo.toml" ] || printf '%s ' "$m"; done)
if [ -z "$missing" ]; then ok "every workspace member has a manifest" "$members"
else bad "every workspace member has a manifest" "$members" "missing: $missing"; fi

# The CHARTER registry must have a row per workspace member. This was a DEAD variable for
# months: computed into `charter_rows` and never compared, so nothing guarded the registry
# while three separate ordinal claims drifted (round 4, 2026-07-23). Its old pattern also
# measured 33 against 34 members, because `numerical-accuracy` does not end in `-types` —
# an instrument that would have failed if it had ever been read.
#
# Round 6: comparing COUNTS is blind to identity and to multiplicity. Deleting the `vss-types`
# row and duplicating the `deadline-types` row kept the count equal and the whole script green,
# with one workspace member carrying no registry row at all. sol's scoreboard check already used
# `comm -3` for exactly this reason; corona did not. Compare the NAME SETS.
charter_names=$(grep -oE '^\| *`?[a-z0-9-]+`? *\| *(research \(toy\)|\*\*graduated\*\*) *\|' CHARTER.md \
                | grep -oE '`?[a-z0-9-]+`? *\|' | head -c-1 | tr -d '`| ' | sort)
charter_rows=$(printf '%s\n' "$charter_names" | grep -c .)
cmp_n "CHARTER registry rows == workspace leaves" "$charter_rows" "$((members - 1))"
dupes=$(printf '%s\n' "$charter_names" | uniq -d | tr '\n' ' ')
if [ -z "$dupes" ]; then ok "CHARTER registry rows are distinct" "0 dupes"
else bad "CHARTER registry rows are distinct" "0 dupes" "$dupes"; fi
leaf_names=$(printf '%s\n' "$member_names" | grep -v '^corona-core$' | sort)
diff_names=$(comm -3 <(printf '%s\n' "$charter_names" | uniq) <(printf '%s\n' "$leaf_names") | tr -d '\t' | tr '\n' ' ')
if [ -z "${diff_names// /}" ]; then ok "CHARTER registry names == workspace leaves" "$((members - 1)) names"
else bad "CHARTER registry names == workspace leaves" "identical sets" "differ: $diff_names"; fi

# Graduation bookkeeping: the count of `**graduated**` rows, the ordinal the newest row
# claims, and the numbered narrative ("The **first**… **tenth**") must agree. Round 4 found
# the narrative one entry short of the registry with no instrument to catch it.
grad_rows=$(grep -cE '^\| *`?[a-z0-9-]+`? *\| *\*\*graduated\*\* *\|' CHARTER.md || true)
ordinals="first second third fourth fifth sixth seventh eighth ninth tenth eleventh twelfth"
narrative=0
for o in $ordinals; do
  grep -qE "^The \*\*$o\*\*|^The \*\*$o leaf-level\*\*" CHARTER.md && narrative=$((narrative+1)) || break
done
cmp_n "graduated rows == numbered narrative entries" "$grad_rows" "$narrative"
# Every "(Nth graduation" claim must be <= the number of graduated rows. Round 6: `<=` alone
# admits DUPLICATES (two rows both claiming 10th, none claiming 9th, still green) and the
# `sort -un` that fed this loop deduped them out of sight. The ordinals are supposed to be a
# numbering, so check that: distinct, and topping out at exactly the graduated-row count.
ord_raw=$(grep -ohE '\(([0-9]+)(st|nd|rd|th) graduation' CHARTER.md | grep -oE '[0-9]+' | sort -n)
ord_n=$(printf '%s\n' "$ord_raw" | grep -c .)
for c in $(printf '%s\n' "$ord_raw" | sort -un); do
  [ "$c" -le "$grad_rows" ] && ok "ordinal '${c}th graduation' <= graduated rows" "$c <= $grad_rows" \
                            || bad "ordinal '${c}th graduation'" "<= $grad_rows" "$c"
done
ord_dupes=$(printf '%s\n' "$ord_raw" | uniq -d | tr '\n' ' ')
if [ -z "$ord_dupes" ]; then ok "graduation ordinals are distinct" "$ord_n claims"
else bad "graduation ordinals are distinct" "0 dupes" "$ord_dupes"; fi
cmp_n "highest graduation ordinal == graduated rows" "$(printf '%s\n' "$ord_raw" | tail -1)" "$grad_rows"
# leaf-count claims in prose must equal members-1 (corona-core is not a leaf)
# CANONICAL docs only. TODO/DEVLOG/INSIGHTS are append-only logs: a past-tense count in a
# dated entry is correct BECAUSE it was true then. Only present-tense assertions can drift.
#
# Round 6, the VANISHING-CLAIM defect: these loops iterate over whatever the pattern matched, so
# a claim that stops matching (someone bolds the number, rewords the noun) silently leaves the
# denominator and the script prints a SMALLER total, green, exit 0 — with a wrong number shipped.
# The nightly branch below already treats a non-result as a SKIP rather than a pass; these loops
# lied the other way. Each now declares how many claims it EXPECTS to find, so a claim going
# missing fails instead of shrinking the score.
leaf_claims=$(grep -rhoE 'corona-core \+ \*{0,2}[0-9]+ leaves\*{0,2}' README.md CHARTER.md COMPOSITION-SEARCH.md 2>/dev/null | grep -oE '[0-9]+')
cmp_n "prose 'corona-core + N leaves' claims found" "$(printf '%s\n' "$leaf_claims" | grep -c .)" "1"
for c in $leaf_claims; do
  cmp_n "prose 'corona-core + N leaves'" "$c" "$((members-1))"
done
# COMPOSITION-SEARCH states how many leaf pairs exist, to make its coverage legible. That
# is a DERIVED number: it must stay C(leaves,2), not merely be a number someone once wrote.
leaves=$((members - 1))
# Match EVERY phrasing, not the one I happened to write first: a retired number survived a
# rewrite as "three of 561 pairs" because the pattern only knew "N unordered leaf pairs".
pair_claims=$(grep -rhoE '\*{0,2}[0-9]+\*{0,2} (unordered )?(leaf )?pairs' COMPOSITION-SEARCH.md tools/surfaces.py 2>/dev/null | grep -oE '[0-9]+')
cmp_n "prose 'N ... pairs' claims found" "$(printf '%s\n' "$pair_claims" | grep -c .)" "3"
for c in $pair_claims; do
  cmp_n "prose 'N ... pairs' == C(leaves,2)" "$c" "$((leaves * (leaves - 1) / 2))"
done

# ---------------------------------------------------------------- VERSIONS
say "version claims"
# Round 6: this loop was four one-argument `ok` calls over a HARDCODED list — it read each
# version and compared it to nothing (setting one to 999.999.999 printed `ok` and kept 19/19),
# and it did not include `accumulator-types`, the leaf actually being graduated. Compare each
# member's manifest version against the lockfile, over every member: that is a real claim, and
# it is the one that was WRONG in this arc (compose-probes' lock pinned 0.1.0 after the bump).
lockmis=$(LOCK_PRE="$lock_pre" python3 - <<'PY'
import os, re, pathlib
lock = pathlib.Path(os.environ['LOCK_PRE'])
locked = {}
if lock.exists():
    for blk in lock.read_text().split('[[package]]'):
        n = re.search(r'^name = "([^"]+)"', blk, re.M)
        v = re.search(r'^version = "([^"]+)"', blk, re.M)
        if n and v:
            locked[n.group(1)] = v.group(1)
s = pathlib.Path('Cargo.toml').read_text()
m = re.search(r'members\s*=\s*\[(.*?)\]', s, re.S)
bad = []
for name in re.findall(r'"([^"]+)"', m.group(1)):
    p = pathlib.Path(name) / 'Cargo.toml'
    if not p.exists():
        continue
    mv = re.search(r'^version\s*=\s*"([^"]+)"', p.read_text(), re.M)
    if not mv:
        bad.append(f'{name}:no-version')
    elif name in locked and locked[name] != mv.group(1):
        bad.append(f'{name}:toml={mv.group(1)}!=lock={locked[name]}')
print(' '.join(bad))
PY
)
if [ -z "$lockmis" ]; then ok "manifest versions == Cargo.lock" "$members members"
else bad "manifest versions == Cargo.lock" "identical" "$lockmis"; fi

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

  # The garden pins its compile-fail evidence with ```compile_fail,EXXXX fences.
  # On STABLE, rustdoc parses that code and IGNORES it: a fence reading
  # E0599 passes on a snippet failing E0382 (mutation-tested). Only nightly enforces it.
  # Found one live mismatch on first run (vid-types claimed E0451 on a snippet whose real
  # diagnostic is the UNCODED "cannot construct ... due to private fields").
  if rustup toolchain list 2>/dev/null | grep -q '^nightly-'; then
    cargo +nightly test --workspace --doc --no-fail-fast >/tmp/nightlydoc 2>&1 \
      && ok "doctest error-code fences (nightly enforces)" "all match" \
      || bad "doctest error-code fences" "all match" \
             "$(grep -m1 'expected error codes' /tmp/nightlydoc || echo 'see /tmp/nightlydoc')"
  else
    # Deliberately does NOT increment `checks`: a skipped check must not be counted as a
    # verified one in the "N/N claims verified" line, or the checker lies about itself.
    printf '  SKIP  %-52s %s\n' "doctest error-code fences" "no nightly toolchain — codes UNCHECKED"
  fi
fi

say ""
say "$((checks-fails))/$checks claims verified"
[ "$fails" -eq 0 ] || { say "FAILED: $fails"; exit 1; }
