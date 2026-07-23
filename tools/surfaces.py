#!/usr/bin/env python3
"""surfaces.py — extract each leaf's compose-friendly public surface.

WHY: WAREHOUSE-AND-LENS.md says composition search should "search the warehouse for
compose-friendly public surfaces (seal / verify / mint)". With 33 leaves that is not a
reading task, it is an extraction task. This prints the raw table; ranking is a human act.

Classification (deliberately shallow — a regex over `pub` items, not a type checker):

  SEALED   a `pub struct` whose every field is private  → a witness only its leaf can mint
  WIRE     a `pub struct` with at least one `pub` field → crosses a process boundary
  MINT     a `pub fn` returning a SEALED type           → the sole doorway into a witness
  TAKES    a `pub fn` accepting a SEALED type           → a consumer that demands evidence
  IN/OUT   plain seam types (&[u8], Vec<u8>, u64, [u8;N]) on a public fn

A composition A ∘ B is *mechanically plausible* when B has a MINT whose inputs A can
supply, and implausible-but-glue when the only shared vocabulary is bytes.

Usage:  tools/surfaces.py            (table)
        tools/surfaces.py --json     (machine-readable)

There is deliberately no `--pairs` ranker. Every leaf accepts `&[u8]`, so a mechanical pair
score would rank all 528 unordered leaf pairs as plausible and mean nothing. Extraction is
the machine's job; the reaction to attempt is a judgement, and then the COMPILER scores it.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAIN = {"u64", "u32", "usize", "u8", "bool", "String"}
SEAM_RE = re.compile(r"&\[u8\]|Vec<u8>|\[u8; *\d+\]|\bu64\b|\bDigest\b|\bThreshold\b")


def members():
    txt = (ROOT / "Cargo.toml").read_text()
    body = re.search(r"members\s*=\s*\[(.*?)\]", txt, re.S).group(1)
    return [m for m in re.findall(r'"([^"]+)"', body)]


def struct_blocks(src):
    """Yield (name, body) for each `pub struct Name ... { ... }` (brace-counted)."""
    for m in re.finditer(r"^pub struct ([A-Za-z0-9_]+)[^;{]*\{", src, re.M):
        i = src.index("{", m.end() - 1)
        depth, j = 0, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield m.group(1), src[i + 1 : j]


def scan(crate):
    d = ROOT / crate / "src"
    if not d.is_dir():
        return None
    src = "\n".join(p.read_text() for p in sorted(d.rglob("*.rs")))
    # strip doc comments: they are full of example code that would pollute every count
    src = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("//"))

    sealed, wire = [], []
    for name, body in struct_blocks(src):
        fields = [l for l in body.splitlines() if re.match(r"\s*(pub )?[a-z_0-9]+\s*:", l)]
        if not fields:
            wire.append(name)  # unit/marker struct: nothing to hide
        elif any(re.match(r"\s*pub ", l) for l in fields):
            wire.append(name)
        else:
            sealed.append(name)

    fns = re.findall(r"^\s*pub fn ([A-Za-z0-9_]+)\s*(?:<[^>]*>)?\(([^)]*)\)\s*(->\s*[^{]+)?\{", src, re.M)
    mint, takes, bytes_in, bytes_out = [], [], [], []
    for name, args, ret in fns:
        ret = (ret or "").replace("->", "").strip()
        for s in sealed:
            if re.search(rf"\b{s}\b", ret):
                mint.append(f"{name} -> {s}")
            if re.search(rf"\b{s}\b", args):
                takes.append(f"{name}({s})")
        if SEAM_RE.search(args):
            bytes_in.append(name)
        if SEAM_RE.search(ret):
            bytes_out.append(name)

    return {
        "crate": crate,
        "sealed": sorted(set(sealed)),
        "wire": sorted(set(wire)),
        "mint": sorted(set(mint)),
        "takes": sorted(set(takes)),
        "bytes_in": sorted(set(bytes_in)),
        "bytes_out": sorted(set(bytes_out)),
        "deps": sorted(
            set(re.findall(r"^([a-z0-9-]+)\s*=", (ROOT / crate / "Cargo.toml").read_text(), re.M))
        ),
    }


def main():
    data = [s for c in members() if (s := scan(c))]
    if "--json" in sys.argv:
        print(json.dumps(data, indent=2))
        return
    print(f"{'crate':22} {'sealed':>6} {'wire':>5} {'mint':>5} {'takes':>6}  minters")
    print("-" * 100)
    for s in data:
        print(
            f"{s['crate']:22} {len(s['sealed']):>6} {len(s['wire']):>5} "
            f"{len(s['mint']):>5} {len(s['takes']):>6}  {', '.join(s['mint'])[:44]}"
        )
    print(f"\n{len(data)} crates scanned")


main()
