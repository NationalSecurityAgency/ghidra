#!/usr/bin/env python3
"""Quick first-pass categorization of Rule applyOp implementations.
Reads /tmp/rule_list.tsv (file, line, name) and the .cc files; produces a markdown table."""

import os, re, sys

CPP_DIR = "/srv/project/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

# Mutation patterns: any of these in the body means "may mutate"
MUTATION_PATS = [
    r"\bdata\.op(Set|Unset|Destroy|Insert|Remove|Swap|Mark|Unlink|Uninsert|MarkHalt|MarkCpoolTransformed|MarkNoCollapse|MarkCalculatedBool|MarkSpacebase)\w*",
    r"\bdata\.newOp\b",
    r"\bdata\.new(Constant|Unique|Varnode|VarnodeOut|UniqueOut|VarnodeIop|VarnodeSpace|VarnodeCallSpecs|CodeRef|UniqueOut)\b",
    r"\bdata\.spacebaseConstant\b",
    r"\bdata\.totalReplaceConstant\b",
    r"\bdata\.fillinReadOnly\b",
    r"\bdata\.replaceVolatile\b",
    r"\bdata\.bumpIrModCount\b",
    r"\bdata\.bumpGlobalModCount\b",
    r"\bdata\.bumpTypeModCount\b",
    r"\bdata\.bumpVnCreateCount\b",
    r"\b(vn|op|invn|copyop|newvn|out|in|in1|in2|newop|cvn|sub)\b->set\w+\(",
    r"\b(vn|op|invn|copyop|newvn|out|in|in1|in2|newop|cvn|sub)\b->clear\w+\(",
    r"\b(vn|op|invn|copyop|newvn|out|in|in1|in2|newop|cvn|sub)\b->flip\w+\(",
]

# Side-effect calls that have mutations even when rule returns 0
SIDE_EFFECT_FAIL_PATS = [
    r"data\.opMarkNoCollapse\b",
    r"data\.opMarkCpoolTransformed\b",
    r"data\.deadRemovalAllowedSeen\b",
    r"->setPtrCheck\b",
    r"->setCpoolTransformed\b",
]

# Loop patterns (suggest Category B vs A)
LOOP_PATS = [
    r"\bfor\s*\(",
    r"\bwhile\s*\(",
]

def read_rule_body(filepath, start_line):
    """Read the body of an applyOp starting at start_line (1-based). Returns text up to next ^int4 ... or EOF."""
    path = os.path.join(CPP_DIR, filepath)
    with open(path) as f:
        lines = f.readlines()
    body = []
    brace_depth = 0
    started = False
    for i, line in enumerate(lines[start_line-1:], start=start_line):
        body.append(line)
        # Count braces to find end of function
        for c in line:
            if c == '{':
                brace_depth += 1
                started = True
            elif c == '}':
                brace_depth -= 1
        if started and brace_depth == 0:
            break
    return "".join(body)

def categorize(body):
    """Return (category, reasons)."""
    reasons = []

    # Check for side effects in failure path (Category C indicators)
    side_effects = []
    for pat in SIDE_EFFECT_FAIL_PATS:
        if re.search(pat, body):
            side_effects.append(pat.replace("\\b", "").replace("data\\.", ""))

    # Check for loops
    loops = sum(1 for pat in LOOP_PATS if re.search(pat, body))

    # Count mutation sites
    mutation_count = 0
    for pat in MUTATION_PATS:
        mutation_count += len(re.findall(pat, body))

    if side_effects:
        return ("C", f"side effects in fail path: {','.join(side_effects[:3])}")
    if mutation_count == 0:
        return ("A_NOOP", "no mutations found — verify rule does anything")
    if loops > 0 and mutation_count > 2:
        return ("B", f"loop + {mutation_count} mutation sites")
    return ("A", f"{mutation_count} mutation sites, no/simple loops")

def main():
    rules = []
    with open("/tmp/rule_list.tsv") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) == 3:
                rules.append(parts)

    by_cat = {"A": [], "B": [], "C": [], "A_NOOP": []}

    print("| Rule | File | Line | Category | Notes |")
    print("|------|------|-----:|----------|-------|")
    for fname, lineno, rname in rules:
        try:
            body = read_rule_body(fname, int(lineno))
            cat, reason = categorize(body)
        except Exception as e:
            cat = "?"
            reason = f"parse error: {e}"
        by_cat.setdefault(cat, []).append(rname)
        print(f"| {rname} | {fname} | {lineno} | {cat} | {reason} |")

    print()
    print("## Category totals")
    for cat, items in sorted(by_cat.items()):
        print(f"- **{cat}**: {len(items)} rules")

if __name__ == "__main__":
    main()
