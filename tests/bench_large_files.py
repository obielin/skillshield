"""Time each rule on large inputs.

This is a benchmark, not a test: pytest only collects ``test_*.py``, so the normal
suite never runs it. Run it by hand before and after a change to a rule and paste
both tables into the PR:

    python tests/bench_large_files.py
    python tests/bench_large_files.py --repeat 5 --rules SG-003,SG-011

It builds two inputs in memory:

* a pretty-printed MCP tool listing with 10,000 tools (about 4 MB, 180,000 lines,
  the shape described in the issue)
* a large Markdown file of ordinary skill documentation of about the same size

Both are benign, so every rule takes its no-match path over the whole text, which
is the cost a CI run pays on a clean file. Each time is the best of ``--repeat``
runs, which hides one-off noise from the machine.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path
from typing import Callable

try:
    from skillshield import SkillScanner
except ImportError:  # running from a checkout without an install
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from skillshield import SkillScanner

from skillshield.mcp import parse_listing
from skillshield.rules import ALL_RULES, Rule

VERBS = ["Read", "List", "Fetch", "Create", "Update", "Search", "Summarise", "Export"]
NOUNS = ["file", "issue", "record", "invoice", "message", "ticket", "report", "event"]


def build_tool_listing(count: int) -> str:
    """Return a pretty-printed MCP ``tools/list`` result with ``count`` tools."""
    tools = []
    for i in range(count):
        verb = VERBS[i % len(VERBS)]
        noun = NOUNS[(i // len(VERBS)) % len(NOUNS)]
        tools.append(
            {
                "name": f"{verb.lower()}_{noun}_{i}",
                "description": f"{verb} a {noun} by its ID and return it as JSON.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}, "limit": {"type": "integer"}},
                },
                "annotations": {"readOnlyHint": verb in ("Read", "List", "Fetch", "Search")},
            }
        )
    return json.dumps({"tools": tools}, indent=2) + "\n"


MARKDOWN_SECTION = """\
## Step {n}: prepare the {noun} report

Open the project folder and look for the {noun} files listed in `config.yaml`.
Each entry has a name, an owner and a due date. Group the entries by owner, then
sort each group by due date so the oldest work comes first.

- Skip entries marked `archived: true`.
- Keep the original order when two entries share a due date.
- Write the result to `reports/{noun}-{n}.md` and link it from the index.

```python
def group_by_owner(entries):
    groups = {{}}
    for entry in entries:
        groups.setdefault(entry["owner"], []).append(entry)
    return {{owner: sorted(items, key=lambda e: e["due"]) for owner, items in groups.items()}}
```

See the [style guide](docs/style.md#reports) for headings and table layout.

"""


def build_markdown(target_bytes: int) -> str:
    """Return a SKILL.md-style document of roughly ``target_bytes`` bytes."""
    parts = ["---\nname: weekly-reports\ndescription: Build the weekly team reports.\n---\n\n"]
    parts.append("# Weekly reports\n\nThis skill turns the project files into weekly reports.\n\n")
    size = sum(len(p) for p in parts)
    n = 0
    while size < target_bytes:
        section = MARKDOWN_SECTION.format(n=n, noun=NOUNS[n % len(NOUNS)])
        parts.append(section)
        size += len(section)
        n += 1
    return "".join(parts)


def best_of(fn: Callable[[], object], repeat: int) -> float:
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def bench_input(label: str, text: str, suffix: str, rules: list[Rule], repeat: int) -> None:
    size_mb = len(text.encode("utf-8")) / 1_000_000
    lines = text.count("\n")
    print(f"\n## {label}: {size_mb:.2f} MB, {lines:,} lines\n")

    listing = parse_listing(text, suffix) if suffix else None
    if suffix == ".json":
        print(f"json.loads:     {best_of(lambda: json.loads(text), repeat):.3f} s")
        print(f"parse_listing:  {best_of(lambda: parse_listing(text, suffix), repeat):.3f} s")
        print()

    rows = []
    for rule in rules:
        seconds = best_of(lambda: rule.match(text), repeat)
        if listing is not None and rule.listing_fn is not None:
            seconds += best_of(lambda: rule.match_listing(listing), repeat)
        rows.append((rule.id, rule.name, seconds))

    print(f"| {'Rule':<7} | {'Name':<46} | {'Time (s)':>8} |")
    print(f"|{'-' * 9}|{'-' * 48}|{'-' * 10}|")
    for rule_id, name, seconds in sorted(rows, key=lambda r: r[2], reverse=True):
        print(f"| {rule_id:<7} | {name[:46]:<46} | {seconds:>8.3f} |")
    print(f"| {'':<7} | {'Sum of rules':<46} | {sum(r[2] for r in rows):>8.3f} |")

    scanner = SkillScanner(rules=rules)
    total = best_of(lambda: scanner.scan_text(text, name=label, listing=listing), repeat)
    print(f"\nFull scan_text (all selected rules): {total:.3f} s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tools", type=int, default=10_000, help="tools in the listing")
    parser.add_argument("--repeat", type=int, default=3, help="runs per timing; best is kept")
    parser.add_argument("--rules", default="", help="comma-separated rule IDs (default: all)")
    args = parser.parse_args(argv)

    rules = ALL_RULES
    if args.rules:
        wanted = {r.strip().upper() for r in args.rules.split(",") if r.strip()}
        rules = [r for r in ALL_RULES if r.id in wanted]
        missing = wanted - {r.id for r in rules}
        if missing:
            parser.error(f"unknown rule IDs: {', '.join(sorted(missing))}")

    version = f"Python {platform.python_version()}, {platform.machine()}"
    print(f"# SkillShield rule benchmark ({version})")
    print(f"Best of {args.repeat} runs per timing.")

    listing_text = build_tool_listing(args.tools)
    listing_label = f"MCP tool listing, {args.tools:,} tools"
    bench_input(listing_label, listing_text, ".json", rules, args.repeat)

    markdown_text = build_markdown(len(listing_text))
    bench_input("Markdown skill file", markdown_text, "", rules, args.repeat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
