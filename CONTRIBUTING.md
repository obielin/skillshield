# Contributing to SkillShield

Thanks for helping. SkillShield scans AI agent skills for prompt injection, data exfiltration and malicious payloads before people install them. Every rule you add or sharpen protects everyone who runs it.

Please read this whole page before you open a pull request. The pull request template asks you to confirm that you have.

## Why contribute here

- **The scope is small and the code is readable.** Five modules, no runtime dependencies, and a test suite that runs in under a second. You can understand the whole project in an afternoon.
- **Rules are a natural first contribution.** Each rule is one self-contained block in `src/skillshield/rules.py` with its own tests, so a new rule rarely touches anything else.
- **Every PR gets a human review.** A maintainer reads each one by hand. You will get specific feedback, not a bot verdict.
- **You get credit.** Merged work is credited to you in [CHANGELOG.md](CHANGELOG.md), and regular contributors take on more of the project over time (see the [contributor ladder](GOVERNANCE.md#contributor-ladder)).

## Before you open a pull request

**Open an issue first** for:

- a new detection rule (use the **New rule proposal** form);
- a change to how scoring or risk levels work;
- a new output format, command or option;
- anything that would add a dependency.

These change what every user sees, so it is worth agreeing on the approach before you write code. Opening an issue first is about scope, never a judgement on your work.

**Go straight to a pull request** for:

- bug fixes;
- fixes for a false positive or a missed detection in an existing rule;
- tests;
- documentation.

If an issue already exists, link it in your PR with `Fixes #123`.

### What makes a good pull request

- It does one thing. Two unrelated fixes are two PRs.
- The description says what was wrong, what you changed and how you checked it.
- It includes a test that fails without your change and passes with it.
- It follows the existing code style (Black and Ruff, line length 100).

## Quick start

1. Fork the repository.
2. Clone your fork.
3. Create a branch: `git checkout -b fix/short-description`.
4. Install the development dependencies: `pip install -e ".[dev]"`.
5. Make your change.
6. Run the checks (see [Running the checks](#running-the-checks)).
7. Commit and push to your fork.
8. Open a pull request against `main`.

## Running the checks

CI runs these on every pull request. Run them locally first:

```bash
pytest
ruff check src tests
black --check src tests
```

CI runs `pytest` on Python 3.10, 3.11 and 3.12, and `ruff` and `black` on Python 3.11. On your first pull request, CI waits for a maintainer to approve the run. If it looks stuck, that queue is on us.

## Adding or changing a detection rule

Rules live in `src/skillshield/rules.py`. Each rule is a `Rule` with these fields:

| Field | What it holds |
|---|---|
| `id` | The next free ID, for example `SG-013`. IDs are never reused or renumbered, because people suppress findings by ID. |
| `name` | A short name, for example `Prompt Injection`. |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO`. |
| `description` | What the rule detects and why it matters. Cite the source of the technique. |
| `remediation` | What a skill author should do instead. |
| `pattern` or `check_fn` | A compiled regex, or a function that returns the matched snippets. Use `check_fn` when a regex alone would give too many false positives. |
| `tags` | Lower-case tags, including any OWASP IDs (for example `owasp-asi01`). |

Add the new rule to `ALL_RULES` at the bottom of the file, and add it to the rules table in the README.

A new rule needs:

1. **A reference.** A published report, advisory, CVE or OWASP entry showing that the technique is used or proposed. Link it in the issue and the PR.
2. **At least three tests** in `tests/test_skillshield.py`: two true positives that are worded differently, and one true negative.
3. **A near-miss test.** A benign skill that uses similar words for a legitimate reason, which the rule must not flag. False positives are the fastest way to make people stop running a scanner.
4. **Remediation text** that tells a skill author what to do.

Changing an existing rule follows the same bar: add a test for the case you are fixing, and keep the existing tests passing.

### Rules must stay explainable

Every finding names its rule and shows the matched text, so a person can check it. Rules that return a verdict without a matched snippet will not be accepted.

## Test samples must be safe

This repository holds examples of attacks, so treat samples with care:

- **No working payloads.** Defang anything that would run or connect: use `example.com`, `example.org` or documentation IP addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **No real secrets.** Use obviously fake keys such as `sk-test-000000`.
- **No live malicious URLs, domains or wallet addresses**, even from a real campaign. Describe the pattern instead.
- **No code copied from a real malicious skill** beyond the short phrase the rule matches.

A PR that breaks these rules will be asked to change the samples before review continues.

## Automated review

[CodeRabbit](https://www.coderabbit.ai) reviews each pull request to `main` and posts a summary and comments, usually within a few minutes. Draft pull requests are reviewed once you mark them ready for review, and pull requests from Dependabot and GitHub Actions are not reviewed. It may add the `quality-check` label to a PR that looks low-effort or machine-generated, which only means a maintainer reads it first. Its comments are suggestions: a maintainer reads every PR and makes the decision. You can reply to it, or ask it a question by mentioning `@coderabbitai` in a comment on your PR.

## Claiming an issue

Comment `/assign` on an open issue and it is assigned to you straight away. No need to wait for a maintainer. The other commands are `/unassign` to let an issue go, and `/extend` if you need more time.

How it stays fair:

- **`good first issue` is for newcomers.** You can claim one if you haven't had a pull request merged here yet, one at a time. After your first merged PR, the [`help wanted`](https://github.com/obielin/skillshield/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) issues are yours.
- **Up to three open claims at once** for everyone.
- **Claims free up on their own.** After 10 days with no activity from you, you get a friendly reminder; after 14 days, the issue is released for someone else. Any comment from you counts as activity, `/extend` resets the clock, and an open pull request that mentions the issue pauses it.
- **Tracking issues** (labelled `roadmap`) are not claimed themselves: claim one of the issues they list.

A pull request on an unassigned issue is always welcome, no claim needed.

## Someone else's open pull request stays theirs

Please do not open a pull request that redoes or rebases someone else's open PR. Landing a replacement closes theirs, and they lose the merged badge for work they did.

If you spot a problem in someone else's PR, say so in a review comment. If a PR goes into conflict because of something a maintainer merged, the maintainer will ask the author to rebase, or rebase it for them.

## Adopting an abandoned pull request

If a PR has had a review and no reply from its author for 30 days, a maintainer may close it with thanks and open an issue labelled `adoptable` that links to the branch and lists what is left.

To adopt it, open a new PR that keeps the original commits, so git keeps the author's credit, or add a `Co-authored-by:` trailer for them. The original author can reclaim the work at any point before the new PR is merged.

## AI-assisted contributions

You may use AI tools to help write code, tests or descriptions. You are still the author:

- you must understand every line you submit and be able to answer questions about it;
- you must have run the checks yourself;
- the PR description must describe what you checked, not what a tool claims.

Pull requests that read as unreviewed tool output will be closed.

## What we do not accept

- **Runtime dependencies.** SkillShield has none, and that is a feature. Development tools in `[dev]` are fine.
- **Network calls during a scan**, including telemetry. A scan must work offline and must never send skill contents anywhere.
- **Detection that depends on an external AI service in the default scan.** An optional, opt-in mode can be discussed in an issue first.
- **Working malware or live malicious infrastructure** in tests or examples (see [Test samples must be safe](#test-samples-must-be-safe)).
- **Changes to existing rule IDs.**

## Security issues

Do not open a public issue for a vulnerability in SkillShield itself. See [SECURITY.md](SECURITY.md) for how to report it privately, and for what counts as a vulnerability rather than a missed detection.

## Getting help

- [SUPPORT.md](SUPPORT.md) lists where to ask what.
- Read the [Code of Conduct](CODE_OF_CONDUCT.md) before you join in.
