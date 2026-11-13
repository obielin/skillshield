# Governance

## Overview

SkillShield is led by [@obielin](https://github.com/obielin), who has the final say on direction, rules and releases. There is a clear path for contributors to take on more responsibility over time.

The goal is a project that keeps working when the lead maintainer is busy: decisions are written down, and the people who review and merge are named in [MAINTAINERS.md](MAINTAINERS.md).

## Decision making

| Change | How it is decided |
|---|---|
| Bug fixes, false-positive fixes, tests, docs | Send a pull request. A maintainer reviews and merges. |
| New detection rules | An issue first (New rule proposal), then a pull request once the approach is agreed. |
| Scoring, risk levels, output formats, CLI changes | An issue first. The lead maintainer decides. |
| Dependencies, network access, the zero-dependency promise | The lead maintainer decides, after discussion in an issue. |
| Releases | A maintainer publishes a release. Releases follow [semantic versioning](https://semver.org/). |

A pull request is merged when a maintainer has reviewed it and any changes they asked for are in. Passing checks are required but are not approval on their own. What happens after a review, including when a maintainer may make small fixes to a contributor's branch, is described in [CONTRIBUTING.md](CONTRIBUTING.md#after-your-pull-request-is-reviewed).

## Contributor ladder

This is the one place the ladder is written down. [MAINTAINERS.md](MAINTAINERS.md) lists who holds each role today.

Roles are earned through sustained, good-quality contributions. You do not need to apply.

### Participant

Everyone starts here.

- Follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Opens issues, reports false positives and missed detections, and comments on pull requests.

### Contributor

Earned with your first merged pull request.

- Credited in [CHANGELOG.md](CHANGELOG.md) for the release that ships your work.
- No longer eligible for `good first issue`, so it stays open for newcomers. `help wanted` is yours.

### Regular contributor

Earned with your third merged pull request.

- Listed in [MAINTAINERS.md](MAINTAINERS.md).
- Can be asked to review pull requests in areas you know. Your review is a valued signal, and a maintainer still approves and merges.
- Asked for input on new rules and roadmap items before decisions are made.

### Maintainer

By invitation, after sustained contributions and a track record of helpful reviews.

- Can merge pull requests and publish releases.
- Identity is confirmed before access is granted, because SkillShield is security tooling that other people run on their machines and in CI.
- Takes part in decisions on direction.

## Values

- **Low false positives.** A scanner people switch off protects no one. A rule earns its place by being precise.
- **Explainable findings.** Every finding names its rule and shows the text it matched, so a person can check it.
- **Local and private.** Scans run offline and never send skill contents anywhere.
- **Zero runtime dependencies.** Installing a security tool should not widen your supply chain.
- **The human decides.** SkillShield reports risk. The person installing a skill makes the call.
- **Respect everyone's time.** Maintainers, contributors and users alike.
