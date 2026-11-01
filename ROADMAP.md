# Roadmap

## Where SkillShield is today

SkillShield is a **pattern scanner**. It reads a skill's text and flags phrasings and code patterns that match known attacks. That makes it fast, local, explainable and free of dependencies, and it catches the low-effort malicious skills that make up most of what has been found on skill marketplaces.

It is not yet a defence on its own. Pattern matching misses attacks that are reworded, written in another language, hidden with invisible characters or encoded, or placed in files it does not open. [docs/threat-coverage.md](docs/threat-coverage.md) lists every published technique and whether SkillShield catches it today; most are still gaps.

No tool that only reads a skill once can be a complete defence. A skill is instructions in natural language, and it can fetch new instructions after it has been scanned. So the goal is not a perfect scanner. It is to give one tool every layer a team needs, from the first scan to the moment the agent acts.

## Principles

These hold for every stage:

- **Explainable.** Every finding names its rule and shows the text or code that triggered it.
- **Local.** Scans never send skill contents anywhere.
- **No runtime dependencies in the core.** Heavier features are optional extras.
- **Low false positives.** A scanner people switch off protects no one. Every rule ships with near-miss tests.
- **Measured.** Claims are backed by the red-team corpus and the false-positive benchmark, and the numbers are published.
- **Layers can only add.** A later layer (such as a semantic model) can raise a finding, but never remove or lower one, so it cannot be talked into approving a skill.

## Stages

Each stage has a tracking issue that lists the work. Stages 1 and 2 are mostly contributor-sized issues; stages 3, 4 and 6 need a design agreed in their tracking issue before code.

| Stage | What it adds | Tracking issue |
|---|---|---|
| 0. Measure | Detection rate, false-positive rate and a performance budget for every rule | #71 |
| 1. Close the cheap evasions | Hidden characters, encodings, other languages, and every file in a skill | #72 |
| 2. Cover every published technique | A rule and a passing red-team test for each technique in the threat catalogue | #73 |
| 3. Judge behaviour, not wording | What a skill's scripts can do (network, secrets, shell) compared with what it says it does | #74 |
| 4. Optional semantic check | A local classifier for reworded and multilingual attacks, as an optional extra | #75 |
| 5. Lock and verify | Detect any change to a skill after it was reviewed | #76 |
| 6. Runtime guard | Block a skill from reading secrets or calling undeclared hosts while the agent runs | #77 |

### 0. Measure (#71)

Know, for each release, how much of the known attack catalogue SkillShield catches, how often it flags safe skills, and that no input can make a scan slow. The red-team corpus and coverage page exist; a performance budget test (#69) and a false-positive benchmark on real, safe skills (#70) are next.

### 1. Close the cheap evasions (#72)

Remove the tricks that need no skill to use: zero-width characters and lookalike letters (#27), Unicode tag characters (#54), right-to-left overrides (#55), base64 (#29), other languages (#66), rewording (#28, #49), and payloads in files SkillShield skips, such as compiled Python, archives and extensionless scripts (#39 to #42). It also stops one evasion from switching off a second rule (#67).

### 2. Cover every published technique (#73)

Give each technique in [docs/threat-coverage.md](docs/threat-coverage.md) a rule and a passing test: payload delivery, data theft, persistence, agent manipulation and metadata abuse.

### 3. Judge behaviour, not wording (#74)

Read each script's code to find what it can actually do (network access, reading secret files, running a shell, reading the environment), and compare that with the skill's stated purpose. A "weather" skill that reads `~/.ssh` is suspicious however it is worded and in any language. This is the step from matching phrases to understanding skills.

### 4. Optional semantic check (#75)

A small classifier that runs locally, installed as `skillshield[semantic]`, to catch reworded and multilingual attacks that patterns miss. It can only add findings, it is scored publicly before it ships, and the red-team corpus includes samples written to fool it.

### 5. Lock and verify (#76)

`skillshield lock` records a hash of every file in each reviewed skill; `skillshield verify` fails when anything changes. This closes the attacks where a skill passes review and changes later, and flags skills that fetch instructions at run time as impossible to lock.

### 6. Runtime guard (#77)

A guard that plugs into agent hooks and checks each tool call while a skill is in use: blocking reads of secret files, writes to agent memory, and calls to hosts the skill did not declare. This is the only layer that stops an attack the scanner missed, and the one that makes SkillShield a defence rather than a tripwire.

## How to help

- Pick an issue from a stage's tracking issue. Issues labelled `good first issue` are scoped for a first contribution.
- Join the design discussion in #74, #75 or #77 if you have experience with static analysis, classifiers or agent runtimes.
- Report a technique SkillShield misses with the **Detection gap** issue form, and a safe skill it flags with **False positive**.

See [CONTRIBUTING.md](CONTRIBUTING.md) before you start.
