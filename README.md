# Oracle Forms-to-APEX CE Workbench

[![Cross-platform install](https://github.com/orajsn/oracle-forms-to-apex-ce/actions/workflows/cross-platform-install.yml/badge.svg)](https://github.com/orajsn/oracle-forms-to-apex-ce/actions/workflows/cross-platform-install.yml)

A portable Codex skill for assessing Oracle Forms applications and building
evidence-led Oracle APEX proof-of-concepts.

The workflow inventories supplied Forms evidence, converts supported Forms
binaries through Oracle tooling, maps Forms behavior to an APEX target design,
and validates generated APEXlang before it can be described as importable.

## What it supports

- `.fmb`, `.mmb`, `.olb`, `.pll`/`.pld`, `.rdf`, Forms XML, SQL, screenshots,
  and related text evidence
- Windows and Linux conversion when supported Oracle Forms tools are installed
- macOS assessment and APEXlang work using preconverted XML/PLD
- Conservative Forms inventory and migration-gap reporting
- APEX target design, APEXlang validation, import guidance, and POC handoff

This is a non-production community proof-of-concept. It does not provide a
one-click conversion, behavioral-equivalence guarantee, or Oracle Support
commitment.

## Install

Requirements:

- Codex Desktop or Codex CLI
- Git, or the repository ZIP downloaded from GitHub
- Python 3.10 or newer

Clone this repository:

```text
git clone https://github.com/orajsn/oracle-forms-to-apex-ce.git
cd oracle-forms-to-apex-ce
```

Then run:

### Windows

```text
py -3 install.py
```

### macOS or Linux

```text
python3 install.py
```

The installer validates the skill, compiles its Python scripts, backs up an
existing installation, verifies copied hashes, and installs it under:

```text
<CODEX_HOME>/skills/oracle-forms-to-apex-ce
```

Restart Codex or begin a new task after installation. See `INSTALL.txt` for
custom `CODEX_HOME` usage and platform boundaries.

### Install without Git

Download the repository ZIP from GitHub, extract it, open a terminal in the
extracted folder, and run the same platform-specific installer command.

### Device compatibility

| Device | Install and assessment | Raw Forms binary conversion |
| --- | --- | --- |
| Windows | Supported | Supported when Oracle Forms tooling is installed |
| Linux | Supported | Supported when Oracle Forms tooling is installed |
| macOS | Supported | Use preconverted XML/PLD or an approved Windows/Linux worker |

The skill is designed for computers that can run Codex and Python. It is not a
standalone mobile application.

## Example prompts

- `Check whether my laptop is ready for a Forms-to-APEX POC.`
- `Assess these FMB and PLL files, but do not build an application.`
- `Build a validated local APEX POC and give me the runtime URL.`
- `Export this POC as APEXlang and standard APEX SQL for handoff.`

## Safety boundaries

- Do not process production credentials, customer records, or restricted data.
- Preserve source files and report inferred or unsupported behavior explicitly.
- Do not parse Forms binaries with ad hoc tools; use supported Oracle tooling.
- Do not import invalid or unproven APEXlang.
- Never connect the POC workflow directly to a production database.

Oracle, Java, and MySQL are registered trademarks of Oracle and/or its
affiliates. Other names may be trademarks of their respective owners.

## License

Copyright (c) 2026 Oracle and/or its affiliates.

Licensed under the Universal Permissive License (UPL), Version 1.0. See
`LICENSE.txt`.
