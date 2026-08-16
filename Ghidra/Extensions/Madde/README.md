# Madde

A legal, open-source starter extension for Ghidra.

This template provides a minimal plugin and extension layout that can serve as a base for custom analysis workflows, project utilities, or a user-facing reverse engineering dashboard.

## Build

From the repository root:

```bash
./gradlew :Ghidra:Extensions:Madde:build
```

## What it contains

- a minimal plugin (`MaddePlugin`)
- a menu action in the Ghidra UI
- standard extension metadata files

## Own-data target matching utility

This folder also includes a legal, own-data checker for matching target addresses against a user-owned mailbox or mail export without scraping unauthorized data. It stores hits in a local SQLite database and exports them as CSV with timestamps.

```bash
python target_matcher.py
```

Use a CSV of targets and either:

- a local mailbox export CSV (`email,mail_date,source`) or
- an IMAP login for a mailbox you explicitly control

The tool records exact matches and a timestamp for each hit.

## Notes

This project intentionally does not copy or reproduce proprietary code from Kraken or other closed-source tools. It is designed as an original codebase built on Ghidra and a lawful, self-owned matching workflow.
