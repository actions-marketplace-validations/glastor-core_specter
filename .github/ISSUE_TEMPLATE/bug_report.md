---
name: "🐛 Bug Report"
about: "Report an issue with polyglot AST extraction, SemVer contract diffing (SPC001–SPC013), or Trojan Commit Guard"
title: "[BUG] "
labels: ["bug"]
assignees: []
---

### Description

A clear and concise description of the bug.

### Reproduction Steps

1. Run `specter` with flags `...` (or GitHub Action inputs `...`)
2. Base and Head source snippet (`.rs` or `.ts`) `...`
3. Observed contract rule / SemVer verdict vs Expected output (`SPC001`–`SPC013`)

### Environment

- Specter Version: `v0.1.0`
- Rust Toolchain: `rustc --version`
- OS / Runner: `ubuntu-latest` / Windows / macOS
