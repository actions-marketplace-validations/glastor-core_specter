## Summary

<!-- Briefly describe the architectural or functional changes in this PR -->

## Linked Issue / Ticket

- Closes #

## Verification Checklist

- [ ] `cargo fmt --all -- --check` passes with 0 formatting issues
- [ ] `cargo clippy --all-targets -- -D warnings` passes with 0 warnings
- [ ] `cargo test --verbose` passes 100% of unit and E2E integration tests
- [ ] `cargo build --release --locked` compiles cleanly and passes Specter self-audit
- [ ] `action.yml` and `README.md` inputs, outputs, and `SPC001`–`SPC013` rules remain synchronized
