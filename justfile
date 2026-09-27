# Release helpers for this single-crate repository.
version := `cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version'`

default:
    @just --list

# Run the same Rust checks as the release workflow.
check:
    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked --all-targets
    cargo test --locked --doc

# Generate the complete changelog with the current Cargo version as the next tag.
changelog:
    git-cliff --config cliff.toml --tag v{{version}} --output CHANGELOG.md

# Preview only the changes since the last release.
changelog-latest:
    git-cliff --config cliff.toml --unreleased --tag v{{version}}

# Verify packaging without uploading anything; requires committed changes.
release-check: check
    cargo publish --locked --dry-run

# Create a local annotated tag. Push it explicitly to trigger publication.
tag:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "$(git status --porcelain)" ]]; then
        echo "Commit all release changes before tagging." >&2
        exit 1
    fi
    just release-check
    git tag -a "v{{version}}" -m "Release v{{version}}"
