# Release guide

`nats-token` uses `just` and `git-cliff` to prepare releases. Pushing a
`vX.Y.Z` tag automatically runs the Rust checks, publishes the crate to crates.io,
and creates a GitHub release with generated notes. Version selection and the
release commit stay manual.

## One-time setup

- Install Rust with `rustfmt` and `clippy`, [just](https://just.systems/),
  [git-cliff](https://git-cliff.org/), and `jq` locally.
- Enable GitHub Actions for the repository.
- Add a crates.io API token as the repository Actions secret
  `CARGO_REGISTRY_TOKEN`. Its owner must be allowed to publish `nats-token`;
  grant the token permission to publish this crate (including creating it if
  this is its first publication).
- The workflow uses GitHub's automatic `GITHUB_TOKEN` to create releases.
  Repository or organization policy must allow its `contents: write` permission.

No local `cargo login` is needed for the automated publication.

## Prepare a release

1. Update `[package].version` in `Cargo.toml`. For the first publication, keep
   `0.1.0` if it has not been published already. Update version references in
   `README.md`, then run `cargo check` to refresh the package version in
   `Cargo.lock`.
2. Commit the code changes that belong in the release. Conventional Commit
   messages (`feat:`, `fix:`, `chore(deps):`, etc.) are grouped in the changelog;
   other messages are retained under “Other changes”.
3. Generate and review the changelog:

   ```bash
   just changelog-latest
   just changelog
   ```

   These commands derive the version from Cargo metadata. `just changelog`
   rebuilds the complete file from Git history, so edit the configuration or
   commit messages if the generated output needs correction.
4. Commit the release files (replace the example version as appropriate):

   ```bash
   git add Cargo.toml Cargo.lock README.md CHANGELOG.md
   git commit -m "chore(release): v0.1.0"
   ```

   Commit the release automation files too when introducing this workflow.
5. Run the checks and create the annotated local tag:

   ```bash
   just tag
   ```

   This requires a clean working tree and runs formatting, Clippy, all default
   test targets, doctests, and `cargo publish --locked --dry-run`. To run these
   checks without tagging, use `just release-check`.
6. Push the commit and the specific tag together from `main`:

   ```bash
   git push --atomic origin main v0.1.0
   ```

   This push triggers publication. Watch the **Release** workflow in GitHub
   Actions. The tag must exactly match `v` plus the manifest version. Prerelease
   versions such as `0.2.0-rc.1` are published to crates.io and marked as
   prereleases on GitHub.

The release checks use the committed lockfile. The Go and `nsc` interoperability
tests remain opt-in, as documented in the README; they are not part of the default
release gate.

## Recovering a failed run

- If validation fails, fix the problem before publishing. Never move a tag for
  a version that has already been published; use a new version for code fixes.
- If publication failed before upload (for example, a missing token), correct
  the configuration and rerun failed jobs in GitHub Actions.
- If crates.io accepted the upload but the publish job subsequently failed,
  check the registry before retrying: published versions cannot be overwritten.
  Create the GitHub release manually for that same tag if necessary.
- If only the GitHub release job failed, use **Re-run failed jobs**. Publication
  is a separate successful job and will not be repeated. The GitHub release
  step also leaves an existing release intact on retries.
