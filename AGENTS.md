When adding dependencies to the project don't edit files - use package managers to always get the latest version.
Commit your changes. Use conventional commits. Split logical changes to individual commits.
Before committing run fmt, clippy and tests.

Commit messages, pull requests, code, tests and docs describe bugs and their fixes, in general terms: what goes
wrong, under which conditions, and what changed. Never frame them around a particular deployment, server, run or
data set ("on my server", "traefik on the fileserver did X", "from these logs"), and never name its containers,
networks, addresses or domains; use placeholders (`app`, `db`, `example.org`, documentation address ranges).

## Documentation

The documentation is the Starlight site in `site/` (pages in `site/src/content/docs/`), published to GitHub Pages
with a version per release and one for `main`. The README is only an overview that links to it.

- Every change to behaviour updates the docs in the same commit or pull request: labels in `policy/` (and the table in
  `policy/overview.md`), settings in `reference/configuration.md` (and `dist/config.toml`, and the `--help` text in
  `src/main.rs`), events and fields in `reference/events.md`, limitations in `limits/`. `project/docs.md` lists
  what goes where.
- Internal links are site-absolute without the version, with a trailing slash: `[egress](/policy/egress/)`.
- Write like the existing pages: plain, precise, engineer to engineer; no marketing. Don't document behaviour the code
  doesn't have.
- Before committing docs changes run `mise run docs:build`: it fails on broken links and anchors.
- `mise run docs` serves the site locally with live reload.
- Released docs are frozen when a release is published (`.github/workflows/docs.yml`, `scripts/docs-publish.sh`);
  don't edit the `gh-pages` branch by hand.
