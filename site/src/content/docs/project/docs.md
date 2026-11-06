---
title: Writing the docs
description: Where the documentation lives, how to preview it, the conventions it follows, and how versions are published.
sidebar:
  order: 1
---

The documentation is this site, an [Astro Starlight](https://starlight.astro.build) project in `site/`. Its pages are Markdown files in `site/src/content/docs/`; the README only has an overview and links here.

## Previewing

```bash
mise run docs          # dev server at http://localhost:4321, reloads on save
mise run docs:build    # build as CI does, and check every internal link and anchor
```

Both install the dependencies first. Node comes from `mise.toml`.

## Where things go

| Directory | Sidebar group | For |
| --- | --- | --- |
| `start/` | Getting started | introduction, quick start, installation |
| `guides/` | Guides | tasks: rolling out, running the service, events, hardening |
| `policy/` | Policy labels | one page per label family, the reference for what labels mean |
| `reference/` | Reference | CLI, configuration, event schema, host resources |
| `examples/` | Examples | complete Compose files for one setup each |
| `internals/` | How it works | architecture and mechanisms |
| `limits/` | Limits and workarounds | what Portcullis can't do, and what to use instead |
| `help/` | Help | troubleshooting, FAQ |
| `project/` | Project | development, docs, releasing |

The sidebar is generated from the directories; order pages with `sidebar.order` in their frontmatter. A new page needs `title` and `description` frontmatter, and no H1.

## When to update what

Every change to behaviour updates the docs in the same pull request:

- A new or changed label: its `policy/` page, the table in `policy/overview.md`, and `examples/` that use it.
- A new or changed setting: `reference/configuration.md`, `dist/config.toml` and the help text in `src/main.rs`.
- A new or changed event or field: `reference/events.md`.
- A new warning: `policy/checks.md` if it is a configuration check, and `reference/events.md`.
- A new limitation, or one lifted: `limits/limitations.md`, and `limits/escape-hatches.md` if there is a workaround.

## Conventions

- Plain, precise sentences, engineer to engineer. Say what happens, not how good it is.
- Internal links are site-absolute, without the version: `[egress labels](/policy/egress/)`, with the trailing slash. A remark plugin adds the base of the version being built. The build fails on a link to a page or anchor that doesn't exist.
- Code blocks have a language, and a `title` when they are a file.
- Asides (`:::note`, `:::tip`, `:::caution`, `:::danger`) for what a reader would regret missing, sparingly.
- Don't promise behaviour the code doesn't have. Check the source, or the end-to-end scenario that covers it.

## Versions

The site is published on GitHub Pages from the `gh-pages` branch, at `https://portcullis.arhipov.net/` (the
`CNAME` file; the DNS record is at Cloudflare), one directory per version:

| Path | Built from | Updated |
| --- | --- | --- |
| `/main/` | the tip of `main` | on every push to `main` |
| `/vX.Y.Z/` | the release tag | once, when the release is published; kept for good |
| `/` | | redirects to the newest release |
| `/versions.json` | | the list of versions, read by the version menu |

A path without a version (`/reference/configuration/`, what the config file and `--help` link to) goes to that page
of the newest release, through `404.html`. So do links to `https://nikarh.github.io/portcullis/`, where the docs were
before: GitHub redirects them to the domain.

The **Docs** workflow (`.github/workflows/docs.yml`) builds the site with `DOCS_VERSION` set to the version, which sets the base path, and `scripts/docs-publish.sh` copies the build into the version's directory of `gh-pages`, rewrites `versions.json` and the root redirect, and pushes. Pull requests only build, so broken links fail them.

A release's docs are its tag's `site/`, frozen when the release is published. To fix the docs of a release after the fact, run the workflow by hand with the tag (`gh workflow run docs.yml -f version=v0.2.0`): it rebuilds that version from the tag, so the fix has to be on the tag. Normally, fix `main` instead; the next release carries it.

Old versions read `versions.json` when they load, so their version menu offers releases made after them.
