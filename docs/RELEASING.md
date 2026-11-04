# Releasing

## How a release happens

1. Run the **Create a release PR** workflow (Actions → Create a release PR → patch / minor / major). It bumps the
   version in `Cargo.toml`, regenerates `CHANGELOG.md` with git-cliff from the conventional commits, and opens a pull
   request titled `Release vX.Y.Z` with the release notes as its body.
2. Review and merge it. The **Release** workflow tags the merge commit and creates the GitHub release with the notes.
3. The **Publish** workflow builds Portcullis for x86_64 and aarch64 on Ubuntu 22.04, runs the tests, packages the
   binary as `.deb` and Arch Linux packages with [nfpm](https://nfpm.goreleaser.com/) (`scripts/package.sh`, config
   in `dist/packaging/`), checks that the `.deb` installs, starts and purges, writes `SHA256SUMS` and its GPG signature, and
   uploads everything to the release.

Every push to `main` also updates the `latest` pre-release (the **Latest** workflow): the tag moves to the new
commit, the notes list the unreleased changes, and Publish uploads the same files, signed the same way, with the
version marked as a build of main (`0.1.1-dev+abc1234`, from `PORTCULLIS_VERSION_SUFFIX`). It is never marked as
GitHub's latest release, so `releases/latest` keeps pointing at the newest `vX.Y.Z`.

Publish then adds the Arch Linux packages to the `portcullis` pacman repositories (`scripts/pacman-repo.sh`), kept in
pre-releases of their own: `pacman-x86_64` and `pacman-aarch64` for releases, `pacman-latest-x86_64` and
`pacman-latest-aarch64` for builds of main. Each holds the repository database (`portcullis.db`, `portcullis.files`)
and the packages under versioned names (`portcullis-0.1.0-1-x86_64.pkg.tar.zst`), all signed with the release signing
key. Older packages stay: every release, and the newest 100 builds of main. A version that is there already is never
replaced, since pacman caches packages by name. The pre-releases are created on the first publish.

Likewise the Debian packages go to the apt repositories (`scripts/apt-repo.sh`), one pre-release each with both
architectures: `apt` for releases and `apt-latest` for builds of main. They are flat repositories (`Suites: ./`, no
`dists/` and `pool/`, which a release can't have): the index (`Packages`, `Packages.gz`, `Release`, signed as
`InRelease` and `Release.gpg`) lists every package in the release, so older versions install with
`apt install portcullis=<version>`. The packages are named so that GitHub keeps the name (`~` and `+` in the version
become `-` and `.`). After an update the job checks that apt, set up as in the README, sees the new version.

Asset names never change, so `https://github.com/nikarh/portcullis/releases/latest/download/<name>` always points at
the newest file:

| Asset | Contents |
| --- | --- |
| `portcullis-x86_64-linux-gnu`, `portcullis-aarch64-linux-gnu` | The binary |
| `portcullis-x86_64-linux-gnu.tar.gz`, `portcullis-aarch64-linux-gnu.tar.gz` | The binary, the systemd unit, the config file, the README and the licenses |
| `portcullis_amd64.deb`, `portcullis_arm64.deb` | Debian / Ubuntu packages |
| `portcullis-x86_64.pkg.tar.zst`, `portcullis-aarch64.pkg.tar.zst` | Arch Linux packages |
| `portcullis.service` | The systemd unit |
| `SHA256SUMS`, `SHA256SUMS.asc` | Checksums of all of the above and their detached GPG signature |

## One-time setup

### Release bot and the `release` environment

The release workflows act as a GitHub App, like the other nikarh repositories: the app needs *Contents* and *Pull
requests* read & write, and to be installed on the repository. The `release` environment (Settings → Environments)
only allows the `main` and `release` branches and `v*` tags, and holds these secrets:

| Secret | Value |
| --- | --- |
| `APP_CLIENT_ID` | The app's client ID (`Iv…`, on the app's settings page) |
| `APP_PRIVATE_KEY` | A private key of the app (PEM) |
| `GPG_PRIVATE_KEY` | ASCII armored private key that signs `SHA256SUMS` and the apt and pacman repositories |
| `GPG_PASSPHRASE` | Its passphrase |

```sh
gh secret set APP_CLIENT_ID --env release --repo nikarh/portcullis --body <client id>
gh secret set APP_PRIVATE_KEY --env release --repo nikarh/portcullis < release-bot.private-key.pem
```

### GPG signing key

"Portcullis releases" (`33DD9B9FB720453D48136F2EB90B594ECF87B58B`, ed25519, until 2029-11-01) is in the
maintainer's GPG keyring, its passphrase in the desktop keyring (`secret-tool lookup service portcullis-release-gpg`).
It was made and set up like this:

```sh
secret-tool store --label "Portcullis release signing key passphrase" service portcullis-release-gpg
gpg --quick-generate-key "Portcullis releases <nikarh@users.noreply.github.com>" ed25519 sign 3y
gpg --armor --export-secret-keys "Portcullis releases" | gh secret set GPG_PRIVATE_KEY --env release
secret-tool lookup service portcullis-release-gpg | gh secret set GPG_PASSPHRASE --env release
gpg --armor --export "Portcullis releases" > docs/signing-key.asc
```

Before it expires, extend it (`gpg --quick-set-expire`), and update the secret and `docs/signing-key.asc`.

### Actions policy

The repository allows only GitHub's own actions, actions by verified creators and the third party actions in
[`.github/allowed-actions.txt`](../.github/allowed-actions.txt), and requires every action to be pinned to a full
commit SHA. Every workflow refers to actions as `owner/action@<40 hex SHA> # vX.Y.Z`; Dependabot updates the SHA and
the version comment together. `scripts/check-actions.sh` (run in CI) fails when a workflow uses an action that isn't
pinned or isn't allowed. Adding a third party action: add it to `allowed-actions.txt`, pin it, and add it to the
repository's allowed actions as well (Settings → Actions → General).

### Dependabot

Dependabot updates actions and cargo dependencies weekly. The **Auto-merge** workflow squash-merges its pull requests
once every required check of the `main` ruleset is green. If GitHub refuses to merge one that changes workflow files,
add a fine-grained token as the `DEPENDABOT_MERGE_TOKEN` repository secret (Contents, Pull requests and Workflows:
write).
