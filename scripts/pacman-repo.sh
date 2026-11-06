#!/usr/bin/env bash
# Adds an Arch Linux package of Portcullis to a pacman repository kept in a GitHub release,
# whose assets pacman reads as Server = https://github.com/<repo>/releases/download/<tag>.
#
#   scripts/pacman-repo.sh <release tag> <builds to keep, 0 for all> <package.pkg.tar.zst>
#
# The release holds the repository database (portcullis.db, portcullis.files) and the
# packages under the names pacman expects (portcullis-0.1.0-1-x86_64.pkg.tar.zst), all
# signed. Older packages stay in the release, so they can be installed with pacman -U,
# unless <builds to keep> is set. A version that is in the release already is left as it
# is: a package must not change under a name pacman may have cached.
#
# Needs gh (GH_REPO, GH_TOKEN), repo-add and bsdtar from pacman, and the signing key in
# gpg's keyring, with its passphrase in GPG_PASSPHRASE.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <release tag> <builds to keep, 0 for all> <package.pkg.tar.zst>" >&2
  exit 2
fi
tag=$1 keep=$2 pkg=$(realpath "$3")
repo=portcullis

info=$(bsdtar -xOf "${pkg}" .PKGINFO)
field() { sed -n "s/^$1 = //p" <<<"${info}"; }
file="$(field pkgname)-$(field pkgver)-$(field arch).pkg.tar.zst"

sign() {
  gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
    --detach-sign --no-armor --output "$1.sig" "$1" <<<"${GPG_PASSPHRASE}"
}

if ! gh release view "${tag}" >/dev/null 2>&1; then
  # A pre-release, so that releases/latest stays the newest vX.Y.Z.
  gh release create "${tag}" --prerelease --latest=false --title "pacman repository (${tag})" \
    --notes "The \`${repo}\` pacman repository, see https://portcullis.arhipov.net/start/installation/. Updated by the Publish workflow."
fi
assets=$(gh release view "${tag}" --json assets --jq '.assets | sort_by(.createdAt) | .[].name')
if grep -qxF "${file}" <<<"${assets}"; then
  echo "${file} is in ${tag} already, leaving it as it is"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
mkdir "${work}/repo" "${work}/upload"
cp "${pkg}" "${work}/repo/${file}"
sign "${work}/repo/${file}"
if grep -qxF "${repo}.db" <<<"${assets}"; then
  gh release download "${tag}" --dir "${work}" --pattern "${repo}.db" --pattern "${repo}.files"
  mv "${work}/${repo}.db" "${work}/repo/${repo}.db.tar.gz"
  mv "${work}/${repo}.files" "${work}/repo/${repo}.files.tar.gz"
fi
# Picks up the signature next to the package. A republished older release isn't put back.
repo-add --prevent-downgrade "${work}/repo/${repo}.db.tar.gz" "${work}/repo/${file}"

for name in "${repo}.db" "${repo}.files"; do
  cp "${work}/repo/${name}.tar.gz" "${work}/upload/${name}"
  sign "${work}/upload/${name}"
done
# The package first, so the database never lists a file that isn't there.
gh release upload "${tag}" "${work}/repo/${file}" "${work}/repo/${file}.sig"
gh release upload "${tag}" --clobber "${work}/upload/"*

if ((keep > 0)); then
  mapfile -t old < <(grep -E '\.pkg\.tar\.zst$' <<<"${assets}" | head -n "-$((keep - 1))")
  for name in "${old[@]}"; do
    echo "removing ${name}, more than ${keep} builds old"
    gh release delete-asset "${tag}" "${name}" --yes
    if grep -qxF "${name}.sig" <<<"${assets}"; then
      gh release delete-asset "${tag}" "${name}.sig" --yes
    fi
  done
fi
