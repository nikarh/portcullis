#!/usr/bin/env bash
# Adds Debian packages of Portcullis to an apt repository kept in a GitHub release, in the
# flat format (no dists/ and pool/, which a release can't have), which apt reads as
#
#   Types: deb
#   URIs: https://github.com/<repo>/releases/download/<tag>/
#   Suites: ./
#
#   scripts/apt-repo.sh <release tag> <builds to keep, 0 for all> <package.deb>...
#
# The release holds the index (Packages, Packages.gz, Release, signed as InRelease and
# Release.gpg) and the packages, under names GitHub keeps as they are (no ~ or +):
# 0.1.0~dev207.abc1234 is in portcullis_0.1.0-dev207.abc1234_amd64.deb, 0.1.0+dev207…
# in portcullis_0.1.0.dev207…. The index lists every package in the release, so any of
# them installs with apt install portcullis=<version>; only the newest <builds to keep>
# are kept if that is set. A version that is in the release already is left as it is.
#
# Needs gh (GH_REPO, GH_TOKEN), dpkg-deb, apt-ftparchive (apt-utils) and the signing key in
# gpg's keyring, with its passphrase in GPG_PASSPHRASE.
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <release tag> <builds to keep, 0 for all> <package.deb>..." >&2
  exit 2
fi
tag=$1 keep=$2
shift 2

gpg_() { gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 "$@" <<<"${GPG_PASSPHRASE}"; }

if ! gh release view "${tag}" >/dev/null 2>&1; then
  # A pre-release, so that releases/latest stays the newest vX.Y.Z.
  gh release create "${tag}" --prerelease --latest=false --title "apt repository (${tag})" \
    --notes "The Portcullis apt repository, see https://nikarh.github.io/portcullis/start/installation/. Updated by the Publish workflow."
fi
assets=$(gh release view "${tag}" --json assets --jq '.assets | sort_by(.createdAt) | .[].name')

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
mkdir "${work}/new" "${work}/index"
added=()
for deb in "$@"; do
  name=$(dpkg-deb -f "${deb}" Package)
  version=$(dpkg-deb -f "${deb}" Version | tr '~+' '-.')
  file="${name}_${version}_$(dpkg-deb -f "${deb}" Architecture).deb"
  if grep -qxF "${file}" <<<"${assets}"; then
    echo "${file} is in ${tag} already, leaving it as it is"
    continue
  fi
  cp "${deb}" "${work}/new/${file}"
  added+=("${file}")
done
if ((${#added[@]} == 0)); then
  exit 0
fi

# The packages of the builds beyond the newest <keep>, counting the new one. A build is a
# version, with a package for each architecture.
removed=()
if ((keep > 0)); then
  build() { sed -E 's/_[^_]+\.deb$//'; }
  new_builds=$(printf '%s\n' "${added[@]}" | build | sort -u)
  mapfile -t old_builds < <(grep -E '\.deb$' <<<"${assets}" | build | awk '!seen[$0]++' | grep -vxF "${new_builds}" || true)
  drop=$((${#old_builds[@]} + $(wc -l <<<"${new_builds}") - keep))
  if ((drop > 0)); then
    mapfile -t removed < <(grep -E '\.deb$' <<<"${assets}" | grep -F -f <(printf '%s_\n' "${old_builds[@]:0:drop}"))
  fi
fi

if grep -qxF Packages <<<"${assets}"; then
  gh release download "${tag}" --dir "${work}" --pattern Packages
else
  : >"${work}/Packages"
fi
# Paragraph by paragraph: drop the removed packages, then add the new ones.
{
  printf '%s\n' "${removed[@]}" | awk '
    NR == FNR { if ($0 != "") drop["Filename: " $0] = 1; next }
    { keep = 1; n = split($0, lines, "\n"); for (i = 1; i <= n; i++) if (lines[i] in drop) keep = 0 }
    keep { print $0 "\n" }
  ' - RS= "${work}/Packages"
  (cd "${work}/new" && apt-ftparchive packages .) | sed 's|^Filename: \./|Filename: |'
} >"${work}/index/Packages"
gzip -9n <"${work}/index/Packages" >"${work}/index/Packages.gz"
(
  cd "${work}/index"
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=Portcullis \
    -o APT::FTPArchive::Release::Label=Portcullis \
    -o "APT::FTPArchive::Release::Description=Portcullis (${tag})" \
    release . >"${work}/Release"
)
mv "${work}/Release" "${work}/index/Release"
gpg_ --clearsign --output "${work}/index/InRelease" "${work}/index/Release"
gpg_ --armor --detach-sign --output "${work}/index/Release.gpg" "${work}/index/Release"

# The packages first, so the index never lists a file that isn't there.
gh release upload "${tag}" "${work}/new/"*
gh release upload "${tag}" --clobber "${work}/index/"*

for file in "${removed[@]}"; do
  echo "removing ${file}, more than ${keep} builds old"
  gh release delete-asset "${tag}" "${file}" --yes
done
