#!/usr/bin/env bash
# Builds the .deb and Arch Linux packages of a Portcullis binary, with nfpm (see mise.toml).
#
#   scripts/package.sh <x86_64|aarch64> <binary> <output dir>
#
# The version is the binary's own (portcullis --version). A build of main (0.1.0-dev+abc1234)
# is packaged as a version that sorts by commit time, and after the release of its base
# version if that is out already (Cargo.toml keeps it until the next release PR), or before:
#
#                released v0.1.0                       no v0.1.0 yet
#   deb    0.1.0+dev20261102101530.abc1234     0.1.0~dev20261102101530.abc1234
#   Arch   0.1.0.dev20261102101530.abc1234     0.1.0dev20261102101530.abc1234
#
# (Arch versions can't have + or -.)
# Outputs portcullis_<amd64|arm64>.deb and portcullis-<arch>.pkg.tar.zst, names that
# don't change between versions, like the other release files.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <x86_64|aarch64> <binary> <output dir>" >&2
  exit 2
fi
arch=$1 binary=$2 out=$3
case "${arch}" in
  x86_64) goarch=amd64 ;;
  aarch64) goarch=arm64 ;;
  *) echo "unknown architecture: ${arch}" >&2 && exit 2 ;;
esac

cd "$(dirname "$0")/.."
stage=target/package
rm -rf "${stage}"
mkdir -p "${stage}"
install -m 0755 "${binary}" "${stage}/portcullis"
# The unit runs the binary where the packages put it.
sed 's|/usr/local/bin/portcullis|/usr/bin/portcullis|' dist/portcullis.service >"${stage}/portcullis.service"
grep -q '^ExecStart=/usr/bin/portcullis$' "${stage}/portcullis.service"

# Debian's package starts the service on install, so its config starts in monitor mode.
awk '
  /^#monitor = false$/ {
    print "# The Debian package starts Portcullis as soon as it is installed, so it starts in"
    print "# monitor mode. Set this to false to enforce the policies of enforced networks."
    print "monitor = true"
    found = 1
    next
  }
  { print }
  END { exit !found }
' dist/config.toml >"${stage}/config-deb.toml"

version=$("${stage}/portcullis" --version | awk '{print $2}')
if [[ "${version}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-dev\+([0-9a-f]+)$ ]]; then
  base=${BASH_REMATCH[1]} commit=${BASH_REMATCH[2]}
  build="dev$(date -u -d "@$(git log -1 --format=%ct HEAD)" +%Y%m%d%H%M%S).${commit}"
  if git ls-remote --exit-code --tags origin "refs/tags/v${base}" >/dev/null; then
    deb_version="${base}+${build}" arch_version="${base}.${build}"
  else
    deb_version="${base}~${build}" arch_version="${base}${build}"
  fi
elif [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  deb_version=${version} arch_version=${version}
else
  echo "can't package version ${version}" >&2
  exit 1
fi
echo "packaging ${version} as ${deb_version} (deb) and ${arch_version} (Arch)"

export PORTCULLIS_ARCH=${goarch}
mkdir -p "${out}"
PORTCULLIS_VERSION=${deb_version} nfpm package --config dist/packaging/nfpm.yaml \
  --packager deb --target "${out}/portcullis_${goarch}.deb"
PORTCULLIS_VERSION=${arch_version} nfpm package --config dist/packaging/nfpm.yaml \
  --packager archlinux --target "${out}/portcullis-${arch}.pkg.tar.zst"
