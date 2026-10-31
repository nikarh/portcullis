#!/usr/bin/env bash
# Disposable Debian VM with Docker for end-to-end tests.
#
# Runs QEMU/KVM as the current user with user-mode networking, so nothing on the host
# (firewall, network, packages) is touched. Needs qemu-system-x86_64, genisoimage (or
# mkisofs), ssh and rsync, and read/write access to /dev/kvm.
#
#   e2e/vm.sh up        create (first run) and boot the VM, wait until it is ready
#   e2e/vm.sh sync      copy the working tree into the VM and build Portcullis there
#   e2e/vm.sh ssh ...   run a command in the VM, or open a shell
#   e2e/vm.sh down      stop the VM
#   e2e/vm.sh destroy   stop the VM and delete its disk
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${PORTCULLIS_VM_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/portcullis-e2e}"
IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
BASE_IMAGE="${STATE_DIR}/debian-13-genericcloud-amd64.qcow2"
DISK="${STATE_DIR}/disk.qcow2"
SEED="${STATE_DIR}/seed.iso"
KEY="${STATE_DIR}/id_ed25519"
PIDFILE="${STATE_DIR}/qemu.pid"
CONSOLE_LOG="${STATE_DIR}/console.log"
SSH_PORT="${PORTCULLIS_VM_SSH_PORT:-2222}"
MEMORY="${PORTCULLIS_VM_MEMORY:-4G}"
CPUS="${PORTCULLIS_VM_CPUS:-4}"
VM_SRC="/home/debian/portcullis"

ssh_opts=(
  -i "${KEY}"
  -p "${SSH_PORT}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o IdentitiesOnly=yes
  -o ConnectTimeout=5
)

log() { printf '[vm] %s\n' "$*" >&2; }

is_running() {
  [[ -f "${PIDFILE}" ]] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null
}

vm_ssh() {
  ssh "${ssh_opts[@]}" debian@127.0.0.1 "$@"
}

create() {
  mkdir -p "${STATE_DIR}"

  if [[ ! -f "${BASE_IMAGE}" ]]; then
    log "downloading ${IMAGE_URL}"
    curl -fL --progress-bar -o "${BASE_IMAGE}.part" "${IMAGE_URL}"
    mv "${BASE_IMAGE}.part" "${BASE_IMAGE}"
  fi

  [[ -f "${KEY}" ]] || ssh-keygen -q -t ed25519 -N '' -f "${KEY}"

  local seed_dir="${STATE_DIR}/seed"
  mkdir -p "${seed_dir}"
  printf 'instance-id: portcullis-e2e\nlocal-hostname: portcullis-e2e\n' >"${seed_dir}/meta-data"
  cat >"${seed_dir}/user-data" <<EOF
#cloud-config
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "${KEY}.pub")
package_update: true
packages:
  - build-essential
  - clang
  - curl
  - dnsmasq-base
  - dnsutils
  - ipset
  - iptables
  - libnftables-dev
  - nftables
  - pkg-config
  - rsync
  - socat
runcmd:
  - curl -fsSL https://get.docker.com | sh
  - usermod -aG docker debian
  - su - debian -c 'curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal'
  - touch /var/lib/portcullis-e2e-ready
EOF
  local mkiso
  mkiso="$(command -v genisoimage || command -v mkisofs)"
  "${mkiso}" -quiet -output "${SEED}" -volid cidata -joliet -rock \
    "${seed_dir}/user-data" "${seed_dir}/meta-data"

  qemu-img create -q -f qcow2 -F qcow2 -b "${BASE_IMAGE}" "${DISK}" 20G
}

up() {
  if is_running; then
    log "already running"
  else
    [[ -f "${DISK}" ]] || create
    log "booting (console log: ${CONSOLE_LOG})"
    qemu-system-x86_64 \
      -name portcullis-e2e \
      -machine q35,accel=kvm \
      -cpu host \
      -smp "${CPUS}" \
      -m "${MEMORY}" \
      -drive "file=${DISK},if=virtio" \
      -drive "file=${SEED},if=virtio,media=cdrom" \
      -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
      -device virtio-net-pci,netdev=net0 \
      -display none \
      -serial "file:${CONSOLE_LOG}" \
      -daemonize \
      -pidfile "${PIDFILE}"
  fi

  log "waiting for provisioning to finish (first boot takes a few minutes)"
  local deadline=$((SECONDS + 900))
  until vm_ssh test -f /var/lib/portcullis-e2e-ready 2>/dev/null; do
    if ((SECONDS > deadline)); then
      log "timed out; see ${CONSOLE_LOG}"
      exit 1
    fi
    if ! is_running; then
      log "VM exited; see ${CONSOLE_LOG}"
      exit 1
    fi
    sleep 5
  done
  log "ready"
}

sync_tree() {
  rsync -az --delete \
    --exclude /target --exclude /.git \
    -e "ssh ${ssh_opts[*]}" \
    "${PROJECT_ROOT}/" "debian@127.0.0.1:${VM_SRC}/"
  vm_ssh "cd ${VM_SRC} && ~/.cargo/bin/cargo build --release --quiet"
}

down() {
  if is_running; then
    vm_ssh sudo poweroff 2>/dev/null || true
    local pid
    pid="$(cat "${PIDFILE}")"
    for _ in $(seq 30); do
      kill -0 "${pid}" 2>/dev/null || break
      sleep 1
    done
    kill "${pid}" 2>/dev/null || true
    log "stopped"
  fi
  rm -f "${PIDFILE}"
}

destroy() {
  down
  rm -f "${DISK}" "${SEED}"
  rm -rf "${STATE_DIR}/seed"
  log "disk deleted (base image kept in ${STATE_DIR})"
}

case "${1:-}" in
  up) up ;;
  sync) sync_tree ;;
  ssh) shift; vm_ssh "$@" ;;
  down) down ;;
  destroy) destroy ;;
  *)
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
