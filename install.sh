#!/usr/bin/env bash
# ============================================================================
# install.sh — One-command installer for WG-Tunnel
# ============================================================================
# Usage (recommended):
#   curl -fsSL https://raw.githubusercontent.com/changecoin938/wg-tunnel/main/install.sh | sudo bash
#
# Env overrides:
#   WG_TUNNEL_DIR=/opt/wg-tunnel
#   WG_TUNNEL_REPO=https://github.com/changecoin938/wg-tunnel.git
#   WG_TUNNEL_BRANCH=main
# ============================================================================

set -euo pipefail

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; NC='\033[0m'
OK="${G}✓${NC}"; FAIL="${R}✗${NC}"; WARN="${Y}⚠${NC}"

log() { echo -e "  $1 $2"; }

die() {
  echo -e "  ${FAIL} $*" >&2
  exit 1
}

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."
}

check_os() {
  [[ -f /etc/os-release ]] || die "Unsupported OS (missing /etc/os-release)"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) return 0 ;;
    *) die "Unsupported distro: ${ID:-unknown} (only Debian/Ubuntu supported)" ;;
  esac
}

install_deps() {
  command -v apt-get >/dev/null 2>&1 || die "apt-get not found"
  log "${OK}" "Installing dependencies (curl, git)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq curl ca-certificates git >/dev/null 2>&1
  log "${OK}" "Dependencies installed"
}

main() {
  need_root
  check_os
  install_deps

  local dir="${WG_TUNNEL_DIR:-/opt/wg-tunnel}"
  local repo="${WG_TUNNEL_REPO:-https://github.com/changecoin938/wg-tunnel.git}"
  local branch="${WG_TUNNEL_BRANCH:-main}"

  if [[ -d "${dir}/.git" ]]; then
    log "${OK}" "Updating existing install: ${dir}"
    git -C "${dir}" fetch --all --prune
    git -C "${dir}" checkout -q "${branch}"
    git -C "${dir}" pull -q --ff-only
  elif [[ -e "${dir}" ]]; then
    die "Install dir exists but is not a git repo: ${dir} (set WG_TUNNEL_DIR=...)"
  else
    log "${OK}" "Cloning to: ${dir}"
    git clone -q --depth 1 --branch "${branch}" "${repo}" "${dir}"
  fi

  chmod +x "${dir}"/*.sh "${dir}"/wg-tunnel.sh 2>/dev/null || true

  install -d /usr/local/bin
  ln -sf "${dir}/wg-tunnel.sh" /usr/local/bin/wg-tunnel

  echo ""
  log "${OK}" "Installed: /usr/local/bin/wg-tunnel"
  echo ""
  exec "${dir}/wg-tunnel.sh" menu
}

main "$@"

