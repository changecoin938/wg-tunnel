#!/usr/bin/env bash
# ============================================================================
# wg-tunnel.sh — Unified entrypoint for WG-Tunnel repo scripts
# ============================================================================
# Goal: a single CLI for running/installing repo scripts
#
# Examples:
#   sudo ./wg-tunnel.sh stealth server [PSK] [PORT] [WG_PORT]
#   sudo ./wg-tunnel.sh stealth relay FOREIGN_IP [PSK] [REMOTE_PORT] [LOCAL_PORT] [PIN] [SNI]
#   sudo ./wg-tunnel.sh stealth status
#   sudo ./wg-tunnel.sh stealth remove
#
#   sudo ./wg-tunnel.sh enterprise
#
#   sudo ./wg-tunnel.sh module anti-dpi
#   sudo ./wg-tunnel.sh module performance
#   sudo ./wg-tunnel.sh module stealth-guard
#   sudo ./wg-tunnel.sh module obfuscator
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() {
  echo "Error: $*" >&2
  exit 1
}

need_tty() {
  [[ -t 0 ]] || die "Menu requires an interactive terminal (TTY)."
}

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "This option requires sudo. Example: sudo ./wg-tunnel.sh"
}

pause() {
  echo ""
  read -r -p "Press Enter to continue..." _ || true
}

prompt_default() {
  local label="$1"
  local default="$2"
  local value=""
  if ! read -r -p "${label} [${default}]: " value; then
    return 1
  fi
  echo "${value:-$default}"
}

prompt_required() {
  local label="$1"
  local value=""
  while true; do
    if ! read -r -p "${label}: " value; then
      return 1
    fi
    [[ -n "${value}" ]] && { echo "${value}"; return 0; }
  done
}

run_script() {
  local rc=0
  set +e
  bash "$@"
  rc=$?
  set -e
  return "${rc}"
}

show_main_menu() {
  clear 2>/dev/null || true
  cat <<'EOF'
WG-Tunnel — Menu

  [1] stealth/server
      Install exit server (foreign)

  [2] stealth/relay
      Install relay server (Iran)

  [3] stealth/status
      Status

  [4] stealth/remove
      Uninstall

  [5] enterprise
      Full installer (WG + Xray)

  [6] module/anti-dpi
      Anti-DPI menu

  [U] module/anti-dpi-ultimate
      Anti-DPI (Ultimate)

  [7] module/performance
      Performance tuning

  [8] module/stealth-guard
      Stealth guard

  [9] module/obfuscator
      Traffic obfuscation

  [0] Exit
EOF
  echo ""
  echo -n "Choice [0-9,U]: "
}

menu_loop() {
  need_tty
  while true; do
    show_main_menu
    local choice=""
    if ! read -r choice; then
      echo ""
      exit 0
    fi
    echo ""

    case "${choice}" in
      1)
        need_root
        local psk="" port="" wg_port=""
        echo "PSK:"
        echo "  (leave empty to auto-generate)"
        read -r psk || exit 0
        port="$(prompt_default "TLS Port" "443")" || exit 0
        wg_port="$(prompt_default "WG UDP Port" "51820")" || exit 0
        if ! run_script "${SCRIPT_DIR}/deploy.sh" server "${psk}" "${port}" "${wg_port}"; then
          echo "Install failed."
        fi
        pause
        ;;
      2)
        need_root
        local foreign="" psk="" rport="" lport="" pin="" sni=""
        foreign="$(prompt_required "FOREIGN_IP")" || exit 0
        echo "PSK:"
        echo "  (recommended. empty = no PSK)"
        read -r psk || exit 0
        rport="$(prompt_default "Remote TLS Port" "443")" || exit 0
        lport="$(prompt_default "Local UDP Port" "51820")" || exit 0
        echo "PIN (SHA256 fingerprint):"
        echo "  (recommended. copy it from exit server output. empty = no pin)"
        read -r pin || exit 0
        echo "SNI Host:"
        echo "  (optional; default: www.google.com)"
        read -r sni || exit 0
        if ! run_script "${SCRIPT_DIR}/deploy.sh" relay "${foreign}" "${psk}" "${rport}" "${lport}" "${pin}" "${sni}"; then
          echo "Install failed."
        fi
        pause
        ;;
      3)
        run_script "${SCRIPT_DIR}/deploy.sh" status || true
        pause
        ;;
      4)
        need_root
        run_script "${SCRIPT_DIR}/deploy.sh" remove || true
        pause
        ;;
      5)
        need_root
        run_script "${SCRIPT_DIR}/tunnel_enterprise.sh" || true
        pause
        ;;
      6)
        need_root
        run_script "${SCRIPT_DIR}/anti_dpi.sh" || true
        pause
        ;;
      [Uu])
        need_root
        run_script "${SCRIPT_DIR}/anti_dpi_ultimate.sh" || true
        pause
        ;;
      7)
        need_root
        run_script "${SCRIPT_DIR}/performance_tuner.sh" || true
        pause
        ;;
      8)
        need_root
        run_script "${SCRIPT_DIR}/stealth_guard.sh" || true
        pause
        ;;
      9)
        need_root
        run_script "${SCRIPT_DIR}/traffic_obfuscator.sh" || true
        pause
        ;;
      0|q|Q|exit)
        exit 0
        ;;
      *)
        echo "Invalid choice: ${choice}"
        pause
        ;;
    esac
  done
}

usage() {
  cat <<'EOF'
wg-tunnel.sh — Unified CLI

Usage:
  ./wg-tunnel.sh                 # interactive menu
  ./wg-tunnel.sh menu
  ./wg-tunnel.sh stealth <server|relay|status|remove> [args...]
  ./wg-tunnel.sh enterprise
  ./wg-tunnel.sh module <anti-dpi|anti-dpi-ultimate|performance|stealth-guard|obfuscator>

Stealth (C tunnel) wrappers:
  sudo ./wg-tunnel.sh stealth server [PSK] [PORT] [WG_PORT]
  sudo ./wg-tunnel.sh stealth relay FOREIGN_IP [PSK] [REMOTE_PORT] [LOCAL_PORT] [PIN] [SNI]
  sudo ./wg-tunnel.sh stealth status
  sudo ./wg-tunnel.sh stealth remove

Enterprise installer:
  sudo ./wg-tunnel.sh enterprise

Modules:
  sudo ./wg-tunnel.sh module anti-dpi
  sudo ./wg-tunnel.sh module anti-dpi-ultimate
  sudo ./wg-tunnel.sh module performance
  sudo ./wg-tunnel.sh module stealth-guard
  sudo ./wg-tunnel.sh module obfuscator
EOF
}

cmd="${1:-menu}"
[[ $# -gt 0 ]] && shift || true

case "${cmd}" in
  menu)
    menu_loop
    ;;

  -h|--help|help)
    usage
    exit 0
    ;;

  stealth)
    sub="${1:-}"
    shift || true
    case "${sub}" in
      server|relay|status|remove)
        exec bash "${SCRIPT_DIR}/deploy.sh" "${sub}" "$@"
        ;;
      *)
        usage
        die "Unknown stealth command: ${sub}"
        ;;
    esac
    ;;

  enterprise)
    exec bash "${SCRIPT_DIR}/tunnel_enterprise.sh" "$@"
    ;;

  module|modules)
    mod="${1:-}"
    shift || true
    case "${mod}" in
      anti-dpi|anti_dpi)
        exec bash "${SCRIPT_DIR}/anti_dpi.sh" "$@"
        ;;
      anti-dpi-ultimate|anti_dpi_ultimate|ultimate)
        exec bash "${SCRIPT_DIR}/anti_dpi_ultimate.sh" "$@"
        ;;
      performance|perf|performance-tuner|performance_tuner)
        exec bash "${SCRIPT_DIR}/performance_tuner.sh" "$@"
        ;;
      stealth-guard|stealth_guard)
        exec bash "${SCRIPT_DIR}/stealth_guard.sh" "$@"
        ;;
      obfuscator|traffic-obfuscator|traffic_obfuscator)
        exec bash "${SCRIPT_DIR}/traffic_obfuscator.sh" "$@"
        ;;
      *)
        usage
        die "Unknown module: ${mod}"
        ;;
    esac
    ;;

  *)
    usage
    die "Unknown command: ${cmd}"
    ;;
esac
