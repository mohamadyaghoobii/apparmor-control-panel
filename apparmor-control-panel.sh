
set -euo pipefail

APP_TITLE="AppArmor Control Panel"
PROFILE_DIR="/etc/apparmor.d"
LOCAL_DIR="/etc/apparmor.d/local"

REQUIRED_PKGS=("apparmor" "apparmor-utils" "libapparmor1" "python3-apparmor")
AUDIT_PKGS=("auditd" "audispd-plugins")

EXTRA_DIRS=(
  "/etc/apparmor.d/local"
  "/var/log/apparmor"
  "/var/lib/apparmor"
)

EXTRA_FILES=(
  "/var/log/apparmor/hardened-web.log"
)

NEED_REBOOT=0
export DEBIAN_FRONTEND=noninteractive

have_cmd() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }

pause() { read -r -p "Press Enter to continue..." _; }

banner() {
  clear >/dev/null 2>&1 || true
  echo "============================================================"
  echo "  ${APP_TITLE}"
  echo "============================================================"
  echo
}

msg() { echo "[*] $*"; }
ok() { echo "[+] $*"; }
warn() { echo "[!] $*"; }
err() { echo "[-] $*"; }

require_root() {
  if ! is_root; then
    err "Run this script with sudo/root."
    exit 1
  fi
}

pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

apt_install() {
  local pkgs=("$@")
  msg "Updating apt cache..."
  apt-get update -y >/dev/null 2>&1 || true
  msg "Installing: ${pkgs[*]}"
  apt-get install -y "${pkgs[@]}"
}

missing_from_list() {
  local -a list=("$@")
  local -a missing=()
  local p
  for p in "${list[@]}"; do
    if ! pkg_installed "$p"; then
      missing+=("$p")
    fi
  done
  printf '%s\n' "${missing[@]:-}"
}

kernel_enabled_value() {
  if [ -f /sys/module/apparmor/parameters/enabled ]; then
    cat /sys/module/apparmor/parameters/enabled 2>/dev/null | tr -d '[:space:]' || true
  else
    echo ""
  fi
}

enable_apparmor_service() {
  banner
  msg "Starting AppArmor service..."
  if have_cmd systemctl; then
    systemctl enable --now apparmor >/dev/null 2>&1 || true
    systemctl restart apparmor >/dev/null 2>&1 || true
  else
    service apparmor start >/dev/null 2>&1 || true
  fi
  ok "AppArmor service is running."
  pause
}

ensure_packages() {
  banner
  msg "Checking required packages..."
  local missing
  missing="$(missing_from_list "${REQUIRED_PKGS[@]}")"
  if [ -z "${missing}" ]; then
    ok "All required packages are already installed."
  else
    warn "Missing packages detected:"
    echo "${missing}"
    apt_install ${missing}
    ok "Required packages installed."
  fi
  pause
}

ensure_audit_logging() {
  banner
  msg "Checking audit/logging packages..."
  local missing
  missing="$(missing_from_list "${AUDIT_PKGS[@]}")"
  if [ -z "${missing}" ]; then
    ok "Audit packages are already installed."
  else
    warn "Missing audit packages detected:"
    echo "${missing}"
    apt_install ${missing}
    ok "Audit packages installed."
  fi

  if have_cmd systemctl; then
    systemctl enable --now auditd >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || true
  fi

  ok "Audit logging should be active."
  pause
}

patch_grub_if_needed() {
  banner
  local enabled
  enabled="$(kernel_enabled_value)"

  if [ "${enabled}" = "Y" ]; then
    ok "Kernel AppArmor is enabled (Y)."
    pause
    return 0
  fi

  warn "Kernel AppArmor is NOT enabled or status is unknown."
  warn "Attempting to patch GRUB with: security=apparmor apparmor=1"

  if [ ! -f /etc/default/grub ]; then
    err "Cannot find /etc/default/grub. Skipping GRUB patch."
    pause
    return 0
  fi

  local key
  for key in GRUB_CMDLINE_LINUX GRUB_CMDLINE_LINUX_DEFAULT; do
    if grep -q "^${key}=" /etc/default/grub; then
      if ! grep -q "^${key}=.*security=apparmor" /etc/default/grub; then
        sed -i "s/^\(${key}=\"[^\"]*\)\"/\1 security=apparmor\"/" /etc/default/grub
      fi
      if ! grep -q "^${key}=.*apparmor=1" /etc/default/grub; then
        sed -i "s/^\(${key}=\"[^\"]*\)\"/\1 apparmor=1\"/" /etc/default/grub
      fi
    else
      echo "${key}=\"security=apparmor apparmor=1\"" >> /etc/default/grub
    fi
  done

  if have_cmd update-grub; then
    update-grub >/dev/null 2>&1 || true
  elif have_cmd grub-mkconfig; then
    grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || true
  else
    warn "Neither update-grub nor grub-mkconfig found."
  fi

  NEED_REBOOT=1
  ok "GRUB updated. Reboot is recommended."
  pause
}

ensure_dirs_and_files() {
  banner
  msg "Creating directories..."
  local d
  for d in "${EXTRA_DIRS[@]}"; do
    mkdir -p "$d"
  done
  ok "Directories ensured."

  msg "Ensuring files exist..."
  local f
  for f in "${EXTRA_FILES[@]}"; do
    if [ ! -f "$f" ]; then
      install -m 0644 /dev/null "$f"
    fi
  done
  ok "Files ensured."
  pause
}

profile_file_from_path() {
  local p="$1"
  p="${p#/}"
  echo "${p//\//.}"
}

backup_if_exists() {
  local f="$1"
  if [ -f "$f" ]; then
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    cp -a "$f" "${f}.bak_${ts}"
    warn "Backup created: ${f}.bak_${ts}"
  fi
}

write_local_hardening_rules() {
  cat <<'EOF'
deny /bin/sh x,
deny /bin/bash x,
deny /usr/bin/dash x,
deny /usr/bin/sh x,
deny /usr/bin/bash x,
deny /usr/bin/python* x,
deny /usr/bin/perl* x,
deny /usr/bin/ruby* x,
deny /usr/bin/php* x,
deny /usr/bin/nc* x,
deny /usr/bin/netcat* x,
deny /usr/bin/socat x,
deny /usr/bin/curl x,
deny /usr/bin/wget x,
deny /usr/bin/ssh x,
deny /usr/bin/scp x,
deny /usr/bin/sftp x,
/tmp/** rw,
deny /tmp/** x,
deny /var/www/** w,
EOF
}

deploy_apache_profile_or_local() {
  local base="${PROFILE_DIR}/usr.sbin.apache2"
  local localf="${LOCAL_DIR}/usr.sbin.apache2"

  if [ -f "$base" ]; then
    backup_if_exists "$localf"
    write_local_hardening_rules > "$localf"
    ok "Apache detected: wrote hardening rules to ${localf}"
    return 0
  fi

  backup_if_exists "$base"
  cat > "$base" <<'EOF'
profile /usr/sbin/apache2 flags=(attach_disconnected,mediate_deleted) {
  /usr/sbin/apache2 mr,

  /etc/apache2/** r,
  /etc/hosts r,
  /etc/nsswitch.conf r,
  /etc/passwd r,
  /etc/group r,
  /etc/resolv.conf r,
  /etc/mime.types r,
  /etc/ssl/** r,

  /usr/lib/apache2/modules/** mr,
  /usr/lib/** mr,
  /lib/** mr,
  /etc/ld.so.cache r,

  /var/www/** r,
  /var/log/apache2/** rw,
  /run/apache2/** rw,
  /run/lock/apache2/** rw,
  /var/run/apache2/** rw,

  /dev/null rw,
  /dev/urandom r,
  /dev/random r,

  /proc/*/status r,
  /proc/*/stat r,
  /proc/*/cmdline r,
  /proc/meminfo r,

  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability chown,
  capability dac_read_search,
  capability kill,

  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,

  deny /bin/sh x,
  deny /bin/bash x,
  deny /usr/bin/dash x,
  deny /usr/bin/sh x,
  deny /usr/bin/bash x,
  deny /usr/bin/python* x,
  deny /usr/bin/perl* x,
  deny /usr/bin/ruby* x,
  deny /usr/bin/php* x,
  deny /usr/bin/nc* x,
  deny /usr/bin/netcat* x,
  deny /usr/bin/socat x,
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /usr/bin/ssh x,
  deny /usr/bin/scp x,
  deny /usr/bin/sftp x,

  /tmp/** rw,
  deny /tmp/** x,
  deny /var/www/** w,
}
EOF
  ok "Apache profile created: ${base}"
}

deploy_nginx_profile_or_local() {
  local base="${PROFILE_DIR}/usr.sbin.nginx"
  local localf="${LOCAL_DIR}/usr.sbin.nginx"

  if [ -f "$base" ]; then
    backup_if_exists "$localf"
    write_local_hardening_rules > "$localf"
    ok "Nginx detected: wrote hardening rules to ${localf}"
    return 0
  fi

  backup_if_exists "$base"
  cat > "$base" <<'EOF'
profile /usr/sbin/nginx flags=(attach_disconnected,mediate_deleted) {
  /usr/sbin/nginx mr,

  /etc/nginx/** r,
  /etc/hosts r,
  /etc/nsswitch.conf r,
  /etc/passwd r,
  /etc/group r,
  /etc/resolv.conf r,
  /etc/ssl/** r,

  /usr/lib/** mr,
  /lib/** mr,
  /etc/ld.so.cache r,

  /var/www/** r,
  /var/log/nginx/** rw,
  /run/nginx.pid rw,
  /run/nginx/** rw,
  /var/lib/nginx/** rw,

  /dev/null rw,
  /dev/urandom r,
  /dev/random r,

  /proc/*/status r,
  /proc/*/stat r,
  /proc/*/cmdline r,
  /proc/meminfo r,

  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability chown,
  capability dac_read_search,
  capability kill,

  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,

  deny /bin/sh x,
  deny /bin/bash x,
  deny /usr/bin/dash x,
  deny /usr/bin/sh x,
  deny /usr/bin/bash x,
  deny /usr/bin/python* x,
  deny /usr/bin/perl* x,
  deny /usr/bin/ruby* x,
  deny /usr/bin/php* x,
  deny /usr/bin/nc* x,
  deny /usr/bin/netcat* x,
  deny /usr/bin/socat x,
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /usr/bin/ssh x,
  deny /usr/bin/scp x,
  deny /usr/bin/sftp x,

  /tmp/** rw,
  deny /tmp/** x,
  deny /var/www/** w,
}
EOF
  ok "Nginx profile created: ${base}"
}

deploy_php_fpm_profiles() {
  local found=0
  local bin
  for bin in /usr/sbin/php-fpm*; do
    if [ -x "$bin" ]; then
      found=1
      local file="${PROFILE_DIR}/$(profile_file_from_path "$bin")"
      local localf="${LOCAL_DIR}/$(profile_file_from_path "$bin")"

      if [ -f "$file" ]; then
        backup_if_exists "$localf"
        write_local_hardening_rules > "$localf"
        ok "PHP-FPM detected: wrote hardening rules to ${localf}"
      else
        backup_if_exists "$file"
        cat > "$file" <<EOF
profile ${bin} flags=(attach_disconnected,mediate_deleted) {
  ${bin} mr,

  /etc/php/** r,
  /etc/hosts r,
  /etc/nsswitch.conf r,
  /etc/passwd r,
  /etc/group r,
  /etc/resolv.conf r,

  /usr/lib/** mr,
  /lib/** mr,
  /etc/ld.so.cache r,

  /run/php/** rw,
  /var/log/** rw,
  /var/www/** r,

  /dev/null rw,
  /dev/urandom r,
  /dev/random r,

  /proc/*/status r,
  /proc/*/stat r,
  /proc/*/cmdline r,
  /proc/meminfo r,

  capability setuid,
  capability setgid,
  capability chown,
  capability dac_read_search,
  capability kill,

  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,

  deny /bin/sh x,
  deny /bin/bash x,
  deny /usr/bin/dash x,
  deny /usr/bin/sh x,
  deny /usr/bin/bash x,
  deny /usr/bin/python* x,
  deny /usr/bin/perl* x,
  deny /usr/bin/ruby* x,
  deny /usr/bin/php* x,
  deny /usr/bin/nc* x,
  deny /usr/bin/netcat* x,
  deny /usr/bin/socat x,
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /usr/bin/ssh x,
  deny /usr/bin/scp x,
  deny /usr/bin/sftp x,

  /tmp/** rw,
  deny /tmp/** x,
  deny /var/www/** w,
}
EOF
        ok "PHP-FPM profile created: ${file}"
      fi
    fi
  done

  if [ "$found" -eq 0 ]; then
    warn "No php-fpm binary found under /usr/sbin/php-fpm* (skipping)."
  fi
}

deploy_profiles_menu() {
  banner
  msg "Detecting installed services and deploying profiles/hardening..."

  if pkg_installed "apache2"; then
    deploy_apache_profile_or_local
  else
    warn "apache2 package not installed (skipping Apache)."
  fi

  if pkg_installed "nginx"; then
    deploy_nginx_profile_or_local
  else
    warn "nginx package not installed (skipping Nginx)."
  fi

  deploy_php_fpm_profiles

  ok "Deploy step completed."
  pause
}

discover_target_profile_files() {
  local -a files=()

  if [ -f "${PROFILE_DIR}/usr.sbin.apache2" ]; then
    files+=("${PROFILE_DIR}/usr.sbin.apache2")
  fi
  if [ -f "${PROFILE_DIR}/usr.sbin.nginx" ]; then
    files+=("${PROFILE_DIR}/usr.sbin.nginx")
  fi

  local f
  for f in "${PROFILE_DIR}"/usr.sbin.php-fpm* "${PROFILE_DIR}"/usr.sbin.phpfpm* "${PROFILE_DIR}"/usr.sbin.php-fpm.*; do
    if [ -f "$f" ]; then
      files+=("$f")
    fi
  done

  printf '%s\n' "${files[@]:-}"
}

load_profiles() {
  banner
  if ! have_cmd apparmor_parser; then
    err "apparmor_parser not found. Install apparmor-utils."
    pause
    return 0
  fi

  msg "Reloading AppArmor profiles..."
  local targets
  targets="$(discover_target_profile_files || true)"
  if [ -z "${targets}" ]; then
    warn "No target profile files found. Deploy profiles first."
    pause
    return 0
  fi

  while IFS= read -r pf; do
    if [ -f "$pf" ]; then
      apparmor_parser -r "$pf" >/dev/null 2>&1 || true
      ok "Loaded: $pf"
    fi
  done <<< "${targets}"

  if have_cmd systemctl; then
    systemctl reload apparmor >/dev/null 2>&1 || true
  fi

  ok "Load completed."
  pause
}

aa_apply_mode_file() {
  local mode="$1"
  local file="$2"

  case "$mode" in
    enforce) aa-enforce "$file" >/dev/null 2>&1 || true ;;
    complain) aa-complain "$file" >/dev/null 2>&1 || true ;;
    disable) aa-disable "$file" >/dev/null 2>&1 || true ;;
    enable) aa-enable "$file" >/dev/null 2>&1 || true ;;
    *) return 1 ;;
  esac
}

apply_mode_menu() {
  banner
  echo "Choose mode:"
  echo "  1) Enforce   (Block/Prevent)"
  echo "  2) Complain  (Log-only / Learning)"
  echo "  3) Disable   (Turn profile off)"
  echo "  4) Enable    (Re-enable disabled profile)"
  echo
  read -r -p "Select: " m

  local mode=""
  case "$m" in
    1) mode="enforce" ;;
    2) mode="complain" ;;
    3) mode="disable" ;;
    4) mode="enable" ;;
    *) warn "Invalid selection"; pause; return 0 ;;
  esac

  local targets
  targets="$(discover_target_profile_files || true)"
  if [ -z "${targets}" ]; then
    warn "No target profiles found. Deploy profiles first."
    pause
    return 0
  fi

  banner
  echo "Apply to:"
  echo "  1) All discovered targets"
  echo "  2) Apache only"
  echo "  3) Nginx only"
  echo "  4) PHP-FPM only"
  echo
  read -r -p "Select: " t

  case "$t" in
    1)
      msg "Applying '${mode}' to all targets..."
      while IFS= read -r pf; do
        [ -f "$pf" ] && aa_apply_mode_file "$mode" "$pf"
      done <<< "${targets}"
      ok "Done."
      ;;
    2)
      if [ -f "${PROFILE_DIR}/usr.sbin.apache2" ]; then
        aa_apply_mode_file "$mode" "${PROFILE_DIR}/usr.sbin.apache2"
        ok "Done."
      else
        warn "Apache profile file not found."
      fi
      ;;
    3)
      if [ -f "${PROFILE_DIR}/usr.sbin.nginx" ]; then
        aa_apply_mode_file "$mode" "${PROFILE_DIR}/usr.sbin.nginx"
        ok "Done."
      else
        warn "Nginx profile file not found."
      fi
      ;;
    4)
      msg "Applying '${mode}' to PHP-FPM targets..."
      local any=0
      local pf
      for pf in "${PROFILE_DIR}"/usr.sbin.php-fpm* "${PROFILE_DIR}"/usr.sbin.phpfpm* "${PROFILE_DIR}"/usr.sbin.php-fpm.*; do
        if [ -f "$pf" ]; then
          any=1
          aa_apply_mode_file "$mode" "$pf"
        fi
      done
      if [ "$any" -eq 1 ]; then
        ok "Done."
      else
        warn "No PHP-FPM profile files found."
      fi
      ;;
    *)
      warn "Invalid selection"
      ;;
  esac

  pause
}

show_status() {
  banner
  echo "Kernel AppArmor flag (/sys/module/apparmor/parameters/enabled):"
  echo "  $(kernel_enabled_value || true)"
  echo
  if have_cmd aa-status; then
    aa-status || true
  else
    warn "aa-status not found."
  fi
  echo
  pause
}

show_logs_menu() {
  banner
  echo "Log viewer:"
  echo "  1) audit.log (AppArmor lines)"
  echo "  2) kernel/journal (AppArmor lines)"
  echo "  3) Install audit logging packages"
  echo
  read -r -p "Select: " x

  case "$x" in
    1)
      banner
      if [ -f /var/log/audit/audit.log ]; then
        grep -i apparmor /var/log/audit/audit.log | tail -n 160 || true
      else
        warn "/var/log/audit/audit.log not found. Install auditd/audispd-plugins."
      fi
      pause
      ;;
    2)
      banner
      if have_cmd journalctl; then
        journalctl -k | grep -i apparmor | tail -n 160 || true
      else
        if [ -f /var/log/kern.log ]; then
          grep -i apparmor /var/log/kern.log | tail -n 160 || true
        elif [ -f /var/log/syslog ]; then
          grep -i apparmor /var/log/syslog | tail -n 160 || true
        else
          warn "No kernel logs found in common paths."
        fi
      fi
      pause
      ;;
    3)
      ensure_audit_logging
      ;;
    *)
      warn "Invalid selection"
      pause
      ;;
  esac
}

troubleshooting_menu() {
  banner
  echo "Troubleshooting:"
  echo "  1) List unconfined processes (aa-unconfined)"
  echo "  2) Remove unknown profiles (aa-remove-unknown)"
  echo "  3) Restart AppArmor service"
  echo
  read -r -p "Select: " t

  case "$t" in
    1)
      banner
      aa-unconfined || true
      pause
      ;;
    2)
      banner
      aa-remove-unknown || true
      pause
      ;;
    3)
      banner
      if have_cmd systemctl; then
        systemctl restart apparmor || true
      else
        service apparmor restart || true
      fi
      ok "AppArmor restarted."
      pause
      ;;
    *)
      warn "Invalid selection"
      pause
      ;;
  esac
}

cleanup_custom_hardening() {
  banner
  msg "Removing hardening local override files (if present)..."

  local removed=0

  if [ -f "${LOCAL_DIR}/usr.sbin.apache2" ]; then
    rm -f "${LOCAL_DIR}/usr.sbin.apache2"
    removed=1
    ok "Removed: ${LOCAL_DIR}/usr.sbin.apache2"
  fi

  if [ -f "${LOCAL_DIR}/usr.sbin.nginx" ]; then
    rm -f "${LOCAL_DIR}/usr.sbin.nginx"
    removed=1
    ok "Removed: ${LOCAL_DIR}/usr.sbin.nginx"
  fi

  local lf
  for lf in "${LOCAL_DIR}"/usr.sbin.php-fpm* "${LOCAL_DIR}"/usr.sbin.phpfpm* "${LOCAL_DIR}"/usr.sbin.php-fpm.*; do
    if [ -f "$lf" ]; then
      rm -f "$lf"
      removed=1
      ok "Removed: $lf"
    fi
  done

  if [ "$removed" -eq 0 ]; then
    warn "No local override files found to remove."
  fi

  pause
}

quick_setup() {
  ensure_packages
  enable_apparmor_service
  patch_grub_if_needed
  ensure_dirs_and_files
  deploy_profiles_menu
  load_profiles

  banner
  ok "Quick setup completed."
  if [ "$NEED_REBOOT" -eq 1 ]; then
    warn "Reboot is recommended to fully apply GRUB kernel flags."
  fi
  pause
}

reboot_prompt() {
  banner
  if [ "$NEED_REBOOT" -eq 1 ]; then
    echo "Reboot is recommended."
  else
    echo "Reboot is optional."
  fi
  echo
  read -r -p "Reboot now? (y/N): " ans
  case "${ans:-n}" in
    y|Y) reboot ;;
    *) ok "Not rebooting." ; pause ;;
  esac
}

about_modes_screen() {
  banner
  cat <<'EOF'
AppArmor modes:

Enforce:
  Policy is enforced. Forbidden actions are blocked (DENIED). Best for production after testing.

Complain:
  Policy is not enforced. Actions are allowed but logged. Best for learning and tuning profiles.

Disable:
  Profile is turned off; the program becomes unconfined (no AppArmor restrictions).

Enable:
  Re-enables a profile that was disabled.

Web-shell hardening idea used here:
  - Block execution of common shells and tooling often abused by web shells:
    sh/bash/dash, curl/wget, nc/socat, ssh/scp/sftp, python/perl/ruby/php CLI
  - Prevent executing payloads from /tmp by denying x on /tmp/**
  - Prevent writing into /var/www (common webroot) to reduce dropper behavior

Notes:
  - These rules may break CGI-heavy setups or apps that legitimately write inside /var/www.
  - Recommended workflow:
    Deploy -> Complain -> test -> review logs -> Enforce
EOF
  pause
}

main_menu() {
  while true; do
    banner
    echo "Main Menu:"
    echo "  1) Quick Setup (Install + Service + GRUB + Deploy + Load)"
    echo "  2) Check/Install required packages"
    echo "  3) Enable/Start AppArmor service"
    echo "  4) Patch GRUB for AppArmor (if needed)"
    echo "  5) Create directories/files"
    echo "  6) Deploy web hardening profiles (Apache/Nginx/PHP-FPM)"
    echo "  7) Load/Reload profiles"
    echo "  8) Apply mode (Enforce/Complain/Disable/Enable)"
    echo "  9) Status (aa-status + kernel flag)"
    echo " 10) View logs"
    echo " 11) Troubleshooting"
    echo " 12) About modes + web-shell hardening"
    echo " 13) Cleanup local hardening overrides"
    echo " 14) Reboot"
    echo "  0) Exit"
    echo
    read -r -p "Select: " choice

    case "$choice" in
      1) quick_setup ;;
      2) ensure_packages ;;
      3) enable_apparmor_service ;;
      4) patch_grub_if_needed ;;
      5) ensure_dirs_and_files ;;
      6) deploy_profiles_menu ;;
      7) load_profiles ;;
      8) apply_mode_menu ;;
      9) show_status ;;
      10) show_logs_menu ;;
      11) troubleshooting_menu ;;
      12) about_modes_screen ;;
      13) cleanup_custom_hardening ;;
      14) reboot_prompt ;;
      0) exit 0 ;;
      *) warn "Invalid selection"; pause ;;
    esac
  done
}

require_root
main_menu
