#!/usr/bin/env bash
# ajar setup for Raspberry Pi OS and Debian: installs ajar as a service that
# starts on boot. Run it from the ajar folder:
#
#   sudo ./setup.sh               install, or upgrade after a git pull
#   sudo ./setup.sh --password    change the dashboard password
#   sudo ./setup.sh --uninstall   remove the service and program, keep your data
#   sudo ./setup.sh --purge       remove everything, including your data
#   sudo ./setup.sh --dry-run     show what it would do, change nothing
#
# What it sets up:
#   /opt/ajar          the program (read-only to the service)
#   /var/lib/ajar      your data: device history, password, HTTPS certificate
#   ajar user          the service runs as this user, not as root, holding only the
#                         two network permissions nmap needs (CAP_NET_RAW, CAP_NET_ADMIN)
#   ajar.service       starts on boot, restarts if it stops
set -euo pipefail

APP=/opt/ajar
DATA=/var/lib/ajar
USER_NAME=ajar
UNIT=/etc/systemd/system/ajar.service
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY=0
MODE=install

for arg in "$@"; do
  case "$arg" in
    --password) MODE=password ;;
    --uninstall) MODE=uninstall ;;
    --purge) MODE=purge ;;
    --dry-run) DRY=1 ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg (try --help)"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mStopped:\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY" = 1 ]; then printf '  would run: %s\n' "$*"; else "$@"; fi; }
trap 'code=$?; [ $code -ne 0 ] && printf "\n\033[31mStopped:\033[0m setup failed at line %s (exit %s). Nothing after that step was changed.\n" "$LINENO" "$code" >&2' EXIT

# ---------------------------------------------------------------- checks
[ "$(uname -s)" = Linux ] || die "This script is for Linux (Raspberry Pi OS or Debian). On Windows or macOS, run python ajar.py instead."
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then die "Run it with sudo:  sudo ./setup.sh"; fi
command -v systemctl >/dev/null || die "systemd was not found, so ajar can't be set up as a service here."
[ -f "$SRC/ajar.py" ] && [ -d "$SRC/aj" ] && [ -d "$SRC/web" ] || die "Run this from the ajar folder (the one with ajar.py, aj/ and web/)."

# ---------------------------------------------------------------- change password
if [ "$MODE" = password ]; then
  [ -f "$APP/ajar.py" ] || die "ajar isn't installed yet. Run sudo ./setup.sh first."
  [ -t 0 ] || die "Run this in a terminal, so you can type the new password."
  run sudo -u "$USER_NAME" env AJAR_DATA="$DATA" python3 "$APP/ajar.py" --set-password
  run systemctl restart ajar.service
  ok "Password changed. Sign in again with the new one."
  exit 0
fi

# ---------------------------------------------------------------- uninstall
if [ "$MODE" != install ]; then
  say "Removing ajar"
  if systemctl list-unit-files ajar.service >/dev/null 2>&1; then
    run systemctl disable --now ajar.service || true
  fi
  run rm -f "$UNIT"
  run systemctl daemon-reload
  run rm -rf "$APP"
  ok "Service and program removed"
  if [ "$MODE" = purge ]; then
    run rm -rf "$DATA"
    if id "$USER_NAME" >/dev/null 2>&1; then run userdel "$USER_NAME"; fi
    ok "Data in $DATA and the $USER_NAME user removed"
  else
    ok "Your data is still in $DATA (use --purge to remove it too)"
  fi
  exit 0
fi

# ---------------------------------------------------------------- retire the old name
# Ajar used to be called wifimap. Remove its old service and move its data over.
if systemctl list-unit-files wifimap.service >/dev/null 2>&1; then
  say "Retiring the old wifimap service"
  run systemctl disable --now wifimap.service || true
  run rm -f /etc/systemd/system/wifimap.service
  run systemctl daemon-reload
  ok "Old wifimap service removed (its data is kept)"
fi
if [ -d /var/lib/wifimap ] && [ ! -d "$DATA" ]; then
  run mv /var/lib/wifimap "$DATA"
  for old in "$DATA"/wifimap.*; do [ -e "$old" ] && run mv "$old" "${old/wifimap./ajar.}"; done
  ok "Moved your data from /var/lib/wifimap to $DATA"
fi
run rm -rf /opt/wifimap

# ---------------------------------------------------------------- packages
say "1. Tools ajar needs"
PKGS=()
command -v python3 >/dev/null || PKGS+=(python3)
command -v nmap >/dev/null || PKGS+=(nmap)
command -v openssl >/dev/null || PKGS+=(openssl)
command -v iw >/dev/null || PKGS+=(iw)
command -v snmpget >/dev/null || PKGS+=(snmp)
if [ ${#PKGS[@]} -gt 0 ]; then
  echo "  Installing: ${PKGS[*]}"
  run apt-get update -qq
  run apt-get install -y -qq "${PKGS[@]}"
fi
if [ "$DRY" = 0 ]; then
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "ajar needs Python 3.8 or newer."
fi
if [ "$DRY" = 0 ]; then
  for t in python3 nmap openssl; do
    command -v "$t" >/dev/null || die "$t still isn't installed. Try: sudo apt-get install $t"
  done
fi
ok "python3, nmap, openssl, iw and snmp are installed"
if command -v nmcli >/dev/null; then ok "NetworkManager (nmcli) found for WiFi scanning"; else warn "No NetworkManager; WiFi scanning will use iw"; fi

# ---------------------------------------------------------------- WiFi radio
say "2. WiFi radio"
if command -v raspi-config >/dev/null; then
  COUNTRY="$(raspi-config nonint get_wifi_country 2>/dev/null || true)"
  if [ -n "$COUNTRY" ]; then
    ok "WiFi country is set ($COUNTRY)"
  else
    warn "No WiFi country set, so the radio stays blocked and the WiFi tab will be empty."
    warn "Fix: sudo raspi-config, then Localisation Options, then WLAN Country. Then run this script again."
  fi
fi
if command -v rfkill >/dev/null && rfkill list wifi 2>/dev/null | grep -q "Soft blocked: yes"; then
  warn "The WiFi radio is switched off (soft blocked). Turn it on with: sudo rfkill unblock wifi"
elif command -v rfkill >/dev/null && rfkill list wifi 2>/dev/null | grep -q "Wireless"; then
  ok "WiFi radio is on"
fi
DEV="$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
case "$DEV" in
  wl*) warn "This computer reaches your router over WiFi ($DEV). Ethernet is steadier and leaves the radio free for scanning." ;;
  "")  warn "No network connection found. Connect the Pi to your router, ideally by ethernet." ;;
  *)   ok "Connected to your router by $DEV" ;;
esac

# ---------------------------------------------------------------- user and folders
say "3. Service user and folders"
if id "$USER_NAME" >/dev/null 2>&1; then
  ok "User $USER_NAME exists"
else
  run useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
  ok "Created user $USER_NAME (can't log in; only runs ajar)"
fi
run install -d -o "$USER_NAME" -g "$USER_NAME" -m 700 "$DATA"
ok "Data folder $DATA (only $USER_NAME can read it)"

# Earlier test runs kept data next to the code. Bring it along once.
for f in ajar.db ajar.auth ajar.crt ajar.key; do
  src="$SRC/$f"
  # Ajar was once called wifimap; bring an old-named file over under the new name.
  [ -f "$src" ] || src="$SRC/${f/ajar./wifimap.}"
  if [ -f "$src" ] && [ ! -f "$DATA/$f" ]; then
    run install -o "$USER_NAME" -g "$USER_NAME" -m 600 "$src" "$DATA/$f"
    ok "Moved over your data as $f"
  fi
done

# ---------------------------------------------------------------- program
say "4. Program"
if [ "$DRY" = 0 ]; then
  STAGE="$(mktemp -d)"
  cp -r "$SRC/ajar.py" "$SRC/aj" "$SRC/web" "$STAGE/"
  [ -f "$SRC/README.md" ] && cp "$SRC/README.md" "$STAGE/"
  find "$STAGE" -name __pycache__ -prune -exec rm -rf {} +
  rm -rf "$APP.new" && mv "$STAGE" "$APP.new"
  chown -R root:root "$APP.new" && chmod -R u=rwX,go=rX "$APP.new"
  rm -rf "$APP" && mv "$APP.new" "$APP"
else
  echo "  would copy ajar.py, aj/ and web/ to $APP (owned by root, read-only to the service)"
fi
ok "Installed to $APP"

# ---------------------------------------------------------------- password
say "5. Dashboard password"
if [ -f "$DATA/ajar.auth" ]; then
  ok "A password is already set (change it with: sudo ./setup.sh --password)"
elif [ "$DRY" = 1 ]; then
  echo "  would ask you to choose a password"
else
  [ -t 0 ] || die "No password set yet, and there's no keyboard here to type one. Run sudo ./setup.sh in a terminal."
  sudo -u "$USER_NAME" env AJAR_DATA="$DATA" python3 "$APP/ajar.py" --set-password ||
    die "The password wasn't saved. Run sudo ./setup.sh again."
fi

# ---------------------------------------------------------------- service
say "6. Service"
UNIT_TEXT="[Unit]
Description=Ajar network mapper and WiFi checker
Documentation=file://$APP/README.md
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
User=$USER_NAME
Group=$USER_NAME
Environment=AJAR_DATA=$DATA
Environment=HOME=$DATA
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=$DATA
ExecStart=/usr/bin/env python3 $APP/ajar.py
Restart=on-failure
RestartSec=10

# Least privilege: not root, only the two network permissions nmap needs.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
# Everything but the data folder is read-only to the service.
ProtectSystem=strict
ReadWritePaths=$DATA
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
"
if [ "$DRY" = 1 ]; then
  echo "  would write $UNIT:"; printf '%s' "$UNIT_TEXT" | sed 's/^/    /'
else
  printf '%s' "$UNIT_TEXT" > "$UNIT"
fi
run systemctl daemon-reload
run systemctl enable ajar.service
run systemctl restart ajar.service
ok "ajar.service installed, enabled at boot, and (re)started"

# ---------------------------------------------------------------- done
if [ "$DRY" = 1 ]; then say "Dry run finished. Nothing was changed."; exit 0; fi
say "7. Checking it started"
for _ in $(seq 1 20); do
  [ -f "$DATA/ajar.crt" ] && systemctl is-active --quiet ajar.service && break
  sleep 1
done
if ! systemctl is-active --quiet ajar.service; then
  echo; journalctl -u ajar.service -n 20 --no-pager || true
  die "The service didn't stay running. The log above says why."
fi
ok "Running"
IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
SCHEME=https; [ -f "$DATA/ajar.crt" ] || SCHEME=http
echo
echo "  Open the dashboard:   $SCHEME://${IP:-this-pi}:8080   or   $SCHEME://$(hostname).local:8080"
if [ -f "$DATA/ajar.crt" ]; then
  FP="$(openssl x509 -in "$DATA/ajar.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
  echo "  Certificate fingerprint (compare with your browser's warning page):"
  echo "    $FP"
fi
echo
echo "  Useful commands:"
echo "    systemctl status ajar          is it running?"
echo "    journalctl -u ajar -f          watch its log"
echo "    sudo systemctl restart ajar    restart it"
echo "    git pull && sudo ./setup.sh       upgrade to the latest version"
echo "    sudo ./setup.sh --password        change the dashboard password"
