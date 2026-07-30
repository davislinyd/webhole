#!/bin/sh
# Enable Touch ID for sudo on macOS (pam_tid).
# One-time setup. After this, interactive `sudo` can use fingerprint.
# Webhole's resolver install still uses the system admin dialog, which also
# offers Touch ID on MacBooks when biometrics are enrolled.
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This script is macOS-only." >&2
  exit 1
fi

SUDO_LOCAL="/etc/pam.d/sudo_local"
TEMPLATE="/etc/pam.d/sudo_local.template"

if [ -f "$SUDO_LOCAL" ] && grep -q 'pam_tid.so' "$SUDO_LOCAL" 2>/dev/null; then
  echo "Touch ID for sudo already enabled in $SUDO_LOCAL"
  exit 0
fi

echo "This will enable Touch ID authentication for sudo (requires admin once)."
echo "File: $SUDO_LOCAL"
echo ""

if [ -f "$TEMPLATE" ]; then
  # Apple ships a template on recent macOS; uncomment pam_tid line if present.
  TMP="$(mktemp)"
  # shellcheck disable=SC2002
  cat "$TEMPLATE" | sed -e 's/^#auth/auth/' -e 's/^# auth/auth/' >"$TMP"
  if ! grep -q 'pam_tid.so' "$TMP"; then
    printf '%s\n' \
      "# Webhole: Touch ID for sudo" \
      "auth       sufficient     pam_tid.so" \
      "" \
      "$(cat "$TMP")" >"${TMP}.out"
    mv "${TMP}.out" "$TMP"
  fi
  sudo cp "$TMP" "$SUDO_LOCAL"
  rm -f "$TMP"
else
  # Fallback for older systems that only have /etc/pam.d/sudo
  TMP="$(mktemp)"
  printf '%s\n' \
    "# Webhole: enable Touch ID for sudo" \
    "auth       sufficient     pam_tid.so" \
    >"$TMP"
  if [ -f /etc/pam.d/sudo ]; then
    echo "Note: modern macOS prefers $SUDO_LOCAL over editing /etc/pam.d/sudo"
  fi
  sudo cp "$TMP" "$SUDO_LOCAL"
  rm -f "$TMP"
fi

sudo chmod 444 "$SUDO_LOCAL" 2>/dev/null || true
echo "Done. Test in Terminal: sudo -v  (should offer Touch ID)"
echo "Then retry Webhole DNS On / Reinstall resolver."
