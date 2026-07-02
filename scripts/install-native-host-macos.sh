#!/bin/sh
set -eu

HOST_NAME="com.webhole.host"
EXTENSION_ID="pofdmafekeknglplcgibcepabbncmhbf"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOST_PATH="$SCRIPT_DIR/native-host/host.js"
WRAPPER_PATH="$SCRIPT_DIR/native-host/run-host.sh"
NODE_BIN=${WEBHOLE_NODE:-}

usage() {
  cat <<EOF
Usage: sh scripts/install-native-host-macos.sh [browser...]

Browsers:
  chrome       Google Chrome
  chrome-dev   Google Chrome Dev
  edge         Microsoft Edge
  edge-dev     Microsoft Edge Dev
  all          Install for all supported browsers

Default: chrome
EOF
}

manifest_dir_for_browser() {
  case "$1" in
    chrome)
      printf "%s\n" "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
      ;;
    chrome-dev)
      printf "%s\n" "$HOME/Library/Application Support/Google/Chrome Dev/NativeMessagingHosts"
      ;;
    edge)
      printf "%s\n" "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
      ;;
    edge-dev)
      printf "%s\n" "$HOME/Library/Application Support/Microsoft Edge Dev/NativeMessagingHosts"
      ;;
    *)
      return 1
      ;;
  esac
}

install_for_browser() {
  BROWSER="$1"
  MANIFEST_DIR=$(manifest_dir_for_browser "$BROWSER") || {
    echo "Unsupported browser: $BROWSER" >&2
    usage >&2
    exit 1
  }
  MANIFEST_PATH="$MANIFEST_DIR/$HOST_NAME.json"

  mkdir -p "$MANIFEST_DIR"

  cat > "$MANIFEST_PATH" <<JSON
{
  "name": "$HOST_NAME",
  "description": "Webhole SSH SOCKS5 tunnel controller",
  "path": "$WRAPPER_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXTENSION_ID/"
  ]
}
JSON

  echo "Installed $HOST_NAME for $BROWSER"
  echo "$MANIFEST_PATH"
}

if [ ! -f "$HOST_PATH" ]; then
  echo "Native host not found: $HOST_PATH" >&2
  exit 1
fi

if [ -z "$NODE_BIN" ]; then
  NODE_BIN=$(command -v node 2>/dev/null || true)
fi

if [ -z "$NODE_BIN" ] || [ ! -x "$NODE_BIN" ]; then
  echo "node executable not found. Install Node.js or set WEBHOLE_NODE=/absolute/path/to/node." >&2
  exit 1
fi

cat > "$WRAPPER_PATH" <<EOF
#!/bin/sh
exec "$NODE_BIN" "$HOST_PATH"
EOF

chmod 755 "$HOST_PATH"
chmod 755 "$WRAPPER_PATH"

if [ "$#" -eq 0 ]; then
  set -- chrome
fi

for BROWSER in "$@"; do
  case "$BROWSER" in
    -h|--help)
      usage
      exit 0
      ;;
    all)
      install_for_browser chrome
      install_for_browser chrome-dev
      install_for_browser edge
      install_for_browser edge-dev
      ;;
    *)
      install_for_browser "$BROWSER"
      ;;
  esac
done
