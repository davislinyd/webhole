# Webhole

Minimal Manifest V3 Chrome extension for controlling a local SSH SOCKS5 tunnel through a Native Messaging Host.

## Flow

```mermaid
sequenceDiagram
    participant U as User
    participant P as Popup
    participant B as Background
    participant H as Native Host
    participant S as ssh / SOCKS5 :1080

    U->>P: 按 On
    P->>P: 顯示 Connecting...
    P->>B: sendMessage(connect, hostAlias, mode, domains)
    B->>H: sendNativeMessage(connect)
    H->>H: 驗證 Host alias
    H->>S: spawn ssh -N -n -D 127.0.0.1:1080 ...
    H->>H: 寫入 state.json / ssh.log
    H->>S: 等待 127.0.0.1:1080 listen
    H-->>B: connected / error
    B->>B: 套用 Chrome proxy
    B-->>P: 回傳狀態
    P-->>U: 顯示 Tunnel connected / error
```

```mermaid
flowchart LR
    U[User] --> P[popup.html / popup.js]
    P --> B[background.js]
    B --> H[native-host/host.js]
    H --> S[ssh -D 127.0.0.1:1080]
    B --> C[chrome.proxy.settings]
    P --> L[chrome.storage.local logs]
    B --> L
    H --> R[native-host/runtime/state.json\nnative-host/runtime/ssh.log]

    X[scripts/install-native-host-macos.sh] --> M[Browser Native Messaging manifest]
    M --> H
```

## File Roles

- `popup.html`: UI 版面、說明、Log、操作按鈕。
- `popup.js`: 讀寫 storage、送 connect/disconnect/status、更新畫面與 log。
- `background.js`: 接 popup 訊息、呼叫 native host、套用或清除 Chrome proxy。
- `native-host/host.js`: 執行 `ssh`，管理 PID，檢查 `1080`，回傳 native messaging response。
- `scripts/install-native-host-macos.sh`: 安裝 browser native host manifest，建立 wrapper，支援 `chrome`、`chrome-dev`、`edge`、`edge-dev`。
- `.gitignore`: 排除 runtime 與本機產物。

## Install

```sh
sh scripts/install-native-host-macos.sh chrome-dev
```

Then load the unpacked extension from:

```text
<project-root>
```
