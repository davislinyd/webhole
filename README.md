# Webhole

Manifest V3 Chrome extension (**v0.4.0**) for:

1. **SSH SOCKS5 tunnels** (Global / Routes)  
2. **DNS Enforce** — domain → nameserver，且 **瀏覽器必須走你設定的 DNS**（方案 D）

## 為什麼需要 DNS Enforce？

只開 local stub **不會**自動讓 Chrome 用它。系統 VPN DNS、Chrome 安全 DNS (DoH)、SOCKS **遠端解析** 都會繞過規則。

v0.4 **三閘**（DNS On 且 Enforce 預設開）：

| 閘 | 行為 |
|----|------|
| **OS** | 自動寫 `/etc/resolver/<domain>` → `127.0.0.1:53535`，並 flush cache |
| **Chrome DoH** | 嘗試 `secureDNSMode=off`（需 `privacy` 權限） |
| **Proxy** | Global/Routes 時走本機 **HTTP CONNECT gateway**：只問 stub 再連 SOCKS（禁止遠端 DNS） |

## Modes (proxy)

| Mode | Behavior |
|------|----------|
| **Direct** | Clear browser proxy（僅 DNS 時靠 resolver + DoH off） |
| **Global** | 全部流量經 Default SSH Host（Enforce 時經 gateway） |
| **Routes** | 規則命中走對應 SSH Host；未匹配 DIRECT 或 Default |

## Split DNS

| 項目 | 預設 |
|------|------|
| Stub | `127.0.0.1:53535` |
| Enforce | **On** |
| 規則 | suffix → Direct IP 或 Via SSH (`ssh -L`) |
| Default NS | 未命中規則（例 `1.1.1.1`） |
| 命中規則且上游無答案 | **NXDOMAIN**（避免 macOS fallback 公司 DNS） |

### 驗收範例（內網名）

**負向**（應解不到、網頁失敗）：

1. 規則：`opscenter.cit.insea.io` → Direct `1.1.1.1`  
2. **DNS On**（admin 裝 resolver、DoH off）  
3. 檢查：
   ```sh
   dig @127.0.0.1 -p 53535 opscenter.cit.insea.io +short   # 空
   dig opscenter.cit.insea.io +short                       # 應為空
   ```
4. Chrome 開該站 → 應失敗  

**正向**：

1. 同 domain → Direct `10.24.11.11`（或你的公司 DNS）  
2. dig / Chrome 應得到內網 IP 並可連  

## Architecture (SVG)

![Webhole architecture](output/webhole-architecture.svg)

![DNS Enforce query / gateway flow](output/webhole-dns-flow.svg)

## Install

```sh
sh scripts/install-native-host-macos.sh chrome-dev
```

Chrome → 載入未封裝 extension（專案根目錄）。  
DNS On 會要求 **管理員密碼**（寫 `/etc/resolver`）。

## File roles

- `popup.html` / `popup.js` — UI（Routes + DNS Enforce）  
- `background.js` — PAC / gateway / DoH / native messaging  
- `native-host/host.js` — tunnels、dns-daemon、resolver、gateway 生命週期  
- `native-host/dns-daemon.js` — stub  
- `native-host/proxy-gateway.js` — resolve-then-proxy CONNECT  

## Notes

- Nameserver 必須是 **IPv4**。  
- DNS Off 會卸 resolver、停 gateway，並嘗試還原 Secure DNS。  
- Popup Enforce 狀態列：`stub` / `resolver` / `DoH` / `gw`。  
- 日誌：`native-host/runtime/dns.log`、`gateway.log`、`ssh.log`。  
- Max：8 tunnels、50 routes、50 DNS rules。  
