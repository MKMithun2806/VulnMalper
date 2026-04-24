# 🛡️  VulnMalper Report

> **Target:** `192.168.1.15` | **Generated:** 2026-04-24 08:55:54 UTC | **Engine:** VulnMalper v2.6.1

> 🔴 CRITICAL EXPOSURE | **151** findings across **8/10** alive targets | scan took **1823.8s**

---

## 🧭 Table of Contents

- [Target Fingerprints](#-target-fingerprints)
- [Findings](#-findings)
- [Scan Metadata](#-scan-metadata)
  - [🟠 `192.168.1.15:445` _(69)_](#target-192-168-1-15-445)
  - [🟠 `http://192.168.1.15:9090/api/v1/status/config` _(2)_](#target-192-168-1-15-9090-api-v1-status-config)
  - [🟠 `http://192.168.1.15:9090/debug/pprof/` _(1)_](#target-192-168-1-15-9090-debug-pprof)
  - [🟡 `http://192.168.1.15:8080/` _(16)_](#target-192-168-1-15-8080)
  - [🟡 `http://192.168.1.15:9090/` _(7)_](#target-192-168-1-15-9090)
  - [🟡 `http://192.168.1.15/site.webmanifest` _(1)_](#target-192-168-1-15-site-webmanifest)
  - [🟡 `http://192.168.1.15:9090/api/v1/status/flags` _(1)_](#target-192-168-1-15-9090-api-v1-status-flags)
  - [🟡 `http://192.168.1.15:9090/api/v1/targets` _(1)_](#target-192-168-1-15-9090-api-v1-targets)
  - [🔵 `http://192.168.1.15/` _(20)_](#target-192-168-1-15)
  - [🔵 `http://192.168.1.15:8081/` _(6)_](#target-192-168-1-15-8081)
  - [🔵 `http://192.168.1.15:8501/` _(6)_](#target-192-168-1-15-8501)
  - [🔵 `http://192.168.1.15/robots.txt/robots.txt` _(2)_](#target-192-168-1-15-robots-txt-robots-txt)
  - [🔵 `http://192.168.1.15:9090/debug/pprof/heap` _(1)_](#target-192-168-1-15-9090-debug-pprof-heap)
  - [🔵 `192.168.1.15:9443` _(1)_](#target-192-168-1-15-9443)
  - [🔵 `http://192.168.1.15:9090/api/v1/status/buildinfo` _(1)_](#target-192-168-1-15-9090-api-v1-status-buildinfo)
  - [🔵 `http://192.168.1.15:9090/metrics` _(1)_](#target-192-168-1-15-9090-metrics)
  - [⚪ `http://192.168.1.15/robots.txt` _(11)_](#target-192-168-1-15-robots-txt)
  - [⚪ `https://192.168.1.15:9443/` _(2)_](#target-192-168-1-15-9443)
  - [⚪ `http://192.168.1.15:9000/` _(2)_](#target-192-168-1-15-9000)

---

## 🔍 Target Fingerprints

<details><summary><b>🟢 <code>http://192.168.1.15/</code></b> | <code>http/80</code> | status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `80` / `http` |
| Service | `http` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | `Next.js`, `Node.js`, `React`, `Webpack` |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>http://192.168.1.15/robots.txt</code></b> | <code>http/80</code> | status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `80` / `http` |
| Service | `http` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🔴 <code>http://192.168.1.15:6767/</code></b> | <code>http/6767</code> | status: <b>n/a</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `6767` / `http` |
| Service | `http` |
| Product | `nginx` |
| HTTP Status | `n/a` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>http://192.168.1.15:8080/</code></b> | <code>http/8080</code> | status: <b>401</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `8080` / `http` |
| Service | `http-proxy` |
| Product | `—` |
| HTTP Status | `401` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>http://192.168.1.15:8081/</code></b> | <code>http/8081</code> | status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `8081` / `http` |
| Service | `http` |
| Product | `nginx` |
| HTTP Status | `200` |
| Detected Tech | `Nginx:1.26.2` |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🔴 <code>https://192.168.1.15:8443/</code></b> | <code>https/8443</code> | status: <b>n/a</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `8443` / `https` |
| Service | `https-alt` |
| Product | `—` |
| HTTP Status | `n/a` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>http://192.168.1.15:8501/</code></b> | <code>http/8501</code> | status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `8501` / `http` |
| Service | `http` |
| Product | `Tornado httpd` |
| HTTP Status | `200` |
| Detected Tech | `TornadoServer:6.5.5` |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>http://192.168.1.15:9000/</code></b> | <code>http/9000</code> | status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `9000` / `http` |
| Service | `cslistener` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>http://192.168.1.15:9090/</code></b> | <code>http/9090</code> | status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `9090` / `http` |
| Service | `zeus-admin` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>https://192.168.1.15:9443/</code></b> | <code>https/9443</code> | status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `192.168.1.15` |
| Port / Scheme | `9443` / `https` |
| Service | `tungsten-https` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

---

## 🎯 Findings

<a id="target-192-168-1-15-445"></a>
### 🌐 `192.168.1.15:445`

**69 finding(s)** | 🟠`4` 🟡`3` 🔵`62`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟠 **HIGH** | `nuclei` | SMB Anonymous Access Detection |
| 2 | 🟠 **HIGH** | `nuclei` | SMB Anonymous Access Detection |
| 3 | 🟠 **HIGH** | `nuclei` | SMB Anonymous Access Detection |
| 4 | 🟠 **HIGH** | `nuclei` | SMB Anonymous Access Detection |
| 5 | 🟡 **MEDIUM** | `nuclei` | SMB Signing Not Required |
| 6 | 🟡 **MEDIUM** | `nuclei` | SMB Signing Not Required |
| 7 | 🟡 **MEDIUM** | `nuclei` | SMB Signing Not Required |
| 8 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 9 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 10 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 11 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 12 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 13 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 14 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 15 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 16 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 17 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 18 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 19 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 20 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 21 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 22 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 23 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 24 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 25 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 26 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 27 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 28 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 29 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 30 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 31 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 32 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 33 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 34 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 35 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 36 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 37 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 38 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 39 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 40 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 41 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 42 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 43 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 44 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 45 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 46 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 47 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 48 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 49 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 50 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 51 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 52 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 53 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 54 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 55 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 56 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 57 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 58 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 59 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 60 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 61 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 62 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 63 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 64 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 65 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 66 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 67 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 68 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |
| 69 | 🔵 **LOW** | `nuclei` | SMB Shares - Enumeration |

#### Detailed Findings

<details><summary><b>#1</b> 🟠 <img src="https://img.shields.io/badge/HIGH-D7263D?style=flat-square" height="18" alt="🟠 high"> <code>nuclei</code> — SMB Anonymous Access Detection</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://wadcoms.github.io/wadcoms/SMBClient-List-Shares-Anonymous/ |

**Evidence:**

```
Detects anonymous access to SMB shares on a remote server.
```

</details>

<details><summary><b>#2</b> 🟠 <img src="https://img.shields.io/badge/HIGH-D7263D?style=flat-square" height="18" alt="🟠 high"> <code>nuclei</code> — SMB Anonymous Access Detection</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://wadcoms.github.io/wadcoms/SMBClient-List-Shares-Anonymous/ |

**Evidence:**

```
Detects anonymous access to SMB shares on a remote server.
```

</details>

<details><summary><b>#3</b> 🟠 <img src="https://img.shields.io/badge/HIGH-D7263D?style=flat-square" height="18" alt="🟠 high"> <code>nuclei</code> — SMB Anonymous Access Detection</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://wadcoms.github.io/wadcoms/SMBClient-List-Shares-Anonymous/ |

**Evidence:**

```
Detects anonymous access to SMB shares on a remote server.
```

</details>

<details><summary><b>#4</b> 🟠 <img src="https://img.shields.io/badge/HIGH-D7263D?style=flat-square" height="18" alt="🟠 high"> <code>nuclei</code> — SMB Anonymous Access Detection</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://wadcoms.github.io/wadcoms/SMBClient-List-Shares-Anonymous/ |

**Evidence:**

```
Detects anonymous access to SMB shares on a remote server.
```

</details>

<details><summary><b>#5</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>nuclei</code> — SMB Signing Not Required</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://www.tenable.com/plugins/nessus/57608, https://nmap.org/nsedoc/scripts/smb2-security-mode.html |

**Evidence:**

```
Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.
```

</details>

<details><summary><b>#6</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>nuclei</code> — SMB Signing Not Required</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://www.tenable.com/plugins/nessus/57608, https://nmap.org/nsedoc/scripts/smb2-security-mode.html |

**Evidence:**

```
Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.
```

</details>

<details><summary><b>#7</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>nuclei</code> — SMB Signing Not Required</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://www.tenable.com/plugins/nessus/57608, https://nmap.org/nsedoc/scripts/smb2-security-mode.html |

**Evidence:**

```
Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.
```

</details>

<details><summary><b>#8</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#9</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#10</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#11</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#12</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#13</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#14</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#15</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#16</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#17</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#18</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#19</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#20</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#21</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#22</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#23</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#24</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#25</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#26</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#27</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#28</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#29</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#30</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#31</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#32</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#33</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#34</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#35</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#36</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#37</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#38</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#39</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#40</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#41</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#42</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#43</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#44</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#45</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#46</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#47</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#48</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#49</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#50</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#51</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#52</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#53</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#54</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#55</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#56</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#57</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#58</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#59</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#60</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#61</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#62</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#63</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#64</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#65</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#66</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#67</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#68</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

<details><summary><b>#69</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — SMB Shares - Enumeration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:445` |
| **Reference** | https://nmap.org/nsedoc/scripts/smb-enum-shares.html |

**Evidence:**

```
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
```

</details>

---

<a id="target-192-168-1-15-9090-api-v1-status-config"></a>
### 🌐 `http://192.168.1.15:9090/api/v1/status/config`

**2 finding(s)** | 🟠`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟠 **HIGH** | `chain:prometheus` | Prometheus config exposed (secrets/scrape targets) |
| 2 | 🟠 **HIGH** | `nuclei` | Prometheus Monitoring System - Unauthenticated |

#### Detailed Findings

<details><summary><b>#1</b> 🟠 <img src="https://img.shields.io/badge/HIGH-D7263D?style=flat-square" height="18" alt="🟠 high"> <code>chain:prometheus</code> — Prometheus config exposed (secrets/scrape targets)</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `chain:prometheus` |
| **Target** | `http://192.168.1.15:9090/api/v1/status/config` |
| **Reference** | Service chain probe — port 9090 (Prometheus) |

**Evidence:**

```
GET http://192.168.1.15:9090/api/v1/status/config
HTTP/1.1 200

�  	n� ��T�n�<|��o��A�{�E�E/\-m��IC�6I��{!���A�Ko9�3��Џ�(h��V��G��j
�}�`�����;�vKƈO0����i/e��0"g��m�4 f���.4������ 1�4��hM��fՐ@��D�O0�5D�-�L�묮��[s}��E�g�B/vK�ws7k��X��Y�(��X�)ψ&�?V����r�{������b�O��=�"ʘ��8!}�g!_�^ۺ����n���|J<���,y��w��1��A�"�G	�e�g:`�HN���w+�q��&������<�{Ӄ�Tb$�Et��)�H`:��fY�P<L���� F��d�6��:.�K�	����)�.��r&��U歐z��*K��^���M�����m���0p|�ޛ�������-���.�3��܌&P���J{L�9���V�>��8�)�����(h�9?w�����t@7�a���ӫ��_   �� ,�|  
```

</details>

<details><summary><b>#2</b> 🟠 <img src="https://img.shields.io/badge/HIGH-D7263D?style=flat-square" height="18" alt="🟠 high"> <code>nuclei</code> — Prometheus Monitoring System - Unauthenticated</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `nuclei` |
| **Target** | `http://192.168.1.15:9090/api/v1/status/config` |

**Evidence:**

```
Detects unauthenticated access to Prometheus Time Series Collection and Processing Server by checking for specific elements in the response from the `/graph` endpoint.
```

</details>

---

<a id="target-192-168-1-15-9090-debug-pprof"></a>
### 🌐 `http://192.168.1.15:9090/debug/pprof/`

**1 finding(s)** | 🟠`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟠 **HIGH** | `nuclei` | Debug Endpoint pprof - Exposure Detection |

#### Detailed Findings

<details><summary><b>#1</b> 🟠 <img src="https://img.shields.io/badge/HIGH-D7263D?style=flat-square" height="18" alt="🟠 high"> <code>nuclei</code> — Debug Endpoint pprof - Exposure Detection</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `nuclei` |
| **Target** | `http://192.168.1.15:9090/debug/pprof/` |
| **Reference** | https://medium.com/bugbountywriteup/my-first-bug-bounty-21d3203ffdb0, http://mmcloughlin.com/posts/your-pprof-is-showing, https://github.com/kubernetes/kubernetes/issues/81023, https://groups.google.com/d/msg/kubernetes-security-announce/pKELclHIov8/BEDtRELACQAJ, https://nvd.nist.gov/vuln/detail/CVE-2019-11248 |

**Evidence:**

```
The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port. This debugging endpoint can potentially leak sensitive information such as internal Kubelet memory addresses and configuration, or for limited denial of service. Versions prior to 1.15.0, 1.14.4, 1.13.8, and 1.12.10 are affected. The issue is of medium severity, but not exposed by the default configuration.
```

</details>

---

<a id="target-192-168-1-15-8080"></a>
### 🌐 `http://192.168.1.15:8080/`

**16 finding(s)** | 🟡`2` 🔵`2` ⚪`12`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `nikto` | GET /: Uncommon header 'x-xss-protection' found, with contents: 1; mode=block |
| 2 | 🟡 **MEDIUM** | `nikto` | Uncommon header 'x-xss-protection' found, with contents: 1; mode=block |
| 3 | 🔵 **LOW** | `nikto` | GET /: Uncommon header 'content-security-policy' found, with contents: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' |
| 4 | 🔵 **LOW** | `nikto` | Uncommon header 'content-security-policy' found, with contents: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; |
| 5 | ⚪ **INFO** | `httpx` | Alive (401) — unknown server |
| 6 | ⚪ **INFO** | `nikto` | 0 items checked: 0 error(s) and 6 item(s) reported on remote host |
| 7 | ⚪ **INFO** | `nikto` | ERROR: Host maximum execution time of 570 seconds reached |
| 8 | ⚪ **INFO** | `nikto` | GET /: Uncommon header 'cross-origin-opener-policy' found, with contents: same-origin |
| 9 | ⚪ **INFO** | `nikto` | GET /: Uncommon header 'referrer-policy' found, with contents: same-origin |
| 10 | ⚪ **INFO** | `nikto` | GET /: Uncommon header 'x-content-type-options' found, with contents: nosniff |
| 11 | ⚪ **INFO** | `nikto` | GET /: Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN |
| 12 | ⚪ **INFO** | `nikto` | Uncommon header 'cross-origin-opener-policy' found, with contents: same-origin |
| 13 | ⚪ **INFO** | `nikto` | Uncommon header 'referrer-policy' found, with contents: same-origin |
| 14 | ⚪ **INFO** | `nikto` | Uncommon header 'x-content-type-options' found, with contents: nosniff |
| 15 | ⚪ **INFO** | `nikto` | Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN |
| 16 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>nikto</code> — GET /: Uncommon header 'x-xss-protection' found, with contents: 1; mode=block</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
GET /: Uncommon header 'x-xss-protection' found, with contents: 1; mode=block
```

</details>

<details><summary><b>#2</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>nikto</code> — Uncommon header 'x-xss-protection' found, with contents: 1; mode=block</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
Uncommon header 'x-xss-protection' found, with contents: 1; mode=block
```

</details>

<details><summary><b>#3</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nikto</code> — GET /: Uncommon header 'content-security-policy' found, with contents: default-src 'self'; style-src 'self' 'unsafe-inli</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
GET /: Uncommon header 'content-security-policy' found, with contents: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; object-src 'none'; form-action 'self'; frame-src 'self' blob:; frame-ancestors 'self';
```

</details>

<details><summary><b>#4</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nikto</code> — Uncommon header 'content-security-policy' found, with contents: default-src 'self'; style-src 'self' 'unsafe-inline'; im</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
Uncommon header 'content-security-policy' found, with contents: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; object-src 'none'; form-action 'self'; frame-src 'self' blob:; frame-ancestors 'self';
```

</details>

<details><summary><b>#5</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>httpx</code> — Alive (401) — unknown server</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://192.168.1.15:8080/` |

_No additional evidence captured._

</details>

<details><summary><b>#6</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — 0 items checked: 0 error(s) and 6 item(s) reported on remote host</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
0 items checked: 0 error(s) and 6 item(s) reported on remote host
```

</details>

<details><summary><b>#7</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — ERROR: Host maximum execution time of 570 seconds reached</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
ERROR: Host maximum execution time of 570 seconds reached
```

</details>

<details><summary><b>#8</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /: Uncommon header 'cross-origin-opener-policy' found, with contents: same-origin</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
GET /: Uncommon header 'cross-origin-opener-policy' found, with contents: same-origin
```

</details>

<details><summary><b>#9</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /: Uncommon header 'referrer-policy' found, with contents: same-origin</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
GET /: Uncommon header 'referrer-policy' found, with contents: same-origin
```

</details>

<details><summary><b>#10</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /: Uncommon header 'x-content-type-options' found, with contents: nosniff</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
GET /: Uncommon header 'x-content-type-options' found, with contents: nosniff
```

</details>

<details><summary><b>#11</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /: Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
GET /: Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN
```

</details>

<details><summary><b>#12</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Uncommon header 'cross-origin-opener-policy' found, with contents: same-origin</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
Uncommon header 'cross-origin-opener-policy' found, with contents: same-origin
```

</details>

<details><summary><b>#13</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Uncommon header 'referrer-policy' found, with contents: same-origin</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
Uncommon header 'referrer-policy' found, with contents: same-origin
```

</details>

<details><summary><b>#14</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Uncommon header 'x-content-type-options' found, with contents: nosniff</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
Uncommon header 'x-content-type-options' found, with contents: nosniff
```

</details>

<details><summary><b>#15</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15:8080/` |

**Evidence:**

```
Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN
```

</details>

<details><summary><b>#16</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>wafw00f</code> — No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://192.168.1.15:8080/` |

_No additional evidence captured._

</details>

---

<a id="target-192-168-1-15-9090"></a>
### 🌐 `http://192.168.1.15:9090/`

**7 finding(s)** | 🟡`1` 🔵`4` ⚪`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Inconsistent Redirection |
| 2 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 3 | 🔵 **LOW** | `wapiti` | Content Security Policy Configuration |
| 4 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |
| 5 | 🔵 **LOW** | `wapiti` | Unencrypted Channels |
| 6 | ⚪ **INFO** | `httpx` | Alive (200) — unknown server |
| 7 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>wapiti</code> — Inconsistent Redirection</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:9090/` |

**Evidence:**

```
GET /
3xx redirection contains unexpected HTML body (links/forms)
```

</details>

<details><summary><b>#2</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:9090/` |

**Evidence:**

```
GET /
X-Frame-Options is not set
```

</details>

<details><summary><b>#3</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Content Security Policy Configuration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:9090/` |

**Evidence:**

```
GET /
CSP is not set for URL: http://192.168.1.15:9090/
```

</details>

<details><summary><b>#4</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:9090/` |

**Evidence:**

```
GET /
X-Content-Type-Options is not set
```

</details>

<details><summary><b>#5</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:9090/` |

**Evidence:**

```
GET /
No HTTPS redirection for this host. All HTTP requests are served in clear text.
```

</details>

<details><summary><b>#6</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>httpx</code> — Alive (200) — unknown server</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://192.168.1.15:9090/` |

**Evidence:**

```
title=Prometheus Time Series Collection and Processing Server
```

</details>

<details><summary><b>#7</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>wafw00f</code> — No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://192.168.1.15:9090/` |

_No additional evidence captured._

</details>

---

<a id="target-192-168-1-15-site-webmanifest"></a>
### 🌐 `http://192.168.1.15/site.webmanifest`

**1 finding(s)** | 🟡`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Unencrypted Channels |

#### Detailed Findings

<details><summary><b>#1</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>wapiti</code> — Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15/site.webmanifest` |

**Evidence:**

```
GET /site.webmanifest
Sensitive data (GET parameters) was sent over an unencrypted HTTP connection to http://192.168.1.15/site.webmanifest?v=4. The server did not enforce HTTPS.
```

</details>

---

<a id="target-192-168-1-15-9090-api-v1-status-flags"></a>
### 🌐 `http://192.168.1.15:9090/api/v1/status/flags`

**1 finding(s)** | 🟡`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `chain:prometheus` | Prometheus runtime flags exposed |

#### Detailed Findings

<details><summary><b>#1</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>chain:prometheus</code> — Prometheus runtime flags exposed</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `chain:prometheus` |
| **Target** | `http://192.168.1.15:9090/api/v1/status/flags` |
| **Reference** | Service chain probe — port 9090 (Prometheus) |

**Evidence:**

```
GET http://192.168.1.15:9090/api/v1/status/flags
HTTP/1.1 200

�  	n� ��Vݎ�6}��.?DZ'�f��e���@/F�ud�CQ�I��{�$��	��R��2��v*k1g�R�#��j!dT+�{��!G࣎�}�-�OQ�,�S��Pإרv��ܹ^9��Ag����l�<�3X�z>��Z7MӈK᤻���@��Y�р}��
��}R;՘�j�l���L�&	������N���L냔�	�~(��,y�ל��V
#�����Z��:�&�A
�k{OQR��&�R/�dBJ�{���a��m�n��M�m!�h��Mse������v��lf�c*R�FR	�M�T�;�z@��UΗ@�0t�9$�V.�>��3F'Ճ��Ĺ��5!H���JeK0��wɬ�������MG��BǶ��{qU즯N�*}��>����3 ԮΌ�^�� ��Q�[�)�Eg����Wڦ~ �٧8#�L�i��9�0��KЌ]���il~YD1�h�Q��/e�U��}b4m(���>���!��pYOc�n>�
��c�>ꖠ��n>�����.g鿇��*���!�j�P�a�,��E���^������Vd�P��&�,"�M�I7��xGM
~�$J|���<�)�Fަ��ҫ����8�R7��n�֛�]h���ǣUs���6�m���,)�2��z�nÌ�Q>�!w�ܑ��c���p���Kܿ�ތOи|.�94��	��u>��u9��2�C �c/�&�����o<�*p�L��C3s�-ړ
�lNMh���#��Ĩ؏�o�!�B2Xc��3c���l7�����k�1��ΐ�����6��:�}���H�\�C}�<�[~{W���ǧ�QZ��k
��	�{�FI>�|� �?������ַ[R,�`�Z�(qڗV��3t����0ʸ�&�8��'33U^�qcF�/F=��M>\�㒑4䌜G��]�d��s�BF��ǿ   �� ��)3:
  
```

</details>

---

<a id="target-192-168-1-15-9090-api-v1-targets"></a>
### 🌐 `http://192.168.1.15:9090/api/v1/targets`

**1 finding(s)** | 🟡`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `chain:prometheus` | Prometheus scrape targets exposed |

#### Detailed Findings

<details><summary><b>#1</b> 🟡 <img src="https://img.shields.io/badge/MEDIUM-F46036?style=flat-square" height="18" alt="🟡 medium"> <code>chain:prometheus</code> — Prometheus scrape targets exposed</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `chain:prometheus` |
| **Target** | `http://192.168.1.15:9090/api/v1/targets` |
| **Reference** | Service chain probe — port 9090 (Prometheus) |

**Evidence:**

```
GET http://192.168.1.15:9090/api/v1/targets
HTTP/1.1 200

�  	n� ��TM��0�+ќ����i�+ ���r�E�k#׎l���w�|�vW�n/{K�{���b���  vJa����I�8�T�p+�������0��,wh�IU�R�1�5�+h�)hA��(!�C]�1�b����ńlT
�q����	��ڸ�� �@R>�.�=�.�9Q��8���9E�b�N��>6F�⽝c�ط`��b�Ћ���I�j��1}�0�~.�����jK6�s�iA��K���+��.�d�A
R�jIshP�Ԁ��=W�ij빩#�;:���o7���7�5����|����+ӧx3���%]�b�����������i#m�T�=Q�Ly�P���.����_�+V�_���zf�c��/�J�?�������mQ��.��w�s��s� �l� }��  �� ����  
```

</details>

---

<a id="target-192-168-1-15"></a>
### 🌐 `http://192.168.1.15/`

**20 finding(s)** | 🔵`5` ⚪`15`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 2 | 🔵 **LOW** | `wapiti` | Content Security Policy Configuration |
| 3 | 🔵 **LOW** | `wapiti` | Information Disclosure - Full Path |
| 4 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |
| 5 | 🔵 **LOW** | `wapiti` | Unencrypted Channels |
| 6 | ⚪ **INFO** | `httpx` | Alive (200) — unknown server |
| 7 | ⚪ **INFO** | `nikto` | "robots.txt" contains 1 entry which should be manually viewed. |
| 8 | ⚪ **INFO** | `nikto` | 0 items checked: 0 error(s) and 7 item(s) reported on remote host |
| 9 | ⚪ **INFO** | `nikto` | ERROR: Host maximum execution time of 570 seconds reached |
| 10 | ⚪ **INFO** | `nikto` | GET /: Retrieved x-powered-by header: Next.js |
| 11 | ⚪ **INFO** | `nikto` | GET /: Server leaks inodes via ETags, header found with file /, fields: 0xabjercz898vz3 |
| 12 | ⚪ **INFO** | `nikto` | GET /: Uncommon header 'x-nextjs-cache' found, with contents: HIT |
| 13 | ⚪ **INFO** | `nikto` | GET /nLWMbQr0/: Uncommon header 'refresh' found, with contents: 0;url=/nLWMbQr0 |
| 14 | ⚪ **INFO** | `nikto` | GET /robots.txt: "robots.txt" contains 1 entry which should be manually viewed. |
| 15 | ⚪ **INFO** | `nikto` | OPTIONS /: Allowed HTTP Methods: HEAD |
| 16 | ⚪ **INFO** | `nikto` | Retrieved x-powered-by header: Next.js |
| 17 | ⚪ **INFO** | `nikto` | Server leaks inodes via ETags, header found with file /, fields: 0xabjercz898vz3 |
| 18 | ⚪ **INFO** | `nikto` | Uncommon header 'refresh' found, with contents: 0;url=/nLWMbQr0 |
| 19 | ⚪ **INFO** | `nikto` | Uncommon header 'x-nextjs-cache' found, with contents: HIT |
| 20 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /
X-Frame-Options is not set
```

</details>

<details><summary><b>#2</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Content Security Policy Configuration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /
CSP is not set for URL: http://192.168.1.15/
```

</details>

<details><summary><b>#3</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Information Disclosure - Full Path</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /
Response contains potential system path: /mnt/NAS
```

</details>

<details><summary><b>#4</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /
X-Content-Type-Options is not set
```

</details>

<details><summary><b>#5</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /
No HTTPS redirection for this host. All HTTP requests are served in clear text.
```

</details>

<details><summary><b>#6</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>httpx</code> — Alive (200) — unknown server</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
tech=Next.js, Node.js, React, Webpack
```

</details>

<details><summary><b>#7</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — "robots.txt" contains 1 entry which should be manually viewed.</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
"robots.txt" contains 1 entry which should be manually viewed.
```

</details>

<details><summary><b>#8</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — 0 items checked: 0 error(s) and 7 item(s) reported on remote host</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
0 items checked: 0 error(s) and 7 item(s) reported on remote host
```

</details>

<details><summary><b>#9</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — ERROR: Host maximum execution time of 570 seconds reached</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
ERROR: Host maximum execution time of 570 seconds reached
```

</details>

<details><summary><b>#10</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /: Retrieved x-powered-by header: Next.js</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /: Retrieved x-powered-by header: Next.js
```

</details>

<details><summary><b>#11</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /: Server leaks inodes via ETags, header found with file /, fields: 0xabjercz898vz3</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /: Server leaks inodes via ETags, header found with file /, fields: 0xabjercz898vz3
```

</details>

<details><summary><b>#12</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /: Uncommon header 'x-nextjs-cache' found, with contents: HIT</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /: Uncommon header 'x-nextjs-cache' found, with contents: HIT
```

</details>

<details><summary><b>#13</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /nLWMbQr0/: Uncommon header 'refresh' found, with contents: 0;url=/nLWMbQr0</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /nLWMbQr0/: Uncommon header 'refresh' found, with contents: 0;url=/nLWMbQr0
```

</details>

<details><summary><b>#14</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /robots.txt: "robots.txt" contains 1 entry which should be manually viewed.</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
GET /robots.txt: "robots.txt" contains 1 entry which should be manually viewed.
```

</details>

<details><summary><b>#15</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — OPTIONS /: Allowed HTTP Methods: HEAD</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
OPTIONS /: Allowed HTTP Methods: HEAD
```

</details>

<details><summary><b>#16</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Retrieved x-powered-by header: Next.js</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
Retrieved x-powered-by header: Next.js
```

</details>

<details><summary><b>#17</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Server leaks inodes via ETags, header found with file /, fields: 0xabjercz898vz3</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
Server leaks inodes via ETags, header found with file /, fields: 0xabjercz898vz3
```

</details>

<details><summary><b>#18</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Uncommon header 'refresh' found, with contents: 0;url=/nLWMbQr0</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
Uncommon header 'refresh' found, with contents: 0;url=/nLWMbQr0
```

</details>

<details><summary><b>#19</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Uncommon header 'x-nextjs-cache' found, with contents: HIT</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/` |

**Evidence:**

```
Uncommon header 'x-nextjs-cache' found, with contents: HIT
```

</details>

<details><summary><b>#20</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>wafw00f</code> — No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://192.168.1.15/` |

_No additional evidence captured._

</details>

---

<a id="target-192-168-1-15-8081"></a>
### 🌐 `http://192.168.1.15:8081/`

**6 finding(s)** | 🔵`4` ⚪`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 2 | 🔵 **LOW** | `wapiti` | Content Security Policy Configuration |
| 3 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |
| 4 | 🔵 **LOW** | `wapiti` | Unencrypted Channels |
| 5 | ⚪ **INFO** | `httpx` | Alive (200) — nginx/1.26.2 |
| 6 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:8081/` |

**Evidence:**

```
GET /
X-Frame-Options is not set
```

</details>

<details><summary><b>#2</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Content Security Policy Configuration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:8081/` |

**Evidence:**

```
GET /
CSP is not set for URL: http://192.168.1.15:8081/
```

</details>

<details><summary><b>#3</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:8081/` |

**Evidence:**

```
GET /
X-Content-Type-Options is not set
```

</details>

<details><summary><b>#4</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:8081/` |

**Evidence:**

```
GET /
No HTTPS redirection for this host. All HTTP requests are served in clear text.
```

</details>

<details><summary><b>#5</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>httpx</code> — Alive (200) — nginx/1.26.2</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://192.168.1.15:8081/` |

**Evidence:**

```
server=nginx/1.26.2 · tech=Nginx:1.26.2 · title=IT Tools - Handy online tools for developers
```

</details>

<details><summary><b>#6</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>wafw00f</code> — No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://192.168.1.15:8081/` |

_No additional evidence captured._

</details>

---

<a id="target-192-168-1-15-8501"></a>
### 🌐 `http://192.168.1.15:8501/`

**6 finding(s)** | 🔵`4` ⚪`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 2 | 🔵 **LOW** | `wapiti` | Content Security Policy Configuration |
| 3 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |
| 4 | 🔵 **LOW** | `wapiti` | Unencrypted Channels |
| 5 | ⚪ **INFO** | `httpx` | Alive (200) — TornadoServer/6.5.5 |
| 6 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:8501/` |

**Evidence:**

```
GET /
X-Frame-Options is not set
```

</details>

<details><summary><b>#2</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Content Security Policy Configuration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:8501/` |

**Evidence:**

```
GET /
CSP is not set for URL: http://192.168.1.15:8501/
```

</details>

<details><summary><b>#3</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:8501/` |

**Evidence:**

```
GET /
X-Content-Type-Options is not set
```

</details>

<details><summary><b>#4</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15:8501/` |

**Evidence:**

```
GET /
No HTTPS redirection for this host. All HTTP requests are served in clear text.
```

</details>

<details><summary><b>#5</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>httpx</code> — Alive (200) — TornadoServer/6.5.5</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://192.168.1.15:8501/` |

**Evidence:**

```
server=TornadoServer/6.5.5 · tech=TornadoServer:6.5.5
```

</details>

<details><summary><b>#6</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>wafw00f</code> — No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://192.168.1.15:8501/` |

_No additional evidence captured._

</details>

---

<a id="target-192-168-1-15-robots-txt-robots-txt"></a>
### 🌐 `http://192.168.1.15/robots.txt/robots.txt`

**2 finding(s)** | 🔵`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 2 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |

#### Detailed Findings

<details><summary><b>#1</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15/robots.txt/robots.txt` |

**Evidence:**

```
GET /robots.txt
X-Frame-Options is not set
```

</details>

<details><summary><b>#2</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>wapiti</code> — MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://192.168.1.15/robots.txt/robots.txt` |

**Evidence:**

```
GET /robots.txt
X-Content-Type-Options is not set
```

</details>

---

<a id="target-192-168-1-15-9090-debug-pprof-heap"></a>
### 🌐 `http://192.168.1.15:9090/debug/pprof/heap`

**1 finding(s)** | 🔵`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `nuclei` | Go pprof Debug Page |

#### Detailed Findings

<details><summary><b>#1</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — Go pprof Debug Page</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `http://192.168.1.15:9090/debug/pprof/heap?debug=1` |

**Evidence:**

```
go pprof debug page was exposed.
```

</details>

---

<a id="target-192-168-1-15-9443"></a>
### 🌐 `192.168.1.15:9443`

**1 finding(s)** | 🔵`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `nuclei` | Self Signed SSL Certificate |

#### Detailed Findings

<details><summary><b>#1</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>nuclei</code> — Self Signed SSL Certificate</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `192.168.1.15:9443` |
| **Reference** | https://www.rapid7.com/db/vulnerabilities/ssl-self-signed-certificate/ |

**Evidence:**

```
self-signed certificates are public key certificates that are not issued by a certificate authority. These self-signed
certificates are easy to make and do not cost money. However, they do not provide any trust value.
```

</details>

---

<a id="target-192-168-1-15-9090-api-v1-status-buildinfo"></a>
### 🌐 `http://192.168.1.15:9090/api/v1/status/buildinfo`

**1 finding(s)** | 🔵`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `chain:prometheus` | Prometheus build info exposed |

#### Detailed Findings

<details><summary><b>#1</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>chain:prometheus</code> — Prometheus build info exposed</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `chain:prometheus` |
| **Target** | `http://192.168.1.15:9090/api/v1/status/buildinfo` |
| **Reference** | Service chain probe — port 9090 (Prometheus) |

**Evidence:**

```
GET http://192.168.1.15:9090/api/v1/status/buildinfo
HTTP/1.1 200

�  	n� �<��J1���a:�d�>)��轓���$��e�]�XU���G�9k��7m}�W0�g���WE�.&)%���f-�� �j
&.�.��LHM����ח����޵��jϞ��h���,C�0��-�'�L�6b¥~��]*�����7   �� 7���   
```

</details>

---

<a id="target-192-168-1-15-9090-metrics"></a>
### 🌐 `http://192.168.1.15:9090/metrics`

**1 finding(s)** | 🔵`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `chain:prometheus` | Prometheus self-metrics exposed |

#### Detailed Findings

<details><summary><b>#1</b> 🔵 <img src="https://img.shields.io/badge/LOW-2E86AB?style=flat-square" height="18" alt="🔵 low"> <code>chain:prometheus</code> — Prometheus self-metrics exposed</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `chain:prometheus` |
| **Target** | `http://192.168.1.15:9090/metrics` |
| **Reference** | Service chain probe — port 9090 (Prometheus) |

**Evidence:**

```
GET http://192.168.1.15:9090/metrics
HTTP/1.1 200

�      �ܽ[��6�?��O��}��u��wJ��o��v�o;�{��HH�4E�X����B��	(v�.1��2����ở~�rJ��k�#��5)/�dI�7R��we]PAR^�9"(߿��P�*H;�rF��TuA�ڀe]%(Ǫ���S�ę�ڲ�9%o�o���
|��~�NW��
���4������},���t�<���zͳ��,�s�9u�HuU�:R-�7��0�e���a�s���*#'WZZW��{���H1���r��+U�����7���+�1Ť��!g�楬��o�� YN�:�I��(a�J+
�J����5,H����ß��8�����n56^��x~캾ύ%vݭK���qnw�<�`�"7�@����8�����w�,{�$U|*O����������N� �WZq�Nuu�����䌪�#�:�|<g<üF � #��_�P�Ueq��=�*��=X��D�����"߿�MHv��D��T�o�����S���J�!�&��K�]2�?��;1\Х�^��a�$�������I�����?������g&�OL�I#5:}�tj�r�X���Ə|'
<7F_;����^�0����{ښ���*;����#���Q����1��Z���$�5�
��:���cdER!H-[%)�,�y����r�j�D%��y�"@������` 1H�1+x�Q�PQ�(���A��"�܇�L>ɂ4c�|o�o��R#�-s�0)O�|5C�?0k|��a�����>�	�m���/�D�`�Q��kgX4{��6۝��-�r�V��'p7n�G��%h������;a����h�3����(�n����m���n�(��0\�h_�P��~ȼuZz�V��bύ��Vs�0�	Ec�UGKѼ�뷶H����}�cql�#g�׾h��o�8v�,��n�W�D�$�䱾�9$�3��
��+�����`aU+Y�.��E9��jh��"֎M��y�S�*;�P���t
߄U����ڧ�k>�
��ΗҤ�wu�L��Xfi,!���(v���_'�v��Ϝ�R�����B�z�h���Q�4��|�]���`��׉g��Tt����+�����΍���):�����b-�n�n,Su�Q�z�R��z�(�w[-v��A䄬���q�]n�u̜�qY��.����Ll��d��M�]�h`�r+�ٗs�����z/�����Lu�2c(�<�x'ѩ���QFS)ǲb6CE�L�53*U(���t
�և߼M�A�dγgԕY��2I�k�+���u���U\`����z����ߩ��8j}:����|s7a�A�U���X#�/��*j�)q}*P�]�#W�5+N]Wi!`���P��>C��纁D��ir�����W�|b�"gT�� e�=��e᎐�����\{6���Q�f|L� +��9Kkؕd��I��
ELa5}FYŅڀ�(�7�y�`�
`�HE}(+@��͍�r?U�I⊬��F��	5q@s�A��Y4T�s���w��x��DI 
```

</details>

---

<a id="target-192-168-1-15-robots-txt"></a>
### 🌐 `http://192.168.1.15/robots.txt`

**11 finding(s)** | ⚪`11`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | ⚪ **INFO** | `httpx` | Alive (200) — unknown server |
| 2 | ⚪ **INFO** | `nikto` | 0 items checked: 0 error(s) and 4 item(s) reported on remote host |
| 3 | ⚪ **INFO** | `nikto` | ERROR: Host maximum execution time of 570 seconds reached |
| 4 | ⚪ **INFO** | `nikto` | GET /robots.txt/robots.txt/.KFPqQ44D: Retrieved x-powered-by header: Next.js |
| 5 | ⚪ **INFO** | `nikto` | GET /robots.txt/robots.txt/.KFPqQ44D: Server leaks inodes via ETags, header found with file /robots.txt/.KFPqQ44D, fields: 0xdc2g57rkcj21e |
| 6 | ⚪ **INFO** | `nikto` | GET /robots.txt/robots.txt/: Uncommon header 'refresh' found, with contents: 0;url=/robots.txt |
| 7 | ⚪ **INFO** | `nikto` | Retrieved x-powered-by header: Next.js |
| 8 | ⚪ **INFO** | `nikto` | Server leaks inodes via ETags, header found with file /robots.txt/.KFPqQ44D, fields: 0xdc2g57rkcj21e |
| 9 | ⚪ **INFO** | `nikto` | Target Path:        /robots.txt |
| 10 | ⚪ **INFO** | `nikto` | Uncommon header 'refresh' found, with contents: 0;url=/robots.txt |
| 11 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>httpx</code> — Alive (200) — unknown server</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://192.168.1.15/robots.txt` |

_No additional evidence captured._

</details>

<details><summary><b>#2</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — 0 items checked: 0 error(s) and 4 item(s) reported on remote host</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
0 items checked: 0 error(s) and 4 item(s) reported on remote host
```

</details>

<details><summary><b>#3</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — ERROR: Host maximum execution time of 570 seconds reached</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
ERROR: Host maximum execution time of 570 seconds reached
```

</details>

<details><summary><b>#4</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /robots.txt/robots.txt/.KFPqQ44D: Retrieved x-powered-by header: Next.js</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
GET /robots.txt/robots.txt/.KFPqQ44D: Retrieved x-powered-by header: Next.js
```

</details>

<details><summary><b>#5</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /robots.txt/robots.txt/.KFPqQ44D: Server leaks inodes via ETags, header found with file /robots.txt/.KFPqQ44D, field</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
GET /robots.txt/robots.txt/.KFPqQ44D: Server leaks inodes via ETags, header found with file /robots.txt/.KFPqQ44D, fields: 0xdc2g57rkcj21e
```

</details>

<details><summary><b>#6</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — GET /robots.txt/robots.txt/: Uncommon header 'refresh' found, with contents: 0;url=/robots.txt</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
GET /robots.txt/robots.txt/: Uncommon header 'refresh' found, with contents: 0;url=/robots.txt
```

</details>

<details><summary><b>#7</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Retrieved x-powered-by header: Next.js</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
Retrieved x-powered-by header: Next.js
```

</details>

<details><summary><b>#8</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Server leaks inodes via ETags, header found with file /robots.txt/.KFPqQ44D, fields: 0xdc2g57rkcj21e</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
Server leaks inodes via ETags, header found with file /robots.txt/.KFPqQ44D, fields: 0xdc2g57rkcj21e
```

</details>

<details><summary><b>#9</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Target Path:        /robots.txt</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
Target Path:        /robots.txt
```

</details>

<details><summary><b>#10</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>nikto</code> — Uncommon header 'refresh' found, with contents: 0;url=/robots.txt</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://192.168.1.15/robots.txt` |

**Evidence:**

```
Uncommon header 'refresh' found, with contents: 0;url=/robots.txt
```

</details>

<details><summary><b>#11</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>wafw00f</code> — No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://192.168.1.15/robots.txt` |

_No additional evidence captured._

</details>

---

<a id="target-192-168-1-15-9443"></a>
### 🌐 `https://192.168.1.15:9443/`

**2 finding(s)** | ⚪`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | ⚪ **INFO** | `httpx` | Alive (200) — unknown server |
| 2 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>httpx</code> — Alive (200) — unknown server</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `https://192.168.1.15:9443/` |

_No additional evidence captured._

</details>

<details><summary><b>#2</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>wafw00f</code> — No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `https://192.168.1.15:9443/` |

_No additional evidence captured._

</details>

---

<a id="target-192-168-1-15-9000"></a>
### 🌐 `http://192.168.1.15:9000/`

**2 finding(s)** | ⚪`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | ⚪ **INFO** | `httpx` | Alive (200) — unknown server |
| 2 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>httpx</code> — Alive (200) — unknown server</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://192.168.1.15:9000/` |

_No additional evidence captured._

</details>

<details><summary><b>#2</b> ⚪ <img src="https://img.shields.io/badge/INFO-6C757D?style=flat-square" height="18" alt="⚪ info"> <code>wafw00f</code> — No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://192.168.1.15:9000/` |

_No additional evidence captured._

</details>

---

## ⚙️ Scan Metadata

| Field | Value |
|---|---|
| VulnMalper version | `v2.6.1` |
| Source NetMalper target | `192.168.1.15` |
| Generated (UTC) | `2026-04-24 08:55:54 UTC` |
| Total scan duration | `1823.8s` |
| Tools dispatched | `httpx`→🟢 local · `whatweb`→🟢 local · `wafw00f`→🟢 local · `testssl`→🟢 local · `nikto`→🟢 local · `nuclei`→🟢 local · `wapiti`→🟢 local · `sqlmap`→🟢 local |

---
_Report generated by **VulnMalper** — pipelines NetMalper recon into nikto, nuclei, sqlmap, wapiti, testssl, httpx, whatweb & wafw00f._
