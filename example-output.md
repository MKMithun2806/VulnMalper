# 🛡️  VulnMalper Report

> **Target:** `nmap.scanme.org` &nbsp;·&nbsp; **Generated:** 2026-04-21 13:31:30 UTC &nbsp;·&nbsp; **Engine:** VulnMalper v2.2.0

---

## 📊 Executive Summary

### 🟡 MODERATE RISK &nbsp;·&nbsp; Risk score: **21/100**

| Critical | High | Medium | Low | Info | **Total** |
|:--------:|:----:|:------:|:---:|:----:|:---------:|
| ![critical](https://img.shields.io/badge/CRITICAL-8B0000?style=flat-square)<br>**0** | ![high](https://img.shields.io/badge/HIGH-D7263D?style=flat-square)<br>**0** | ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square)<br>**3** | ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square)<br>**9** | ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square)<br>**2** | **14** |

| Metric | Value |
|---|---|
| Web targets discovered | **1** |
| Alive after fingerprinting | **1** |
| Targets behind a WAF | **0** |
| Scan duration | **280.4s** |
| Tool runners | `httpx`→🟢 local · `whatweb`→🟢 local · `wafw00f`→🟢 local · `testssl`→🟢 local · `nikto`→🟢 local · `nuclei`→🟢 local · `wapiti`→🟢 local · `sqlmap`→🟢 local |

## 🧭 Table of Contents

- [Executive Summary](#-executive-summary)
- [Target Fingerprints](#-target-fingerprints)
- [Findings](#-findings)
  - [🟡 `nmap.scanme.org:22` _(6)_](#target-nmap-scanme-org-22)
  - [🟡 `http://nmap.scanme.org/search/` _(1)_](#target-nmap-scanme-org-search)
  - [🔵 `http://nmap.scanme.org/` _(6)_](#target-nmap-scanme-org)
  - [🔵 `http://nmap.scanme.org/index` _(1)_](#target-nmap-scanme-org-index)

---

## 🔍 Target Fingerprints

<details><summary><b>🟢 <code>http://nmap.scanme.org/</code></b> &nbsp;·&nbsp; <code>http/80</code> &nbsp;·&nbsp; status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `nmap.scanme.org` |
| Port / Scheme | `80` / `http` |
| Service | `http` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | `Apache HTTP Server:2.4.7`, `Ubuntu` |
| WAF | — |
| Injectable Endpoints | — |

</details>

---

## 🎯 Findings

<a id="target-nmap-scanme-org-22"></a>
### 🌐 `nmap.scanme.org:22`

**6 finding(s)** &nbsp;·&nbsp; 🟡`2` 🔵`4`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `nuclei` | OpenSSH Terrapin Attack - Detection |
| 2 | 🟡 **MEDIUM** | `nuclei` | SSH Weak Algorithms Supported |
| 3 | 🔵 **LOW** | `nuclei` | SSH Diffie-Hellman Modulus <= 1024 Bits |
| 4 | 🔵 **LOW** | `nuclei` | SSH Server CBC Mode Ciphers Enabled |
| 5 | 🔵 **LOW** | `nuclei` | SSH Weak Key Exchange Algorithms Enabled |
| 6 | 🔵 **LOW** | `nuclei` | SSH Weak MAC Algorithms Enabled |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; OpenSSH Terrapin Attack - Detection</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `nuclei` |
| **Target** | `nmap.scanme.org:22` |
| **Reference** | https://github.com/RUB-NDS/Terrapin-Scanner, https://terrapin-attack.com/, http://packetstormsecurity.com/files/176280/Terrapin-SSH-Connection-Weakening.html, http://seclists.org/fulldisclosure/2024/Mar/21, http://www.openwall.com/lists/oss-security/2023/12/18/3 |

**Evidence:**

```
The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; SSH Weak Algorithms Supported</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `nuclei` |
| **Target** | `nmap.scanme.org:22` |
| **Reference** | https://www.tenable.com/plugins/nessus/90317 |

**Evidence:**

```
SSH weak algorithms are outdated cryptographic methods that pose security risks. Identifying and disabling these vulnerable algorithms is crucial for enhancing the overall security of SSH connections.
```

</details>

<details><summary><b>#3</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; SSH Diffie-Hellman Modulus <= 1024 Bits</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `nmap.scanme.org:22` |
| **Reference** | https://access.redhat.com/solutions/4278651 |

**Evidence:**

```
SSH weak algorithms are outdated cryptographic methods that pose security risks. Identifying and disabling these vulnerable algorithms is crucial for enhancing the overall security of SSH connections.
```

</details>

<details><summary><b>#4</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; SSH Server CBC Mode Ciphers Enabled</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `nmap.scanme.org:22` |
| **Reference** | https://www.tenable.com/plugins/nessus/70658 |

**Evidence:**

```
"SSH Server CBC Mode Ciphers Enabled" signifies that the SSH server supports Cipher Block Chaining (CBC) mode ciphers, which are known for potential vulnerabilities. This configuration poses a security risk, and it's recommended to disable CBC ciphers in favor of more secure alternatives for enhanced protection during data transmission.
```

</details>

<details><summary><b>#5</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; SSH Weak Key Exchange Algorithms Enabled</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `nmap.scanme.org:22` |
| **Reference** | https://www.tenable.com/plugins/nessus/153953 |

**Evidence:**

```
SSH Weak Key Exchange Algorithms Enabled indicates that the SSH server or client is configured to allow the use of less secure key exchange methods, posing a potential security risk during the establishment of secure connections. It's crucial to update configurations to prioritize stronger key exchange algorithms.
```

</details>

<details><summary><b>#6</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; SSH Weak MAC Algorithms Enabled</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `nmap.scanme.org:22` |
| **Reference** | https://www.tenable.com/plugins/nessus/71049 |

**Evidence:**

```
The system's SSH configuration poses a security risk by allowing weak Message Authentication Code (MAC) algorithms, potentially exposing it to vulnerabilities and unauthorized access. It is crucial to update and strengthen the MAC algorithms for enhanced security.
```

</details>

---

<a id="target-nmap-scanme-org-search"></a>
### 🌐 `http://nmap.scanme.org/search/`

**1 finding(s)** &nbsp;·&nbsp; 🟡`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Unencrypted Channels |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://nmap.scanme.org/search/` |

**Evidence:**

```
GET /search/
Sensitive data (GET parameters) was sent over an unencrypted HTTP connection to http://nmap.scanme.org/search/?q=default. The server did not enforce HTTPS.
```

</details>

---

<a id="target-nmap-scanme-org"></a>
### 🌐 `http://nmap.scanme.org/`

**6 finding(s)** &nbsp;·&nbsp; 🔵`4` ⚪`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 2 | 🔵 **LOW** | `wapiti` | Content Security Policy Configuration |
| 3 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |
| 4 | 🔵 **LOW** | `wapiti` | Unencrypted Channels |
| 5 | ⚪ **INFO** | `httpx` | Alive (200) — Apache/2.4.7 (Ubuntu) |
| 6 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://nmap.scanme.org/` |

**Evidence:**

```
GET /
X-Frame-Options is not set
```

</details>

<details><summary><b>#2</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Content Security Policy Configuration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://nmap.scanme.org/` |

**Evidence:**

```
GET /
CSP is not set for URL: http://nmap.scanme.org/
```

</details>

<details><summary><b>#3</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://nmap.scanme.org/` |

**Evidence:**

```
GET /
X-Content-Type-Options is not set
```

</details>

<details><summary><b>#4</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://nmap.scanme.org/` |

**Evidence:**

```
GET /
No HTTPS redirection for this host. All HTTP requests are served in clear text.
```

</details>

<details><summary><b>#5</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>httpx</code> &nbsp; — &nbsp; Alive (200) — Apache/2.4.7 (Ubuntu)</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://nmap.scanme.org/` |

**Evidence:**

```
server=Apache/2.4.7 (Ubuntu) · tech=Apache HTTP Server:2.4.7, Ubuntu · title=Go ahead and ScanMe!
```

</details>

<details><summary><b>#6</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>wafw00f</code> &nbsp; — &nbsp; No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://nmap.scanme.org/` |

_No additional evidence captured._

</details>

---

<a id="target-nmap-scanme-org-index"></a>
### 🌐 `http://nmap.scanme.org/index`

**1 finding(s)** &nbsp;·&nbsp; 🔵`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `nuclei` | Apache mod_negotiation - Pseudo Directory Listing |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; Apache mod_negotiation - Pseudo Directory Listing</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `http://nmap.scanme.org/index` |
| **Reference** | https://www.acunetix.com/vulnerabilities/web/apache-mod_negotiation-filename-bruteforcing/, https://cwe.mitre.org/data/definitions/538.html |

**Evidence:**

```
Detected Apache server with mod_negotiation and MultiViews enabled, exposing a pseudo directory listing when invalid Accept headers are sent to extensionless filenames..
```

</details>

---

## ⚙️ Scan Metadata

| Field | Value |
|---|---|
| VulnMalper version | `v2.2.0` |
| Source NetMalper target | `nmap.scanme.org` |
| Generated (UTC) | `2026-04-21 13:31:30 UTC` |
| Total scan duration | `280.4s` |
| Tools dispatched | `httpx`→🟢 local · `whatweb`→🟢 local · `wafw00f`→🟢 local · `testssl`→🟢 local · `nikto`→🟢 local · `nuclei`→🟢 local · `wapiti`→🟢 local · `sqlmap`→🟢 local |

---
_Report generated by **VulnMalper** — pipelines NetMalper recon into nikto, nuclei, sqlmap, wapiti, testssl, httpx, whatweb & wafw00f._
