# 🛡️  VulnMalper Report

> **Target:** `demo.testfire.net` &nbsp;·&nbsp; **Generated:** 2026-04-21 14:41:46 UTC &nbsp;·&nbsp; **Engine:** VulnMalper v2.4.0

> 🔴 CRITICAL EXPOSURE &nbsp;·&nbsp; **173** findings across **4/7** alive targets &nbsp;·&nbsp; scan took **1229.4s**

---

## 🧭 Table of Contents

- [Target Fingerprints](#-target-fingerprints)
- [Findings](#-findings)
- [Scan Metadata](#-scan-metadata)
  - [🟠 `https://demo.testfire.net/` _(45)_](#target-demo-testfire-net)
  - [🟠 `https://demo.testfire.net/admin/` _(41)_](#target-demo-testfire-net-admin)
  - [🟠 `https://demo.testfire.net/admin` _(41)_](#target-demo-testfire-net-admin)
  - [🟠 `http://demo.testfire.net:8080/login.jsp` _(1)_](#target-demo-testfire-net-8080-login-jsp)
  - [🟡 `http://demo.testfire.net:8080/` _(9)_](#target-demo-testfire-net-8080)
  - [🟡 `https://demo.testfire.net/index.jsp` _(7)_](#target-demo-testfire-net-index-jsp)
  - [🟡 `http://demo.testfire.net:8080/index.jsp` _(7)_](#target-demo-testfire-net-8080-index-jsp)
  - [🟡 `https://demo.testfire.net/sendFeedback` _(2)_](#target-demo-testfire-net-sendfeedback)
  - [🟡 `http://demo.testfire.net:8080/search.jsp` _(2)_](#target-demo-testfire-net-8080-search-jsp)
  - [🟡 `http://demo.testfire.net:8080/sendFeedback` _(2)_](#target-demo-testfire-net-8080-sendfeedback)
  - [🟡 `https://demo.testfire.net/search.jsp` _(1)_](#target-demo-testfire-net-search-jsp)
  - [🟡 `http://demo.testfire.net:8080/doSubscribe` _(1)_](#target-demo-testfire-net-8080-dosubscribe)
  - [🔵 `demo.testfire.net:443` _(6)_](#target-demo-testfire-net-443)
  - [🔵 `https://demo.testfire.net/admin/admin` _(3)_](#target-demo-testfire-net-admin-admin)
  - [🔵 `https://demo.testfire.net/admin/admin/` _(3)_](#target-demo-testfire-net-admin-admin)
  - [🔵 `http://demo.testfire.net:8080/default.jsp` _(1)_](#target-demo-testfire-net-8080-default-jsp)
  - [🔵 `http://demo.testfire.net:8080/doLogin` _(1)_](#target-demo-testfire-net-8080-dologin)

---

## 🔍 Target Fingerprints

<details><summary><b>🟢 <code>https://demo.testfire.net/</code></b> &nbsp;·&nbsp; <code>https/443</code> &nbsp;·&nbsp; status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `demo.testfire.net` |
| Port / Scheme | `443` / `https` |
| Service | `https` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | `Apache Tomcat`, `Java` |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>https://demo.testfire.net/admin</code></b> &nbsp;·&nbsp; <code>https/443</code> &nbsp;·&nbsp; status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `demo.testfire.net` |
| Port / Scheme | `443` / `https` |
| Service | `https` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | `Apache Tomcat`, `Java` |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>https://demo.testfire.net/admin/</code></b> &nbsp;·&nbsp; <code>https/443</code> &nbsp;·&nbsp; status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `demo.testfire.net` |
| Port / Scheme | `443` / `https` |
| Service | `https` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | `Apache Tomcat`, `Java` |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🔴 <code>http://demo.testfire.net/</code></b> &nbsp;·&nbsp; <code>http/80</code> &nbsp;·&nbsp; status: <b>n/a</b></summary>

| Field | Value |
|---|---|
| Host | `demo.testfire.net` |
| Port / Scheme | `80` / `http` |
| Service | `http` |
| Product | `—` |
| HTTP Status | `n/a` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🔴 <code>http://demo.testfire.net/admin</code></b> &nbsp;·&nbsp; <code>http/80</code> &nbsp;·&nbsp; status: <b>n/a</b></summary>

| Field | Value |
|---|---|
| Host | `demo.testfire.net` |
| Port / Scheme | `80` / `http` |
| Service | `http` |
| Product | `—` |
| HTTP Status | `n/a` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🔴 <code>http://demo.testfire.net/admin/</code></b> &nbsp;·&nbsp; <code>http/80</code> &nbsp;·&nbsp; status: <b>n/a</b></summary>

| Field | Value |
|---|---|
| Host | `demo.testfire.net` |
| Port / Scheme | `80` / `http` |
| Service | `http` |
| Product | `—` |
| HTTP Status | `n/a` |
| Detected Tech | — |
| WAF | — |
| Injectable Endpoints | — |

</details>

<details><summary><b>🟢 <code>http://demo.testfire.net:8080/</code></b> &nbsp;·&nbsp; <code>http/8080</code> &nbsp;·&nbsp; status: <b>200</b></summary>

| Field | Value |
|---|---|
| Host | `demo.testfire.net` |
| Port / Scheme | `8080` / `http` |
| Service | `http-alt` |
| Product | `—` |
| HTTP Status | `200` |
| Detected Tech | `Apache Tomcat`, `Java` |
| WAF | — |
| Injectable Endpoints | — |

</details>

---

## 🎯 Findings

<a id="target-demo-testfire-net"></a>
### 🌐 `https://demo.testfire.net/`

**45 finding(s)** &nbsp;·&nbsp; 🟠`1` 🟡`5` 🔵`34` ⚪`5`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟠 **HIGH** | `testssl` | LOGJAM-common_primes |
| 2 | 🟡 **MEDIUM** | `testssl` | BEAST_CBC_TLS1 |
| 3 | 🟡 **MEDIUM** | `testssl` | DH_groups |
| 4 | 🟡 **MEDIUM** | `testssl` | fallback_SCSV |
| 5 | 🟡 **MEDIUM** | `testssl` | overall_grade |
| 6 | 🟡 **MEDIUM** | `testssl` | security_headers |
| 7 | 🔵 **LOW** | `testssl` | BEAST |
| 8 | 🔵 **LOW** | `testssl` | cipher-tls1_1_x33 |
| 9 | 🔵 **LOW** | `testssl` | cipher-tls1_1_x39 |
| 10 | 🔵 **LOW** | `testssl` | cipher-tls1_1_xc013 |
| 11 | 🔵 **LOW** | `testssl` | cipher-tls1_1_xc014 |
| 12 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x33 |
| 13 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x39 |
| 14 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x67 |
| 15 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x6b |
| 16 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc013 |
| 17 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc014 |
| 18 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc027 |
| 19 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc028 |
| 20 | 🔵 **LOW** | `testssl` | cipher-tls1_x33 |
| 21 | 🔵 **LOW** | `testssl` | cipher-tls1_x39 |
| 22 | 🔵 **LOW** | `testssl` | cipher-tls1_xc013 |
| 23 | 🔵 **LOW** | `testssl` | cipher-tls1_xc014 |
| 24 | 🔵 **LOW** | `testssl` | cipher_order |
| 25 | 🔵 **LOW** | `testssl` | cipher_order-tls1_2 |
| 26 | 🔵 **LOW** | `testssl` | cipherlist_OBSOLETED |
| 27 | 🔵 **LOW** | `testssl` | DNS_CAArecord |
| 28 | 🔵 **LOW** | `testssl` | engine_problem |
| 29 | 🔵 **LOW** | `testssl` | FS_KEMs |
| 30 | 🔵 **LOW** | `testssl` | FS_TLS12_sig_algs |
| 31 | 🔵 **LOW** | `testssl` | HSTS |
| 32 | 🔵 **LOW** | `testssl` | LUCKY13 |
| 33 | 🔵 **LOW** | `testssl` | OCSP_stapling |
| 34 | 🔵 **LOW** | `testssl` | QUIC |
| 35 | 🔵 **LOW** | `testssl` | TLS1 |
| 36 | 🔵 **LOW** | `testssl` | TLS1_1 |
| 37 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 38 | 🔵 **LOW** | `wapiti` | Content Security Policy Configuration |
| 39 | 🔵 **LOW** | `wapiti` | HTTP Strict Transport Security (HSTS) |
| 40 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |
| 41 | ⚪ **INFO** | `httpx` | Alive (200) — Apache-Coyote/1.1 |
| 42 | ⚪ **INFO** | `httpx` | Alive (200) — Apache-Coyote/1.1 |
| 43 | ⚪ **INFO** | `nikto` | ERROR: Host maximum execution time of 570 seconds reached |
| 44 | ⚪ **INFO** | `nikto` | ERROR: Unable to open '' for write: |
| 45 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![high](https://img.shields.io/badge/HIGH-D7263D?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; LOGJAM-common_primes</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |
| **Reference** | CVE-2015-4000 |

**Evidence:**

```
RFC2409/Oakley Group 2
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; BEAST_CBC_TLS1</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |
| **Reference** | CVE-2011-3389 |

**Evidence:**

```
ECDHE-RSA-AES256-SHA DHE-RSA-AES256-SHA ECDHE-RSA-AES128-SHA DHE-RSA-AES128-SHA
```

</details>

<details><summary><b>#3</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; DH_groups</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
RFC2409/Oakley Group 2
```

</details>

<details><summary><b>#4</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; fallback_SCSV</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
NOT supported
```

</details>

<details><summary><b>#5</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; overall_grade</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
B
```

</details>

<details><summary><b>#6</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; security_headers</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
--
```

</details>

<details><summary><b>#7</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; BEAST</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |
| **Reference** | CVE-2011-3389 |

**Evidence:**

```
VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
```

</details>

<details><summary><b>#8</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.1   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#9</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.1   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#10</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.1   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#11</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.1   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#12</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.2   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#13</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.2   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#14</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x67</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.2   x67     DHE-RSA-AES128-SHA256             DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
```

</details>

<details><summary><b>#15</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x6b</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.2   x6b     DHE-RSA-AES256-SHA256             DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
```

</details>

<details><summary><b>#16</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.2   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#17</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.2   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#18</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc027</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.2   xc027   ECDHE-RSA-AES128-SHA256           ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
```

</details>

<details><summary><b>#19</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc028</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1.2   xc028   ECDHE-RSA-AES256-SHA384           ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
```

</details>

<details><summary><b>#20</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#21</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#22</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#23</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
TLSv1   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#24</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher_order</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
NOT a server cipher order configured
```

</details>

<details><summary><b>#25</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher_order-tls1_2</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
NOT a cipher order configured
```

</details>

<details><summary><b>#26</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipherlist_OBSOLETED</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |
| **Reference** | CWE-310 |

**Evidence:**

```
offered
```

</details>

<details><summary><b>#27</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; DNS_CAArecord</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
--
```

</details>

<details><summary><b>#28</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; engine_problem</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
No engine or GOST support via engine with your /usr/bin/openssl
```

</details>

<details><summary><b>#29</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; FS_KEMs</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
No KEMs offered
```

</details>

<details><summary><b>#30</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; FS_TLS12_sig_algs</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
RSA+SHA512 RSA+SHA384 RSA+SHA256 RSA+SHA1
```

</details>

<details><summary><b>#31</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; HSTS</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
not offered
```

</details>

<details><summary><b>#32</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; LUCKY13</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |
| **Reference** | CVE-2013-0169 |

**Evidence:**

```
potentially vulnerable, uses TLS CBC ciphers
```

</details>

<details><summary><b>#33</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; OCSP_stapling</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
not offered
```

</details>

<details><summary><b>#34</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; QUIC</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
not tested due to lack of local OpenSSL support
```

</details>

<details><summary><b>#35</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; TLS1</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
offered (deprecated)
```

</details>

<details><summary><b>#36</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; TLS1_1</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
offered (deprecated)
```

</details>

<details><summary><b>#37</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
GET /
X-Frame-Options is not set
```

</details>

<details><summary><b>#38</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Content Security Policy Configuration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
GET /
CSP is not set for URL: https://demo.testfire.net/
```

</details>

<details><summary><b>#39</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; HTTP Strict Transport Security (HSTS)</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
GET /
Strict-Transport-Security is not set
```

</details>

<details><summary><b>#40</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
GET /
X-Content-Type-Options is not set
```

</details>

<details><summary><b>#41</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>httpx</code> &nbsp; — &nbsp; Alive (200) — Apache-Coyote/1.1</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
server=Apache-Coyote/1.1 · tech=Apache Tomcat, Java · title=Altoro Mutual
```

</details>

<details><summary><b>#42</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>httpx</code> &nbsp; — &nbsp; Alive (200) — Apache-Coyote/1.1</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
server=Apache-Coyote/1.1 · tech=Apache Tomcat, Java · title=Altoro Mutual
```

</details>

<details><summary><b>#43</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>nikto</code> &nbsp; — &nbsp; ERROR: Host maximum execution time of 570 seconds reached</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
ERROR: Host maximum execution time of 570 seconds reached
```

</details>

<details><summary><b>#44</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>nikto</code> &nbsp; — &nbsp; ERROR: Unable to open '' for write:</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `https://demo.testfire.net/` |

**Evidence:**

```
ERROR: Unable to open '' for write:
```

</details>

<details><summary><b>#45</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>wafw00f</code> &nbsp; — &nbsp; No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `https://demo.testfire.net/` |

_No additional evidence captured._

</details>

---

<a id="target-demo-testfire-net-admin"></a>
### 🌐 `https://demo.testfire.net/admin/`

**41 finding(s)** &nbsp;·&nbsp; 🟠`1` 🟡`5` 🔵`30` ⚪`5`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟠 **HIGH** | `testssl` | LOGJAM-common_primes |
| 2 | 🟡 **MEDIUM** | `testssl` | BEAST_CBC_TLS1 |
| 3 | 🟡 **MEDIUM** | `testssl` | DH_groups |
| 4 | 🟡 **MEDIUM** | `testssl` | fallback_SCSV |
| 5 | 🟡 **MEDIUM** | `testssl` | overall_grade |
| 6 | 🟡 **MEDIUM** | `testssl` | security_headers |
| 7 | 🔵 **LOW** | `testssl` | BEAST |
| 8 | 🔵 **LOW** | `testssl` | cipher-tls1_1_x33 |
| 9 | 🔵 **LOW** | `testssl` | cipher-tls1_1_x39 |
| 10 | 🔵 **LOW** | `testssl` | cipher-tls1_1_xc013 |
| 11 | 🔵 **LOW** | `testssl` | cipher-tls1_1_xc014 |
| 12 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x33 |
| 13 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x39 |
| 14 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x67 |
| 15 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x6b |
| 16 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc013 |
| 17 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc014 |
| 18 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc027 |
| 19 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc028 |
| 20 | 🔵 **LOW** | `testssl` | cipher-tls1_x33 |
| 21 | 🔵 **LOW** | `testssl` | cipher-tls1_x39 |
| 22 | 🔵 **LOW** | `testssl` | cipher-tls1_xc013 |
| 23 | 🔵 **LOW** | `testssl` | cipher-tls1_xc014 |
| 24 | 🔵 **LOW** | `testssl` | cipher_order |
| 25 | 🔵 **LOW** | `testssl` | cipher_order-tls1_2 |
| 26 | 🔵 **LOW** | `testssl` | cipherlist_OBSOLETED |
| 27 | 🔵 **LOW** | `testssl` | DNS_CAArecord |
| 28 | 🔵 **LOW** | `testssl` | engine_problem |
| 29 | 🔵 **LOW** | `testssl` | FS_KEMs |
| 30 | 🔵 **LOW** | `testssl` | FS_TLS12_sig_algs |
| 31 | 🔵 **LOW** | `testssl` | HSTS |
| 32 | 🔵 **LOW** | `testssl` | LUCKY13 |
| 33 | 🔵 **LOW** | `testssl` | OCSP_stapling |
| 34 | 🔵 **LOW** | `testssl` | QUIC |
| 35 | 🔵 **LOW** | `testssl` | TLS1 |
| 36 | 🔵 **LOW** | `testssl` | TLS1_1 |
| 37 | ⚪ **INFO** | `httpx` | Alive (200) — Apache-Coyote/1.1 |
| 38 | ⚪ **INFO** | `httpx` | Alive (200) — Apache-Coyote/1.1 |
| 39 | ⚪ **INFO** | `nikto` | ERROR: Host maximum execution time of 570 seconds reached |
| 40 | ⚪ **INFO** | `nikto` | ERROR: Unable to open '' for write: |
| 41 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![high](https://img.shields.io/badge/HIGH-D7263D?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; LOGJAM-common_primes</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |
| **Reference** | CVE-2015-4000 |

**Evidence:**

```
RFC2409/Oakley Group 2
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; BEAST_CBC_TLS1</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |
| **Reference** | CVE-2011-3389 |

**Evidence:**

```
ECDHE-RSA-AES256-SHA DHE-RSA-AES256-SHA ECDHE-RSA-AES128-SHA DHE-RSA-AES128-SHA
```

</details>

<details><summary><b>#3</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; DH_groups</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
RFC2409/Oakley Group 2
```

</details>

<details><summary><b>#4</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; fallback_SCSV</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
NOT supported
```

</details>

<details><summary><b>#5</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; overall_grade</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
B
```

</details>

<details><summary><b>#6</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; security_headers</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
--
```

</details>

<details><summary><b>#7</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; BEAST</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |
| **Reference** | CVE-2011-3389 |

**Evidence:**

```
VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
```

</details>

<details><summary><b>#8</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.1   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#9</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.1   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#10</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.1   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#11</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.1   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#12</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.2   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#13</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.2   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#14</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x67</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.2   x67     DHE-RSA-AES128-SHA256             DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
```

</details>

<details><summary><b>#15</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x6b</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.2   x6b     DHE-RSA-AES256-SHA256             DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
```

</details>

<details><summary><b>#16</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.2   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#17</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.2   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#18</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc027</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.2   xc027   ECDHE-RSA-AES128-SHA256           ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
```

</details>

<details><summary><b>#19</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc028</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1.2   xc028   ECDHE-RSA-AES256-SHA384           ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
```

</details>

<details><summary><b>#20</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#21</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#22</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#23</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
TLSv1   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#24</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher_order</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
NOT a server cipher order configured
```

</details>

<details><summary><b>#25</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher_order-tls1_2</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
NOT a cipher order configured
```

</details>

<details><summary><b>#26</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipherlist_OBSOLETED</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |
| **Reference** | CWE-310 |

**Evidence:**

```
offered
```

</details>

<details><summary><b>#27</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; DNS_CAArecord</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
--
```

</details>

<details><summary><b>#28</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; engine_problem</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
No engine or GOST support via engine with your /usr/bin/openssl
```

</details>

<details><summary><b>#29</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; FS_KEMs</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
No KEMs offered
```

</details>

<details><summary><b>#30</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; FS_TLS12_sig_algs</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
RSA+SHA512 RSA+SHA384 RSA+SHA256 RSA+SHA1
```

</details>

<details><summary><b>#31</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; HSTS</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
not offered
```

</details>

<details><summary><b>#32</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; LUCKY13</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |
| **Reference** | CVE-2013-0169 |

**Evidence:**

```
potentially vulnerable, uses TLS CBC ciphers
```

</details>

<details><summary><b>#33</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; OCSP_stapling</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
not offered
```

</details>

<details><summary><b>#34</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; QUIC</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
not tested due to lack of local OpenSSL support
```

</details>

<details><summary><b>#35</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; TLS1</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
offered (deprecated)
```

</details>

<details><summary><b>#36</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; TLS1_1</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
offered (deprecated)
```

</details>

<details><summary><b>#37</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>httpx</code> &nbsp; — &nbsp; Alive (200) — Apache-Coyote/1.1</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
server=Apache-Coyote/1.1 · tech=Apache Tomcat, Java · title=Altoro Mutual
```

</details>

<details><summary><b>#38</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>httpx</code> &nbsp; — &nbsp; Alive (200) — Apache-Coyote/1.1</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
server=Apache-Coyote/1.1 · tech=Apache Tomcat, Java · title=Altoro Mutual
```

</details>

<details><summary><b>#39</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>nikto</code> &nbsp; — &nbsp; ERROR: Host maximum execution time of 570 seconds reached</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
ERROR: Host maximum execution time of 570 seconds reached
```

</details>

<details><summary><b>#40</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>nikto</code> &nbsp; — &nbsp; ERROR: Unable to open '' for write:</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `https://demo.testfire.net/admin/` |

**Evidence:**

```
ERROR: Unable to open '' for write:
```

</details>

<details><summary><b>#41</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>wafw00f</code> &nbsp; — &nbsp; No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `https://demo.testfire.net/admin/` |

_No additional evidence captured._

</details>

---

<a id="target-demo-testfire-net-admin"></a>
### 🌐 `https://demo.testfire.net/admin`

**41 finding(s)** &nbsp;·&nbsp; 🟠`1` 🟡`5` 🔵`30` ⚪`5`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟠 **HIGH** | `testssl` | LOGJAM-common_primes |
| 2 | 🟡 **MEDIUM** | `testssl` | BEAST_CBC_TLS1 |
| 3 | 🟡 **MEDIUM** | `testssl` | DH_groups |
| 4 | 🟡 **MEDIUM** | `testssl` | fallback_SCSV |
| 5 | 🟡 **MEDIUM** | `testssl` | overall_grade |
| 6 | 🟡 **MEDIUM** | `testssl` | security_headers |
| 7 | 🔵 **LOW** | `testssl` | BEAST |
| 8 | 🔵 **LOW** | `testssl` | cipher-tls1_1_x33 |
| 9 | 🔵 **LOW** | `testssl` | cipher-tls1_1_x39 |
| 10 | 🔵 **LOW** | `testssl` | cipher-tls1_1_xc013 |
| 11 | 🔵 **LOW** | `testssl` | cipher-tls1_1_xc014 |
| 12 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x33 |
| 13 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x39 |
| 14 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x67 |
| 15 | 🔵 **LOW** | `testssl` | cipher-tls1_2_x6b |
| 16 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc013 |
| 17 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc014 |
| 18 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc027 |
| 19 | 🔵 **LOW** | `testssl` | cipher-tls1_2_xc028 |
| 20 | 🔵 **LOW** | `testssl` | cipher-tls1_x33 |
| 21 | 🔵 **LOW** | `testssl` | cipher-tls1_x39 |
| 22 | 🔵 **LOW** | `testssl` | cipher-tls1_xc013 |
| 23 | 🔵 **LOW** | `testssl` | cipher-tls1_xc014 |
| 24 | 🔵 **LOW** | `testssl` | cipher_order |
| 25 | 🔵 **LOW** | `testssl` | cipher_order-tls1_2 |
| 26 | 🔵 **LOW** | `testssl` | cipherlist_OBSOLETED |
| 27 | 🔵 **LOW** | `testssl` | DNS_CAArecord |
| 28 | 🔵 **LOW** | `testssl` | engine_problem |
| 29 | 🔵 **LOW** | `testssl` | FS_KEMs |
| 30 | 🔵 **LOW** | `testssl` | FS_TLS12_sig_algs |
| 31 | 🔵 **LOW** | `testssl` | HSTS |
| 32 | 🔵 **LOW** | `testssl` | LUCKY13 |
| 33 | 🔵 **LOW** | `testssl` | OCSP_stapling |
| 34 | 🔵 **LOW** | `testssl` | QUIC |
| 35 | 🔵 **LOW** | `testssl` | TLS1 |
| 36 | 🔵 **LOW** | `testssl` | TLS1_1 |
| 37 | ⚪ **INFO** | `httpx` | Alive (200) — Apache-Coyote/1.1 |
| 38 | ⚪ **INFO** | `httpx` | Alive (200) — Apache-Coyote/1.1 |
| 39 | ⚪ **INFO** | `nikto` | ERROR: Host maximum execution time of 570 seconds reached |
| 40 | ⚪ **INFO** | `nikto` | ERROR: Unable to open '' for write: |
| 41 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![high](https://img.shields.io/badge/HIGH-D7263D?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; LOGJAM-common_primes</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |
| **Reference** | CVE-2015-4000 |

**Evidence:**

```
RFC2409/Oakley Group 2
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; BEAST_CBC_TLS1</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |
| **Reference** | CVE-2011-3389 |

**Evidence:**

```
ECDHE-RSA-AES256-SHA DHE-RSA-AES256-SHA ECDHE-RSA-AES128-SHA DHE-RSA-AES128-SHA
```

</details>

<details><summary><b>#3</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; DH_groups</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
RFC2409/Oakley Group 2
```

</details>

<details><summary><b>#4</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; fallback_SCSV</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
NOT supported
```

</details>

<details><summary><b>#5</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; overall_grade</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
B
```

</details>

<details><summary><b>#6</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; security_headers</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
--
```

</details>

<details><summary><b>#7</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; BEAST</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |
| **Reference** | CVE-2011-3389 |

**Evidence:**

```
VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
```

</details>

<details><summary><b>#8</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.1   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#9</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.1   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#10</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.1   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#11</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_1_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.1   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#12</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.2   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#13</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.2   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#14</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x67</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.2   x67     DHE-RSA-AES128-SHA256             DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
```

</details>

<details><summary><b>#15</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_x6b</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.2   x6b     DHE-RSA-AES256-SHA256             DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
```

</details>

<details><summary><b>#16</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.2   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#17</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.2   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#18</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc027</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.2   xc027   ECDHE-RSA-AES128-SHA256           ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
```

</details>

<details><summary><b>#19</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_2_xc028</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1.2   xc028   ECDHE-RSA-AES256-SHA384           ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
```

</details>

<details><summary><b>#20</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_x33</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1   x33     DHE-RSA-AES128-SHA                DH 1024    AES         128      TLS_DHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#21</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_x39</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1   x39     DHE-RSA-AES256-SHA                DH 1024    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#22</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_xc013</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1   xc013   ECDHE-RSA-AES128-SHA              ECDH 256   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

</details>

<details><summary><b>#23</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher-tls1_xc014</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
TLSv1   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```

</details>

<details><summary><b>#24</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher_order</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
NOT a server cipher order configured
```

</details>

<details><summary><b>#25</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipher_order-tls1_2</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
NOT a cipher order configured
```

</details>

<details><summary><b>#26</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; cipherlist_OBSOLETED</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |
| **Reference** | CWE-310 |

**Evidence:**

```
offered
```

</details>

<details><summary><b>#27</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; DNS_CAArecord</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
--
```

</details>

<details><summary><b>#28</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; engine_problem</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
No engine or GOST support via engine with your /usr/bin/openssl
```

</details>

<details><summary><b>#29</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; FS_KEMs</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
No KEMs offered
```

</details>

<details><summary><b>#30</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; FS_TLS12_sig_algs</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
RSA+SHA512 RSA+SHA384 RSA+SHA256 RSA+SHA1
```

</details>

<details><summary><b>#31</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; HSTS</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
not offered
```

</details>

<details><summary><b>#32</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; LUCKY13</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |
| **Reference** | CVE-2013-0169 |

**Evidence:**

```
potentially vulnerable, uses TLS CBC ciphers
```

</details>

<details><summary><b>#33</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; OCSP_stapling</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
not offered
```

</details>

<details><summary><b>#34</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; QUIC</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
not tested due to lack of local OpenSSL support
```

</details>

<details><summary><b>#35</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; TLS1</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
offered (deprecated)
```

</details>

<details><summary><b>#36</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>testssl</code> &nbsp; — &nbsp; TLS1_1</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `testssl` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
offered (deprecated)
```

</details>

<details><summary><b>#37</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>httpx</code> &nbsp; — &nbsp; Alive (200) — Apache-Coyote/1.1</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
server=Apache-Coyote/1.1 · tech=Apache Tomcat, Java · title=Altoro Mutual
```

</details>

<details><summary><b>#38</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>httpx</code> &nbsp; — &nbsp; Alive (200) — Apache-Coyote/1.1</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
server=Apache-Coyote/1.1 · tech=Apache Tomcat, Java · title=Altoro Mutual
```

</details>

<details><summary><b>#39</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>nikto</code> &nbsp; — &nbsp; ERROR: Host maximum execution time of 570 seconds reached</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
ERROR: Host maximum execution time of 570 seconds reached
```

</details>

<details><summary><b>#40</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>nikto</code> &nbsp; — &nbsp; ERROR: Unable to open '' for write:</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `https://demo.testfire.net/admin` |

**Evidence:**

```
ERROR: Unable to open '' for write:
```

</details>

<details><summary><b>#41</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>wafw00f</code> &nbsp; — &nbsp; No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `https://demo.testfire.net/admin` |

_No additional evidence captured._

</details>

---

<a id="target-demo-testfire-net-8080-login-jsp"></a>
### 🌐 `http://demo.testfire.net:8080/login.jsp`

**1 finding(s)** &nbsp;·&nbsp; 🟠`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟠 **HIGH** | `wapiti` | Cleartext Submission of Password on `passw` |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![high](https://img.shields.io/badge/HIGH-D7263D?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Cleartext Submission of Password on `passw`</summary>

| | |
|---|---|
| **Severity** | 🟠 `HIGH` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/login.jsp` |

**Evidence:**

```
GET /login.jsp
Password field passw sent in clear text from URL http://demo.testfire.net:8080/login.jsp
```

</details>

---

<a id="target-demo-testfire-net-8080"></a>
### 🌐 `http://demo.testfire.net:8080/`

**9 finding(s)** &nbsp;·&nbsp; 🟡`1` 🔵`4` ⚪`4`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Unencrypted Channels |
| 2 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 3 | 🔵 **LOW** | `wapiti` | Content Security Policy Configuration |
| 4 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |
| 5 | 🔵 **LOW** | `wapiti` | Secure Flag cookie |
| 6 | ⚪ **INFO** | `httpx` | Alive (200) — Apache-Coyote/1.1 |
| 7 | ⚪ **INFO** | `nikto` | ERROR: Host maximum execution time of 570 seconds reached |
| 8 | ⚪ **INFO** | `nikto` | ERROR: Unable to open '' for write: |
| 9 | ⚪ **INFO** | `wafw00f` | No WAF detected |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/` |

**Evidence:**

```
GET /
Sensitive data (cookie in the response) was sent over an unencrypted HTTP connection to http://demo.testfire.net:8080/. The server did not enforce HTTPS.
```

</details>

<details><summary><b>#2</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/` |

**Evidence:**

```
GET /
X-Frame-Options is not set
```

</details>

<details><summary><b>#3</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Content Security Policy Configuration</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/` |

**Evidence:**

```
GET /
CSP is not set for URL: http://demo.testfire.net:8080/
```

</details>

<details><summary><b>#4</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/` |

**Evidence:**

```
GET /
X-Content-Type-Options is not set
```

</details>

<details><summary><b>#5</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Secure Flag cookie</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/` |

**Evidence:**

```
GET /
Secure flag is not set on the cookie: 'JSESSIONID' set at 'http://demo.testfire.net:8080/'
```

</details>

<details><summary><b>#6</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>httpx</code> &nbsp; — &nbsp; Alive (200) — Apache-Coyote/1.1</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `httpx` |
| **Target** | `http://demo.testfire.net:8080/` |

**Evidence:**

```
server=Apache-Coyote/1.1 · tech=Apache Tomcat, Java · title=Altoro Mutual
```

</details>

<details><summary><b>#7</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>nikto</code> &nbsp; — &nbsp; ERROR: Host maximum execution time of 570 seconds reached</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://demo.testfire.net:8080/` |

**Evidence:**

```
ERROR: Host maximum execution time of 570 seconds reached
```

</details>

<details><summary><b>#8</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>nikto</code> &nbsp; — &nbsp; ERROR: Unable to open '' for write:</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `nikto` |
| **Target** | `http://demo.testfire.net:8080/` |

**Evidence:**

```
ERROR: Unable to open '' for write:
```

</details>

<details><summary><b>#9</b> &nbsp; ![info](https://img.shields.io/badge/INFO-6C757D?style=flat-square) &nbsp; <code>wafw00f</code> &nbsp; — &nbsp; No WAF detected</summary>

| | |
|---|---|
| **Severity** | ⚪ `INFO` |
| **Tool** | `wafw00f` |
| **Target** | `http://demo.testfire.net:8080/` |

_No additional evidence captured._

</details>

---

<a id="target-demo-testfire-net-index-jsp"></a>
### 🌐 `https://demo.testfire.net/index.jsp`

**7 finding(s)** &nbsp;·&nbsp; 🟡`7`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 2 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 3 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 4 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 5 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 6 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 7 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#3</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#4</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#5</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#6</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#7</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

---

<a id="target-demo-testfire-net-8080-index-jsp"></a>
### 🌐 `http://demo.testfire.net:8080/index.jsp`

**7 finding(s)** &nbsp;·&nbsp; 🟡`7`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 2 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 3 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 4 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 5 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 6 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |
| 7 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `content` |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#3</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#4</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#5</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#6</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

<details><summary><b>#7</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `content`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/index.jsp` |

**Evidence:**

```
GET /index.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter content
```

</details>

---

<a id="target-demo-testfire-net-sendfeedback"></a>
### 🌐 `https://demo.testfire.net/sendFeedback`

**2 finding(s)** &nbsp;·&nbsp; 🟡`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `email_addr` |
| 2 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `name` |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `email_addr`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/sendFeedback` |

**Evidence:**

```
POST /sendFeedback
Reflected Cross Site Scripting vulnerability found via injection in the parameter email_addr
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `name`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/sendFeedback` |

**Evidence:**

```
POST /sendFeedback
Reflected Cross Site Scripting vulnerability found via injection in the parameter name
```

</details>

---

<a id="target-demo-testfire-net-8080-search-jsp"></a>
### 🌐 `http://demo.testfire.net:8080/search.jsp`

**2 finding(s)** &nbsp;·&nbsp; 🟡`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `query` |
| 2 | 🟡 **MEDIUM** | `wapiti` | Unencrypted Channels |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `query`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/search.jsp` |

**Evidence:**

```
GET /search.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter query
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/search.jsp` |

**Evidence:**

```
GET /search.jsp
Sensitive data (GET parameters) was sent over an unencrypted HTTP connection to http://demo.testfire.net:8080/search.jsp?query=default. The server did not enforce HTTPS.
```

</details>

---

<a id="target-demo-testfire-net-8080-sendfeedback"></a>
### 🌐 `http://demo.testfire.net:8080/sendFeedback`

**2 finding(s)** &nbsp;·&nbsp; 🟡`2`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `email_addr` |
| 2 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `name` |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `email_addr`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/sendFeedback` |

**Evidence:**

```
POST /sendFeedback
Reflected Cross Site Scripting vulnerability found via injection in the parameter email_addr
```

</details>

<details><summary><b>#2</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `name`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/sendFeedback` |

**Evidence:**

```
POST /sendFeedback
Reflected Cross Site Scripting vulnerability found via injection in the parameter name
```

</details>

---

<a id="target-demo-testfire-net-search-jsp"></a>
### 🌐 `https://demo.testfire.net/search.jsp`

**1 finding(s)** &nbsp;·&nbsp; 🟡`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🟡 **MEDIUM** | `wapiti` | Reflected Cross Site Scripting on `query` |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![medium](https://img.shields.io/badge/MEDIUM-F46036?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Reflected Cross Site Scripting on `query`</summary>

| | |
|---|---|
| **Severity** | 🟡 `MEDIUM` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/search.jsp` |

**Evidence:**

```
GET /search.jsp
Reflected Cross Site Scripting vulnerability found via injection in the parameter query
```

</details>

---

<a id="target-demo-testfire-net-8080-dosubscribe"></a>
### 🌐 `http://demo.testfire.net:8080/doSubscribe`

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
| **Target** | `http://demo.testfire.net:8080/doSubscribe` |

**Evidence:**

```
POST /doSubscribe
Sensitive data (POST data) was sent over an unencrypted HTTP connection to http://demo.testfire.net:8080/doSubscribe. The server did not enforce HTTPS.
```

</details>

---

<a id="target-demo-testfire-net-443"></a>
### 🌐 `demo.testfire.net:443`

**6 finding(s)** &nbsp;·&nbsp; 🔵`6`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `nuclei` | Weak Cipher Suites Detection |
| 2 | 🔵 **LOW** | `nuclei` | Weak Cipher Suites Detection |
| 3 | 🔵 **LOW** | `nuclei` | Weak Cipher Suites Detection |
| 4 | 🔵 **LOW** | `nuclei` | Weak Cipher Suites Detection |
| 5 | 🔵 **LOW** | `nuclei` | Weak Cipher Suites Detection |
| 6 | 🔵 **LOW** | `nuclei` | Weak Cipher Suites Detection |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; Weak Cipher Suites Detection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `demo.testfire.net:443` |
| **Reference** | https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |

**Evidence:**

```
A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
```

</details>

<details><summary><b>#2</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; Weak Cipher Suites Detection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `demo.testfire.net:443` |
| **Reference** | https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |

**Evidence:**

```
A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
```

</details>

<details><summary><b>#3</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; Weak Cipher Suites Detection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `demo.testfire.net:443` |
| **Reference** | https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |

**Evidence:**

```
A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
```

</details>

<details><summary><b>#4</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; Weak Cipher Suites Detection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `demo.testfire.net:443` |
| **Reference** | https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |

**Evidence:**

```
A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
```

</details>

<details><summary><b>#5</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; Weak Cipher Suites Detection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `demo.testfire.net:443` |
| **Reference** | https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |

**Evidence:**

```
A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
```

</details>

<details><summary><b>#6</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>nuclei</code> &nbsp; — &nbsp; Weak Cipher Suites Detection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `nuclei` |
| **Target** | `demo.testfire.net:443` |
| **Reference** | https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/, http://ciphersuite.info |

**Evidence:**

```
A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
```

</details>

---

<a id="target-demo-testfire-net-admin-admin"></a>
### 🌐 `https://demo.testfire.net/admin/admin`

**3 finding(s)** &nbsp;·&nbsp; 🔵`3`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 2 | 🔵 **LOW** | `wapiti` | HTTP Strict Transport Security (HSTS) |
| 3 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/admin/admin` |

**Evidence:**

```
GET /admin
X-Frame-Options is not set
```

</details>

<details><summary><b>#2</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; HTTP Strict Transport Security (HSTS)</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/admin/admin` |

**Evidence:**

```
GET /admin
Strict-Transport-Security is not set
```

</details>

<details><summary><b>#3</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/admin/admin` |

**Evidence:**

```
GET /admin
X-Content-Type-Options is not set
```

</details>

---

<a id="target-demo-testfire-net-admin-admin"></a>
### 🌐 `https://demo.testfire.net/admin/admin/`

**3 finding(s)** &nbsp;·&nbsp; 🔵`3`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Clickjacking Protection |
| 2 | 🔵 **LOW** | `wapiti` | HTTP Strict Transport Security (HSTS) |
| 3 | 🔵 **LOW** | `wapiti` | MIME Type Confusion |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Clickjacking Protection</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/admin/admin/` |

**Evidence:**

```
GET /admin/
X-Frame-Options is not set
```

</details>

<details><summary><b>#2</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; HTTP Strict Transport Security (HSTS)</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/admin/admin/` |

**Evidence:**

```
GET /admin/
Strict-Transport-Security is not set
```

</details>

<details><summary><b>#3</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; MIME Type Confusion</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `https://demo.testfire.net/admin/admin/` |

**Evidence:**

```
GET /admin/
X-Content-Type-Options is not set
```

</details>

---

<a id="target-demo-testfire-net-8080-default-jsp"></a>
### 🌐 `http://demo.testfire.net:8080/default.jsp`

**1 finding(s)** &nbsp;·&nbsp; 🔵`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Unencrypted Channels |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/default.jsp` |

**Evidence:**

```
GET /default.jsp
No HTTPS redirection for this host. All HTTP requests are served in clear text.
```

</details>

---

<a id="target-demo-testfire-net-8080-dologin"></a>
### 🌐 `http://demo.testfire.net:8080/doLogin`

**1 finding(s)** &nbsp;·&nbsp; 🔵`1`

#### Summary

| # | Severity | Tool | Title |
|--:|:--------:|:----:|------|
| 1 | 🔵 **LOW** | `wapiti` | Unencrypted Channels |

#### Detailed Findings

<details><summary><b>#1</b> &nbsp; ![low](https://img.shields.io/badge/LOW-2E86AB?style=flat-square) &nbsp; <code>wapiti</code> &nbsp; — &nbsp; Unencrypted Channels</summary>

| | |
|---|---|
| **Severity** | 🔵 `LOW` |
| **Tool** | `wapiti` |
| **Target** | `http://demo.testfire.net:8080/doLogin` |

**Evidence:**

```
POST /doLogin
Sensitive data (POST data) was sent over an unencrypted HTTP connection to http://demo.testfire.net:8080/doLogin. The server redirected, but not to an HTTPS URL, leaving the initial data and the redirection exposed.
```

</details>

---

## ⚙️ Scan Metadata

| Field | Value |
|---|---|
| VulnMalper version | `v2.4.0` |
| Source NetMalper target | `demo.testfire.net` |
| Generated (UTC) | `2026-04-21 14:41:46 UTC` |
| Total scan duration | `1229.4s` |
| Tools dispatched | `httpx`→🟢 local · `whatweb`→🟢 local · `wafw00f`→🟢 local · `testssl`→🟢 local · `nikto`→🟢 local · `nuclei`→🟢 local · `wapiti`→🟢 local · `sqlmap`→🟢 local |

---
_Report generated by **VulnMalper** — pipelines NetMalper recon into nikto, nuclei, sqlmap, wapiti, testssl, httpx, whatweb & wafw00f._
