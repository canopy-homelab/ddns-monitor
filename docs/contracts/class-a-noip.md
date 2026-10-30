# No-IP DDNS API Contract Specification

> [!NOTE]
> This document details the technical contract for No-IP's Dynamic DNS update endpoint.
> All findings below reflect empirical verification against No-IP production endpoints
> (`dynupdate.no-ip.com`) on October 30, 2026, executed via
> [`tests/contracts/test_noip_contract.py`](file:///home/kiskaadee/Projects/active/ddns-monitor/tests/contracts/test_noip_contract.py).

---

## 1. Remote Interface & Transport

* **Category:** Class A (Dedicated HTTP DDNS Protocol / DynDNS2 Dialect)
* **Base Endpoint:** `GET https://dynupdate.no-ip.com/nic/update`
* **Transport:** HTTPS (Port 443) recommended; HTTP (Ports 80 and 8245) supported for legacy devices or ISP proxy bypass.
* **Authentication Mechanism:** HTTP Basic Authentication (`Authorization: Basic base64(username:password)`).
  * Supports primary account email/password or scoped **DDNS Keys** (`username@ddnskey.com` / password token).
* **Primary Query Parameters:**
  * `hostname`: Target FQDN, comma-separated list of hostnames, or group meta-host (`all.ddnskey.com`).
  * `myip`: Target IPv4 address, IPv6 address, or comma-separated dual-stack pair (`v4,v6`). Auto-detected if omitted.
  * `myipv6`: Optional explicit IPv6 parameter.
  * `offline`: `YES` marks the host as parked/offline.
* **User-Agent Header:** Requires a custom formatted User-Agent (`Program/Version contact@domain.com`). Generic/blacklisted agents risk rate limiting or `badagent` rejection.

---

## 2. Empirical Verification: Claims vs. Reality

Testing against live No-IP endpoints revealed crucial deviations from legacy DynDNS2 documentation and literature claims:

| Dimension / Test Case | Legacy Claim | Observed Reality (Production) | Classification |
|---|---|---|---|
| **Rate Limiting / Abuse** | Returns `200 OK` with body `abuse` or `911` | Returns standard **`HTTP 429 Too Many Requests`** | **MAJOR DISCREPANCY** |
| **Bogon / Test IP Filtering (`198.51.100.42`)** | Sets record to specified IP | Discards RFC 5737 IPs; silently falls back to caller WAN IP | **DISCREPANCY** |
| **Idempotency Syntax** | Returns `nochg <ip>` | Returns exact string **`nochg <ip>`** (always includes IP token) | **CONFIRMED** |
| **Missing Parameter (`hostname=""`)** | Returns `nohost` | Returns string **`nohost`** (HTTP 200) | **CONFIRMED** |
| **DDNS Key Group Scoping** | Requires specific FQDN | Key updates entire assigned group regardless of hostname string | **CONFIRMED** |
| **Unauthenticated Short-Circuit** | Returns HTTP 401 `badauth` | Returns **`200 OK` with `nochg <ip>`** if caller IP matches! | **MAJOR DISCREPANCY** |
| **Authoritative DNS Reflection** | Matches updated IP | Verified on `nf1.no-ip.com` | **CONFIRMED** |

---

## 3. Behavioral Mechanisms & Analysis

### Modern HTTP 429 vs. Legacy `abuse` String
While historical documentation describes No-IP returning a plaintext string `abuse` inside an HTTP 200 payload, modern edge infrastructure enforces standard HTTP status codes:
* Rapid consecutive requests trigger an immediate **`HTTP 429 Too Many Requests`**.
* The HTTP response body on a 429 is empty or a standard gateway notice.
* The engine must inspect HTTP status codes before inspecting DynDNS2 text bodies.

### The Universal "Idempotency Bypass" Short-Circuit
Consistent with Dynu, No-IP inspects the caller's source IP address before evaluating credentials:
* If the incoming request matches the active record on No-IP, the edge gateway returns `nochg <ip>` (HTTP 200) **without requiring or verifying HTTP Basic Auth**.
* Only when an update would actually **mutate** DNS state (e.g., specifying a differing `myip` or unowned domain) does No-IP enforce authentication and reject invalid credentials with `401 Unauthorized` / `badauth`.

### Strict DynDNS2 Token Formatting
Unlike Dynu (which often returns a bare `nochg` with no following IP), No-IP strictly outputs exactly two space-separated tokens for successful operations:
* Mutating success: `good <ip>`
* Idempotent no-op: `nochg <ip>`

### Bogon / Documentation IP Discarding
No-IP does not allow setting RFC 5737 (`198.51.100.0/24`) or private RFC 1918 addresses. When supplied, No-IP silently discards the parameter and defaults to the connection's public source IPv4 address.

### DDNS Key Scoping
When authenticating with a DDNS Key (`@ddnskey.com`):
* The key is cryptographically tied to a pre-configured hostname group in the No-IP account dashboard.
* Supplying any arbitrary string in `hostname` (or `all.ddnskey.com`) automatically updates the group.
* Only omitting the parameter entirely (`hostname=`) triggers `nohost`.

---

## 4. Adapter Implementation Requirements (Rust Engine)

The No-IP plugin (`src/plugins/noip.rs`) must observe the following contract invariants:

1. **Explicit HTTP 429 Handling:**
   Catch HTTP 429 in the transport layer and trigger an exponential backoff circuit breaker (e.g., 30 minutes) to avoid account suspension:
   ```rust
   if response.status() == 429 {
       return Err(DdnsError::RateLimited("No-IP HTTP 429: Too Many Requests"));
   }
   ```
2. **Two-Token Parsing:**
   Parse the response by splitting whitespace tokens:
   ```rust
   let mut parts = body.split_whitespace();
   match parts.next() {
       Some("good") => Ok(UpdateResult::Updated(parts.next().unwrap_or_default())),
       Some("nochg") => Ok(UpdateResult::NoChange(parts.next().unwrap_or_default())),
       Some("badauth") => Err(DdnsError::AuthenticationFailed),
       Some("nohost") => Err(DdnsError::DomainNotFound),
       _ => Err(DdnsError::ProtocolViolation(body)),
   }
   ```
3. **Mandatory Custom User-Agent:**
   Always inject a formatted `User-Agent: <app>/<version> <email>` header into the request.

---

## 5. Untested Surfaces & Open Questions

- [ ] **Dual-Stack Comma Notation:** Does `myip=1.2.3.4,2001:db8::1` update both `A` and `AAAA` records in a single hit?
- [ ] **Offline Mode (`offline=YES`):** Does setting `offline=YES` disable DNS resolution or redirect to a parked IP?
