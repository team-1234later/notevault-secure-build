# Term Project Report — Secure Build

> Fill in every section. Keep the headings. Total **100 pts** (see rubric at the end).
> This is **team work** (2–3). Do not share your report with other teams.

## Cover

| Field | Value |
|---|---|
| Team name | |
| Members (name + ID) | |
| Target application | |
| Repository URL | |
| Date | |

## AI-tool usage disclosure
*Academic integrity: state how you used any AI tools (ChatGPT, Copilot, etc.) — e.g. searching, coding, translating, drafting. "None" is a valid answer.*

| Tool | How it was used |
|---|---|
| | |

---

## 1. Executive Summary
*(½ page) What the app is, how many findings by severity, and the overall risk before vs. after your fixes.*

---

## 2. System Scope & Function
- What the application does; in-scope components and endpoints.
- **Data-Flow Diagram (DFD):** processes, data stores, external entities, **trust boundaries** (insert image).

---

## 3. Threat Model — STRIDE  *(20 pts)*

| Element / data flow | S | T | R | I | D | E | Top threat & mitigation |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

*Then rank the top 5 risks by likelihood × impact.*

---

## 4. Vulnerability Findings  *(25 pts)*

One block per finding (copy as needed):

### Finding F-01 — Passwords stored as unsalted MD5
| Field | Value |
|---|---|
| CWE | CWE-916 (Use of Password Hash With Insufficient Computational Effort) / CWE-327 (Broken Crypto Algorithm) |
| OWASP 2025 | A04 Cryptographic Failures |
| Severity | High |
| Location | `project/starter-app/app.py:68-69` (`seed()`), also used at registration (`app.py:117`) and login (`app.py:129`) |
| Reproduction | `seed()` stores `hashlib.md5(b"alicepw").hexdigest()` for user `alice` and `hashlib.md5(b"admin123").hexdigest()` for user `admin` — no salt. Given only these hash values (e.g. from a future `/admin` dump), the same guess-hash-compare dictionary attack used in Week 3 Task 1 recovers both plaintexts (`alicepw`, `admin123`) almost instantly, since MD5 is deliberately fast and unsalted. |
| Impact | Anyone who obtains the `users` table (via `/admin` with a hijacked/leaked admin session, or a future SQL injection) can recover every account's real password in seconds, including the `admin` account, giving full account takeover. |
| Evidence | Source lines above + Week 3 `worksheet.md` Task 1 (same cracking method applied to `hashes.txt`). Verified crack of the dumped hashes: `admin -> admin123`, `alice -> alicepw`. Screenshot: `screenshots/findings/F-01-crack-md5.png`. |

### Finding F-02 — Session tokens accept the `alg: none` JWT (authentication bypass)
| Field | Value |
|---|---|
| CWE | CWE-347 (Improper Verification of Cryptographic Signature) |
| OWASP 2025 | A07 Identification and Authentication Failures |
| Severity | Medium (latent misconfiguration — not currently exploitable; see verified note) |
| Location | `app.py:83` (`current_user()`), `jwt.decode(tok, SECRET, algorithms=["HS256", "none"])` |
| Reproduction | A JWT session cookie is normally trusted because it carries an `HS256` signature made with the server's secret, which an attacker cannot reproduce. `current_user()` also lists the `none` algorithm — a token type that carries *no* signature and is not verified — which is a dangerous thing to accept: in principle an attacker could craft `{"alg":"none"}` / `{"sub":"admin"}` with an empty signature and be trusted. |
| Impact | **Verified: not exploitable as currently deployed.** The pinned library `PyJWT==1.7.1` refuses an `alg:none` token whenever a key is supplied, and `current_user()` always passes `SECRET`. A forged `none` token therefore fails with `InvalidKeyError: When alg = "none", key value must be None`, the `except` returns `None`, and `/admin` returns `403` (tested). The risk is latent: the allow-list still *declares* `none` as acceptable, so a later refactor that passes `key=None`, or a library version that honors `none` with a key, would immediately expose full authentication bypass. Treat as defense-in-depth hardening. |
| Evidence | Verified against the running app: forged token `eyJhbGciOiJub25lIi...` on the `session` cookie → `/admin` returns `403`; in-container `jwt.decode(tok, SECRET, algorithms=["HS256","none"])` raises `InvalidKeyError`. (The *exploitable* forgery path is F-05, using the known `SECRET` to mint a valid `HS256` token instead.) Screenshot: `screenshots/findings/F-02-none-rejected.png`. |

*Root cause in plain terms: the whole security of the token lives in its signature, yet the client is allowed to choose `none`, i.e. to say "don't check my signature." The one routine whose job is to verify is handed a mode that means do-not-verify — a check that doesn't check. Here a second safety net (the library's key guard) happens to stop it, but the misconfiguration should still be removed so the design doesn't rely on that accident. Fix: `algorithms=["HS256"]`.*

### Finding F-03 — SQL injection in the login query (authentication bypass)
| Field | Value |
|---|---|
| CWE | CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) |
| OWASP 2025 | A03 Injection |
| Severity | Critical |
| Location | `app.py:128` (`login()`), `q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (...)` |
| Reproduction | The login query is built by pasting the user's input straight into the SQL string with `%s`, so the database cannot tell which part is the query the app meant to send and which part is user data — if the input contains SQL, it runs as SQL. Submitting username `admin'--` with any password turns the query into `SELECT * FROM users WHERE username = 'admin'--' AND password = '...'`, where `--` comments out the rest of the line, deleting the password check. A row is returned and the server issues a valid session cookie. **Verified** against the running app: `curl "http://localhost:8080/login" --data-urlencode "username=admin'--" --data-urlencode "password=wrongpassword"` returns `302` + `Set-Cookie: session=...` (not `401 login failed`), and the home page then shows `Signed in as admin'--`. |
| Impact | Authentication bypass: an attacker obtains a valid logged-in session with no knowledge of any password. **Scope note (verified):** because `login()` writes the raw username into the token's `sub`, the resulting session is for the literal string `admin'--`, which is not the real `admin` row — so `/admin` still returns `403` and this flaw alone does **not** grant admin privileges. It does bypass the credential check and can be used for blind data extraction from the `users` table. Privilege escalation to admin is achieved by F-02 or F-04, not by this finding. |
| Evidence | Verified curl above (302 + session cookie with a wrong password); `/admin` with that cookie returns `403` (confirming no role escalation). The same file shows the correct, safe pattern in `role_of()` (`app.py:91`) using a `?` placeholder. Attack screenshot: `screenshots/findings/F-03-sqli-login-bypass.png`. Before/after remediation screenshots to be added in §5. |

*Contrast within the same file: `login()` concatenates input into the SQL string (vulnerable), while `role_of()` at `app.py:91` passes input through a `?` parameter, which keeps the command and the data separate so user input can never be executed as SQL. The fix for F-03 is to make `login()` use the same parameterized form.*

### Finding F-04 — Privilege escalation via mass assignment on registration
| Field | Value |
|---|---|
| CWE | CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) |
| OWASP 2025 | A04 Insecure Design / A01 Broken Access Control |
| Severity | High |
| Location | `app.py:114` (`register()`), `role = request.form.get("role") or ... or "user"` |
| Reproduction | `register()` reads `role` from client-supplied input and stores it directly, so it accepts a role the user chose rather than forcing a default. The web form (`app.py:48`) only shows username and password fields — but that is not a control, it merely hides the field. An attacker bypasses the form and sends the request directly, adding a `role` parameter. **Verified** against the running app: `curl "http://localhost:8080/register" --data-urlencode "username=pwned" --data-urlencode "password=x" --data-urlencode "role=admin"` → `302`; then logging in as `pwned` and requesting `/admin` returns `200` with the full users dump. The account is created as an administrator at sign-up, because the function does not reject the extra field. |
| Impact | Any anonymous visitor can create an admin account for themselves, gaining access to `/admin` (which dumps every user's hash — see F-01) and all administrative functionality. No existing credentials required. This is a second verified path to admin, independent of F-05. |
| Evidence | Verified curl above (`pwned` account → `/admin` returns `200`). The registration form at `app.py:48` has no `role` input, demonstrating that the field is accepted by the backend only, not exposed in the UI. Attack screenshot: `screenshots/findings/F-04-register-as-admin.png`. Before/after remediation screenshots to be added in §5. |

*Root cause in plain terms: `register()` accepts whatever fields the client sends, including `role`, and never refuses the ones a user should not be allowed to set. Hiding the field in the HTML form does not protect it — the backend must force new accounts to `"user"` and ignore any client-supplied role.*

### Finding F-05 — Hard-coded session-signing secret
| Field | Value |
|---|---|
| CWE | CWE-798 (Use of Hard-coded Credentials) / CWE-321 (Use of Hard-coded Cryptographic Key) |
| OWASP 2025 | A05 Security Misconfiguration / A02 Cryptographic Failures |
| Severity | High |
| Location | `app.py:23`, `SECRET = "notevault-dev-secret"` (used to sign/verify JWT session tokens at `app.py:83,134`) |
| Reproduction | `SECRET` is the system's own password — the single key used to sign every `HS256` session token and to verify incoming ones. Its security depends entirely on staying secret, yet it is written in plaintext in the source, so anyone who can read the code (any teammate, anyone on GitHub, anyone the repo leaks to) has the key. The value `notevault-dev-secret` is also trivially guessable. **Verified exploit:** using the key from line 23, mint a valid HS256 token — `jwt.encode({"sub":"admin"}, "notevault-dev-secret", algorithm="HS256")` → `eyJ0eXAiOiJKV1Qi...` — and send it as the `session` cookie: `curl -b "session=<token>" http://localhost:8080/admin` returns `200` with the full `users` table dump (all usernames, roles, and MD5 password hashes). |
| Impact | Full session forgery and admin account takeover with no password. This is the real, working path to admin (F-02's `none` route is blocked by the library; this HS256 route is not). It chains directly: forged admin → `/admin` dumps every password hash → F-01 (unsalted MD5) recovers the plaintexts (`admin123`, `alicepw`) offline in seconds. |
| Evidence | Verified against the running app (curl above returned the users dump incl. `admin` hash `0192023a7bbd73250516f069df18b500` = md5("admin123")). The signing *algorithm* (HS256) being public is fine; only the key must stay secret, and here it does not. Attack screenshot: `screenshots/findings/F-05-forge-token-admin-dump.png`. Before/after remediation screenshots to be added in §5. |

*Root cause in plain terms: `SECRET` is effectively the whole system's password — unlike a user's password, it proves a session token was issued by this server. Publishing a user password is bad; publishing the system's password, which unlocks every account, is worse. It must be loaded from an environment variable (or secrets manager), never committed, and set to a long random value.*

### Finding F-06 — Session cookie set without security flags (HttpOnly / Secure / SameSite)
| Field | Value |
|---|---|
| CWE | CWE-1004 (Sensitive Cookie Without HttpOnly) / CWE-614 (Sensitive Cookie Without Secure) |
| OWASP 2025 | A05 Security Misconfiguration |
| Severity | Medium |
| Location | `app.py:136` (`login()`), `resp.set_cookie("session", tok)` — no flags set |
| Reproduction | The session cookie (the JWT that proves a user is logged in) is set with no protective flags. **No `HttpOnly`:** page JavaScript can read `document.cookie`, so if the app is hit by an XSS (e.g. the stored-XSS style issue seen in Week 14), the injected script reads the victim's session cookie and exfiltrates it, letting the attacker impersonate the victim with no password. **No `Secure`:** the cookie is sent over plain HTTP, so a network eavesdropper (e.g. shared Wi-Fi) can capture it. **No `SameSite`:** the browser attaches the cookie to cross-site requests, enabling CSRF. |
| Impact | Session hijacking / account takeover when combined with an XSS or a network-level attacker; CSRF against state-changing endpoints. Elevates the impact of any XSS from "run script" to "steal the session." |
| Evidence | Source line above. Before/after: `document.cookie` shows the session value while the flag is absent, and returns empty for it once `HttpOnly` is set. Verified: the login response sets `Set-Cookie: session=...; Path=/` with no `HttpOnly`/`Secure`/`SameSite`. Screenshot: `screenshots/findings/F-06-cookie-no-flags.png`. |

*Root cause in plain terms: the cookie holding the login token is handed out with no rules about who may touch it. `HttpOnly` stops page scripts from reading it (defuses cookie theft via XSS), `Secure` keeps it off unencrypted connections, and `SameSite` stops other sites from riding on it. Fix: `resp.set_cookie("session", tok, httponly=True, secure=True, samesite="Lax")`.*

---

## 5. Remediation  *(25 pts)*

Per finding: the fix, **before/after** code, and the commit that implements it.

### Fix for F-01
```diff
- vulnerable line
+ fixed line
```
- **Why this fixes it:** …
- **Commit:** `<hash>`
- **Proof the exploit now fails:** (screenshot)

---

## 6. Supply-Chain Hardening  *(15 pts)*
- **SBOM** (CycloneDX) generated — attach `sbom.json`, note component count.
- **Artifact signed & verified** with Cosign — paste the `cosign verify` output.
- One-paragraph **SLSA** self-assessment (which level, why).

---

## 7. Security CI Pipeline  *(10 pts)*
- Link to the GitHub Actions workflow (SAST + SCA + secret scanning).
- Screenshot of a build **failing** on a HIGH/CRITICAL finding.
- How the gate is configured (what fails the build).

---

## 8. Conclusion & Reflection  *(5 pts — clarity)*
- Residual risks and what you'd harden next.
- Lessons learned.

---

## Appendix
- Tools used, references (OWASP/CWE links), and the team's task split.

---

## Grading rubric (100)

| Criterion | Pts |
|---|---|
| Threat model quality & completeness (§3) | 20 |
| Vulnerability findings — correctness, CWE/OWASP mapping, depth (§4) | 25 |
| Remediation quality — correct, minimal, well-explained (§5) | 25 |
| Supply-chain hardening — SBOM + signing + provenance (§6) | 15 |
| CI pipeline — works, fails build appropriately (§7) | 10 |
| Presentation & report clarity (§1, §8) | 5 |

*All work stays within the [ethics policy](../ETHICS.md).*
