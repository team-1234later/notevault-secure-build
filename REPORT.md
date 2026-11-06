# Term Project Report — Secure Build

> Fill in every section. Keep the headings. Total **100 pts** (see rubric at the end).
> This is **team work** (2–3). Do not share your report with other teams.

## Cover

| Field | Value |
|---|---|
| Team name | 1234Later (`TEAM_ID=1234Later`) |
| Members (name + ID) | A: Sorrawit Thanakhwang (6531503080) · B: Neree Booncharoen (6631503018) · C: Sutapat Chucham (6531503085) · D: Nararat Kritphet (6631503110) |
| Target application | NoteVault (course term-project starter app: Flask note-sharing web app + JSON API) |
| Repository URL | https://github.com/team-1234later/notevault-secure-build (fixes on branch `remediation`) |
| Video | ____ *(unlisted link — added after the clips are combined)* |
| Date | 6 November 2026 |

## AI-tool usage disclosure
*Academic integrity: state how you used any AI tools (ChatGPT, Copilot, etc.) — e.g. searching, coding, translating, drafting. "None" is a valid answer.*

| Member | Tool | How it was used |
|---|---|---|
| A — Sorrawit | Claude (Anthropic), via Claude Code | Used as a tutor and assistant throughout. It explained concepts in Thai before each fix (parameterized queries, JWT algorithms, cookie flags, argon2id, fail-closed secrets), and I answered its questions before the fix was written. It drafted the fix code for F-01–F-06 and F-11, which I reviewed and committed myself. It rebuilt the app in Docker to check that each fix stopped the attack and broke nothing, ran the Trivy scans, and noticed that `requests`/`urllib3` are unused. During that checking it also found the `/search` template injection (§8). It produced the DFD as a diagram, polished the English of the report sections I own plus §2, and drafted wording from my own notes and answers (e.g. the lessons learned in §8). I ran every attack and retest myself for the screenshots, decided which findings and fixes to keep, and can explain each one. |
| B — Neree | ChatGPT (OpenAI) | Help with the parameterized `/search` query and the ownership check on `/api/notes/<id>` (F-10), and with adapting the Week 15 lab's `security-ci.yml` template into this repo's pipeline. |
| C — Sutapat | Claude (Anthropic) | Help with testing and writing up F-07–F-09 (command injection in `/export`, password hashes in `/admin`, Dockerfile hardening): explaining the issues, drafting the fix code and its comments, suggesting the `docker inspect`/`docker history` checks used as evidence, and polishing the English of the §4/§5 entries. |
| D — Nararat | ChatGPT (OpenAI) | Used to understand the Trivy scan output for `requirements.txt` (what each CVE means, which libraries the app actually uses, and why removing unused ones is safer than upgrading them), and to check the wording of the system-scope description in §2. |

---

## 1. Executive Summary
NoteVault is a small Flask web app where users register, log in with a cookie session, keep private notes, search them, and export them, with an admin panel that lists users. We assessed it as a four-person team: we threat-modelled it with STRIDE over a data-flow diagram (§3), attacked every endpoint and the container build, and fixed what we found on the `remediation` branch.

**Before our fixes the app was effectively wide open.** We verified **14 findings: 3 Critical, 7 High, 3 Medium, 1 Low.**

| Severity | Findings |
|---|---|
| Critical | F-03 SQL injection in `/login` · F-07 OS command injection in `/export` (remote code execution as root) · F-13 template injection in `/search` (remote code execution) |
| High | F-01 unsalted MD5 passwords · F-04 self-registration as admin · F-05 hard-coded JWT signing key · F-09 Dockerfile runs as root with a baked-in secret · F-10 any user can read any note by id (BOLA) · F-11 17 known CVEs in outdated dependencies · F-12 SQL injection in `/search` |
| Medium | F-02 `alg:none` allowed in JWT verification (latent) · F-06 session cookie without HttpOnly/Secure/SameSite · F-08 `/admin` returns password hashes |
| Low | F-14 HTML injection in notes (stored XSS, currently self-only) |

Three independent paths gave a stranger full control with no password: register with `role=admin` (F-04), forge an admin token with the key from the source code (F-05), or inject a shell command through `/export` (F-07). Once inside, `/admin` handed out every password hash (F-08), and because they were unsalted MD5 (F-01), `admin123` and `alicepw` cracked in seconds.

**After our fixes,** every one of these attacks was replayed against a fresh build and now fails (§5): queries are parameterized, roles are set by the server, the signing key comes from the environment and the app refuses to start without one, only `HS256` tokens are accepted, cookies carry all three flags, passwords are argon2id, `/export` no longer uses a shell, `/admin` no longer returns hashes, notes are checked for ownership, the container runs as a non-root user from a pinned image, and every dependency is on a current release with Trivy reporting zero High/Critical issues. The overall risk drops from **critical (anonymous admin and remote code execution)** to **low**, with the remaining hardening items listed in §8. All 14 findings are fixed and retested in §5, including the two output-handling bugs found last: F-13 (template injection in `/search`) and F-14 (HTML injection in notes).

---

## 2. System Scope & Function
### What the application does
NoteVault is a small team note-sharing web app with a JSON API, written in Python with Flask and backed by a single SQLite file. A visitor can register and log in. Login issues a session cookie that holds a JWT signed by the server. A logged-in user can then add private notes, list and search their own notes, fetch a single note through the API, and export their notes. Users with the `admin` role also get an admin panel that lists every account. The app ships as one Docker container built from the repository's `Dockerfile` and is started with `docker compose up` on port 8080.

### In-scope components

| Component | What it is | In scope because |
|---|---|---|
| Web app (`app.py`) | Flask routes, session handling, HTML templates | All application logic and every finding in §4 lives here |
| Session token | JWT (`HS256`) in the `session` cookie, signed with `SECRET` | It is the only thing that proves who a request comes from |
| Database | SQLite at `/tmp/notevault.db`: `users` (username, password hash, role) and `notes` (owner, title, body) | Holds credentials and private notes |
| OS shell | Reached by `/export` through `subprocess` | It is a second trust boundary inside the server |
| Container build | `Dockerfile`, `docker-compose.yml` | Decides the user the app runs as and where secrets live |
| Dependencies | `requirements.txt` (Flask, Werkzeug, Jinja2, PyJWT, requests, urllib3, argon2-cffi) | Third-party code runs with the app's privileges |

Out of scope: the host machine, Docker itself, GitHub, and any network beyond `localhost`.

### Endpoints

| Method + path | Auth needed | Purpose | Related findings |
|---|---|---|---|
| `GET /` | optional | Login/register forms, or the user's notes when logged in | F-14 |
| `POST /register` | none | Create an account | F-01, F-04 |
| `POST /login` | none | Check credentials, set the `session` cookie | F-01, F-03, F-05, F-06 |
| `GET /logout` | none | Delete the session cookie | session revocation (§8) |
| `POST /notes` | user | Add a note | — |
| `GET /api/notes/<id>` | user | Return one note as JSON | F-10 |
| `GET /search?q=` | user | Search the user's own notes | F-12, F-13 |
| `GET /admin` | admin | List all users | F-08 |
| `GET /export?fmt=` | user | Export notes in a chosen format | F-07 |
| every request | — | `current_user()` reads and verifies the JWT | F-02, F-05 |

### Data-Flow Diagram (DFD)

![NoteVault DFD](screenshots/dfd-notevault.png)

The diagram shows one external entity (the user's browser), four processes (Auth & Session, Notes & Search, Admin Panel, Export), two data stores (the SQLite database and the signing secret) and the OS shell. It has **two trust boundaries**:
1. **Browser → Server.** Everything the client sends (form fields, query strings, the cookie) is untrusted until the server checks it. Most of our findings sit on this line: F-03 and F-04 trust form input, and F-02 and F-05 trust the token.
2. **App → OS shell.** `/export` passes data from the app into a shell command. Crossing this line without validation turns an input bug into remote code execution (F-07).

The full STRIDE walk over each element of this diagram is in §3.

---

## 3. Threat Model — STRIDE  *(20 pts)*

We walked each element and flow of the §2 DFD and applied STRIDE. `✓` marks a threat that is realistic for that element in NoteVault as built; `–` marks one that does not meaningfully apply. The "Top threat & mitigation" column names the single worst case and the control that removes it. Findings proven in §4 are cited by their `F-` number. The threat model was drawn before the findings were split across the team; the extra threats it surfaced (command injection, BOLA, search SQLi, stored XSS) were then confirmed and written up as F-07, F-10, F-12 and F-14.

| Element / data flow | S | T | R | I | D | E | Top threat & mitigation |
|---|---|---|---|---|---|---|---|
| **Credentials flow** — Browser → `/login`, `/register` | ✓ | ✓ | ✓ | ✓ | – | ✓ | **Authentication bypass / self-made admin.** `login()` builds SQL by string formatting (`admin'--` logs in with no password, **F-03**), and `register()` trusts a client-supplied `role` (`role=admin` → instant admin, **F-04**). *Mitigation:* parameterize the login query (use the `?` form already in `role_of()`); force new accounts to `role="user"` and ignore any client role. |
| **Session cookie (JWT)** — issued by `/login`, read by every route via `current_user()` | ✓ | ✓ | – | ✓ | – | ✓ | **Token forgery → admin with no password.** The signing key is hard-coded (`SECRET`, **F-05**), so anyone can mint a valid `HS256` token for `sub=admin`; `current_user()` also allow-lists `alg:none` (**F-02**, latent); the cookie carries no `HttpOnly`/`Secure`/`SameSite`, so an XSS can steal it (**F-06**). *Mitigation:* load `SECRET` from the environment / a secrets manager and rotate it; `algorithms=["HS256"]` only; set `httponly=True, secure=True, samesite="Lax"`. |
| **Auth & Session process** — `current_user()`, `role_of()` | ✓ | – | ✗ | – | – | ✓ | **Spoofing via a forged or `none` token** is accepted as a real identity. *Mitigation:* as above — verify only `HS256` against a secret the client cannot know. |
| **Notes & Search process** — `/`, `/notes`, `/api/notes/<id>`, `/search` | – | ✓ | – | ✓ | – | – | **Cross-user note disclosure + second SQLi.** `/api/notes/<id>` returns any note by id with no owner check — any logged-in user reads the admin's note (`prod db password is hunter2`), a BOLA (**F-10**); `/search` builds SQL with `%s` again, a second injection (**F-12**), and renders results through `render_template_string`, a template injection (**F-13**); note bodies render with `\|safe`, enabling stored XSS (**F-14**). *Mitigation:* check `owner == current_user()` on `nid`; parameterize the search; escape note output (drop `\|safe`). |
| **Admin Panel process** — `/admin` | – | – | ✓ | ✓ | – | ✓ | **Full credential dump to anyone holding an admin session.** `/admin` returns every user's username, role, and password hash as JSON; reaching it is role-gated but the gate is defeated by F-04/F-05, and the dump is not logged (**F-08**). *Mitigation:* never return password hashes; enforce real role-based access control; write an audit log of admin access (counters the R gap). |
| **Export process → OS shell** — `/export` | – | ✓ | – | ✓ | ✓ | ✓ | **OS command injection → remote code execution** (**F-07**). `subprocess.run("echo exporting notes as " + fmt, shell=True)` pastes the client's `fmt` into a shell string, so `fmt=txt;id` runs `id`; any registered user can reach it. *Mitigation:* remove the shell call entirely and build the export in-process; if a command is unavoidable, pass an argument list (no `shell=True`) and allow-list `fmt`. |
| **SQLite DB** — `users`, `notes` (`/tmp/notevault.db`) | – | ✓ | ✓ | ✓ | – | – | **Weak password storage + secrets at rest.** Passwords are unsalted MD5 (**F-01**), crackable in seconds once dumped; a plaintext production secret is stored in an admin note. *Mitigation:* hash with argon2id; never store live secrets as note data; run the DB under a least-privilege account. |
| **SECRET store** — `app.py:23` | ✓ | – | – | ✓ | – | – | **Signing-key disclosure** (**F-05**). The key lives in source, so every reader of the repo holds it and can forge sessions. *Mitigation:* move to an environment variable / secrets manager, keep it out of version control, and set it to a long random value. |

### Top 5 risks, ranked by likelihood × impact

1. **OS command injection in `/export` (RCE)** — *likelihood High × impact Critical.* Any attacker can register an account to obtain a session, then run arbitrary commands on the server as the app user. Worst possible impact, trivially reachable. (**F-07**; made worse by the container running as root, **F-09**)
2. **Hard-coded `SECRET` → session forgery → admin (F-05)** — *High × Critical.* No credentials needed: mint an `HS256` admin token and read `/admin`, which dumps every password hash. Chains into F-01.
3. **SQL injection in `/login` (F-03)** — *High × Critical.* Authentication bypass and blind data extraction from the `users` table with no password; the same flaw recurs in `/search` (F-12).
4. **Mass-assignment admin at registration (F-04)** — *High × High.* An anonymous visitor creates an admin account in one request; independent second path to `/admin`.
5. **Unsalted MD5 password storage (F-01)** — *Medium × High.* Once any of the paths above exposes the `users` table, every real password (`admin123`, `alicepw`) is recovered offline in seconds.

*Notable mentions below the top 5: BOLA on `/api/notes/<id>` (cross-user note read, **F-10**), missing cookie flags (F-06) which upgrade any XSS into session theft, and the `alg:none` allow-list (F-02) which is latent today but one refactor away from full bypass.*

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

### Finding F-07 — OS command injection in `/export` (remote code execution as root)
| Field | Value |
|---|---|
| CWE | CWE-78 (Improper Neutralization of Special Elements used in an OS Command) |
| OWASP 2025 | A03 Injection |
| Severity | Critical |
| Location | `app.py:197-203` (`export()`), `out = subprocess.run("echo exporting notes as " + fmt, shell=True, capture_output=True, text=True)` |
| Reproduction | `fmt` comes straight from the query string and is pasted into a shell command string that runs with `shell=True`, so the shell cannot tell the app's intended command apart from attacker-supplied shell syntax — anything after a `;`, `\|`, `` ` ``, or `$()` in `fmt` executes as a separate command. **Verified** as logged-in user `alice` (an ordinary, non-admin account): `curl -b alice.cookies "http://localhost:8080/export?fmt=txt;id"` returns `uid=0(root) gid=0(root) groups=0(root)` — proving arbitrary command execution, not just a crash. |
| Impact | Any authenticated user, regardless of role, gets full code execution inside the container as **root** (the Dockerfile never drops privileges — see F-09). **Verified chained impact:** `fmt=txt;env\|grep -E 'SECRET\|TEAM'` dumped `APP_SECRET`/`TEAM_SALT` from the process environment (making F-05's hard-coded-secret risk moot — the attacker doesn't even need to read the source, injection hands them every secret directly); `fmt=txt;cat /tmp/notevault.db\|strings\|grep hunter2` read the raw SQLite file and recovered `admin`'s private note ("prod db password is hunter2") without going through any `owner=` check in the app — this single bug defeats every access-control fix made elsewhere in the app, because it reads the database file directly from disk. |
| Evidence | Verified curls above. `uid=0(root)` confirms both the injection and that the process runs as root. Screenshot: `screenshots/findings/F-07-export-rce.png`. |

*Root cause in plain terms: `subprocess.run(string, shell=True)` hands the whole string to `/bin/sh -c`, so user input and shell syntax share the same channel — exactly the command-injection twin of the SQL injection in F-03. Fix: never build a shell string from user input; call `subprocess.run(["echo", "exporting notes as", fmt], shell=False)` (or better, validate `fmt` against an allow-list like `{"txt","csv","json"}` before using it at all), and never pass `shell=True` with any request-derived data.*

### Finding F-08 — `/admin` exposes raw password hashes with no redaction or audit trail
| Field | Value |
|---|---|
| CWE | CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) |
| OWASP 2025 | A01 Broken Access Control / A04 Insecure Design |
| Severity | Medium (role check itself is sound here; the problem is what a legitimate admin session returns) |
| Location | `app.py:186-193` (`admin()`), `rows = con.execute("SELECT id,username,password,role FROM users").fetchall()` then `jsonify([dict(r) for r in rows])` |
| Reproduction | The admin endpoint selects every column, including `password`, and serializes the whole row straight to JSON. **Verified**: logging in as the real `admin` account and requesting `/admin` returns every user's raw MD5 hash in the response body (`alice` → `15da1f78ad7d474862865bab1aab4d51`, `admin` → `0192023a7bbd73250516f069df18b500`). An endpoint whose stated purpose is "list users" has no reason to ever put password material on the wire. |
| Impact | Every admin session — including ones obtained legitimately, via a phished/stolen cookie, or via any of F-02/F-04/F-05's forgery paths — walks away with the full hash table, feeding directly into F-01's offline cracking. This also means the blast radius of *any* future admin-session compromise is far larger than "an attacker can manage users" — it is "an attacker can crack every password in the system." There is also no logging of who dumped the table or when. |
| Evidence | Verified JSON dump above from a genuine `admin`/`admin123` login (not a forged token). Screenshot: `screenshots/findings/F-08-admin-password-dump.png`. |

*Root cause in plain terms: `SELECT *`-style queries and "just serialize the row" handlers leak whatever columns happen to exist, including ones that were never meant to leave the server. Fix: `SELECT id, username, role FROM users` (drop `password` from the query entirely, not just from the output), and add an audit log entry for admin-panel access.*

### Finding F-09 — Dockerfile: runs as root, bakes a secret into the image, ships the whole repo
| Field | Value |
|---|---|
| CWE | CWE-250 (Execution with Unnecessary Privileges) / CWE-798 (Use of Hard-coded Credentials) / CWE-1104 (Use of Unmaintained Third-Party components — unpinned mutable base tag) |
| OWASP 2025 | A05 Security Misconfiguration |
| Severity | High |
| Location | `Dockerfile:1-12` — `FROM python:3.12` (no digest pin), no `USER` instruction, `ENV APP_SECRET=notevault-dev-secret`, `COPY . .`; also `app.py:209`, `app.run(host="0.0.0.0", port=8080, debug=True)` |
| Reproduction | Four stacked issues, each verified against the built image: (1) **No non-root user** — the Dockerfile never creates or switches to one, so `docker image inspect notevault-secure-build-notevault -f '{{.Config.User}}'` prints empty and `docker exec ... whoami` prints `root`; this is exactly the privilege F-07's RCE lands in. (2) **Secret baked into the image layer**, not just present at runtime — `docker history --no-trunc notevault-secure-build-notevault \| grep -i secret` shows `ENV APP_SECRET=notevault-dev-secret` in the image metadata, meaning anyone who merely pulls/receives the image (no running container, no app access at all) recovers the secret. (3) **`COPY . .` with no `.dockerignore`** ships `.git/` (full history), `REPORT.md`, `PLAN.md`, and `screenshots/` into the runtime image — confirmed via `docker exec ... ls -la /app`, which lists `.git` alongside the app code; this needlessly exposes source history and project documents inside the deployed artifact and bloats the image. (4) **Unpinned, mutable base tag** `python:3.12` — the same tag resolves to a different image over time, so builds are not reproducible and a compromised/retagged upstream image would be pulled silently. As a related runtime misconfiguration, `app.py:209` also starts Flask with `debug=True`, which enables the Werkzeug interactive debugger (confirmed reachable at `GET /console`) and leaks stack traces with source and local variables on any unhandled error. |
| Impact | (1) turns *any* code-execution bug (F-07) into a full root compromise of the container instead of a limited one. (2) means the signing secret (F-05) leaks from the image itself, independent of the application ever running or being reachable — e.g. to anyone with registry/CI access. (3) leaks the project's git history and internal documents to anyone with the image. (4) undermines build reproducibility and supply-chain integrity (the SBOM in §6 is only meaningful if the base image is pinned). The debug console adds a second, lower-effort path toward the same RCE outcome as F-07. |
| Evidence | All four `docker image inspect` / `docker history` / `docker exec` commands above were run against the image built from this repo's own `Dockerfile` with `TEAM_ID=1234Later`. Screenshot: `screenshots/findings/F-09-dockerfile-root-secret.png`. |

*Root cause in plain terms: the Dockerfile trusts its build context and base image completely and never narrows the container's privileges afterward — it copies everything, keeps root, and never pins what "the latest `python:3.12`" even means. Fix (see §6): add a non-root `USER`, drop the baked `ENV APP_SECRET` (pass secrets at runtime instead, e.g. via `docker compose` `environment:`/a secrets file, never `ENV` in the image), add a `.dockerignore` (`.git`, `*.md`, `screenshots/`), pin the base image by digest, and set `debug=False` for any non-dev run.*

### Finding F-10 — Any user can read any note by id (BOLA / IDOR)
| Field | Value |
|---|---|
| CWE | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| OWASP 2025 | A01 Broken Access Control (OWASP API Top 10: API1 Broken Object Level Authorization) |
| Severity | High |
| Location | `app.py` `api_note()`, `SELECT id,owner,title,body FROM notes WHERE id = ?` (no owner check) |
| Reproduction | `/api/notes/<id>` checks that *someone* is logged in, but never checks that the note belongs to *them*. Note ids are small sequential integers, so any user can walk them. **Verified:** logged in as the ordinary user `alice`, opening `http://localhost:8080/api/notes/3` returns the admin's note `{"owner":"admin","title":"build-tag","body":"team=1234Later marker=903fd6ff6fce"}`; id 2 returns the admin's `infra` note `prod db password is hunter2`. |
| Impact | Every note in the system is readable by every registered account, including the admin's stored production database password. Since registration is open, the attacker needs nothing but a free account. |
| Evidence | Screenshot: `screenshots/findings/F-10-idor-before.png` (admin's note returned to alice; team marker visible). |

*Root cause in plain terms: authentication ("who are you?") was checked, authorization ("is this yours?") was not. The id in the URL is chosen by the client, so the server must tie every lookup to the logged-in user. Fix: add `AND owner = ?` with the current user to the query.*

### Finding F-11 — Vulnerable and unused third-party dependencies
| Field | Value |
|---|---|
| CWE | CWE-1395 (Dependency on Vulnerable Third-Party Component) / CWE-1104 (Use of Unmaintained Third-Party Components) |
| OWASP 2025 | A03 Software Supply Chain Failures |
| Severity | High (scanner rates one CVE Critical; see the reachability note below) |
| Location | `requirements.txt`: `Flask==2.0.1`, `Werkzeug==2.0.1`, `Jinja2==3.0.1`, `PyJWT==1.7.1`, `requests==2.25.1`, `urllib3==1.26.4` |
| Reproduction | Software-composition scan of the dependency file: `docker run --rm -v "%cd%
equirements.txt:/src/requirements.txt:ro" aquasec/trivy:0.56.2 fs --scanners vuln --severity HIGH,CRITICAL /src` reports **17 known vulnerabilities (1 Critical, 16 High) in 4 of the 6 pinned libraries**. PyJWT 1.7.1 has 6 (including Critical CVE-2026-102268, authentication bypass via improper public-key validation, and CVE-2026-48526, forged-JWT authentication bypass), urllib3 1.26.4 has 8, Werkzeug 2.0.1 has 2 (including CVE-2024-34069, code execution through the debugger) and Flask 2.0.1 has 1 (CVE-2023-30861, session cookie exposure behind a cache). Every pin dates from 2021. |
| Impact | The app inherits every bug in the code it imports, and these libraries handle exactly the security-critical parts of NoteVault: PyJWT verifies every session, and Werkzeug parses every request. **Reachability (checked by reading `app.py`):** not all 17 are exploitable as the app is written today. The app signs tokens with `HS256` only, so the PyJWT public-key/JWK CVEs do not apply yet. They would become live the moment someone switches to RS256 or JWKs, so they are a latent risk. `requests` and `urllib3` are **never imported anywhere in the code**, so their 8 CVEs add risk and scanner noise with no benefit. The Werkzeug multipart-parsing DoS (CVE-2023-25577) *is* reachable through every form POST, and CVE-2024-34069 was reachable while `debug=True` was on (fixed in F-09). |
| Evidence | Trivy output above. Screenshot: `screenshots/findings/F-11-trivy-vulnerable-deps.png`. |

*Root cause in plain terms: the dependencies were pinned once and never revisited, and nothing in the build checked them. Pinning is good, because it makes builds reproducible, but a pin is a promise to keep updating it. Fix: upgrade the libraries the app uses to current releases, remove the ones it doesn't use, and gate the CI on a Trivy scan so this can't quietly drift back (§7).*

### Finding F-12 — SQL injection in `/search`
| Field | Value |
|---|---|
| CWE | CWE-89 (SQL Injection) |
| OWASP 2025 | A03 Injection |
| Severity | High |
| Location | `app.py` `search()`, `q = "SELECT id,title,body FROM notes WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, term)` |
| Reproduction | The same `%s` string-building flaw as F-03, in a second place: the search term is pasted into the SQL text. **Verified:** as `alice`, searching for `' OR 1=1 -- ` (`/search?q=%27%20OR%201%3D1%20--%20`) turns the condition into `... body LIKE '%' OR 1=1 -- %'`, which bypasses the `owner=` filter. The page lists **every user's notes**, including the admin's `infra: prod db password is hunter2` and `build-tag: team=1234Later marker=903fd6ff6fce`. |
| Impact | Cross-user disclosure of all notes. A `UNION SELECT` on the same parameter could also read other tables, such as `users` with its password hashes. A second, independent path to the data F-10 exposes. |
| Evidence | Screenshot: `screenshots/findings/F-12-sqli-search-before.png`. |

*Root cause in plain terms: fixing SQL injection in one function (F-03, `login()`) does not fix it in the others. Every query that touches user input needs the `?` form, and here the `%` wildcards belong in the bound value, not the SQL text.*

### Finding F-13 — Server-side template injection in `/search` (remote code execution)
| Field | Value |
|---|---|
| CWE | CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine) / CWE-94 (Code Injection) |
| OWASP 2025 | A03 Injection |
| Severity | Critical |
| Location | `app.py` `search()`, `render_template_string("<a href=/>back</a><ul>" + "".join("<li>%s: %s</li>" % (r["title"], r["body"]) ...) + "</ul>")` |
| Reproduction | The search page is built by pasting note titles and bodies into a string, and that string is then handed to `render_template_string`, which **executes it as a Jinja2 template**. A note's text therefore runs as template code when it appears in search results. **Verified on the `remediation` build (after F-12's SQLi fix):** as `alice`, add a note with body `zz{{7*7}}` and search `zz`, and the result shows `zz49`. Add `yy{{ cycler.__init__.__globals__.os.popen('id').read() }}` and search `yy`, and it returns `uid=10001(notevault) gid=10001(notevault)`: shell commands run on the server. Semgrep flags this line (`render-template-string`, WARNING). |
| Impact | Any registered user can run arbitrary commands on the server: read the database file, environment variables (including `APP_SECRET`), and anything else the app account can reach. F-09's non-root user limits it to the `notevault` account instead of root, but it is still full code execution in the app. |
| Evidence | Reproduced with the requests above against the running container (`{{7*7}}` gave `49`; `os.popen('id')` gave `uid=10001(notevault)`). Screenshot: `screenshots/findings/F-13-ssti-before.png`. |

*Root cause in plain terms: the template engine was given user data as if it were template code. Templates are code, so data must be passed in as variables, never concatenated into the template string. This is the template-engine twin of SQL injection (F-03/F-12) and command injection (F-07).*

### Finding F-14 — HTML injection in notes (stored XSS)
| Field | Value |
|---|---|
| CWE | CWE-79 (Improper Neutralization of Input During Web Page Generation, stored XSS) |
| OWASP 2025 | A03 Injection |
| Severity | Low (currently self-only; see impact) |
| Location | `app.py` `home()`, notes built as `"<li>#%d <b>%s</b>: %s</li>" % (...)` and printed with `{{ notes_html\|safe }}` in `PAGE` |
| Reproduction | Note titles and bodies are formatted into raw HTML and then marked `\|safe`, which switches off Jinja's auto-escaping, so any HTML in a note is rendered by the browser. **Verified:** as `alice`, a note whose body contains HTML bold tags shows on the home page as bold text (`#5 HTML Test: Security Test`) instead of the literal tags. The same path accepts `<script>` or `<img onerror=…>`. |
| Impact | Script injected into a note runs in the browser of whoever views it. Today notes are only shown to their owner, so this is mostly self-XSS. It becomes a real cross-user attack the moment notes are shared, shown to an admin, or combined with a CSRF that plants a note. F-06's `HttpOnly` already stops such a script from stealing the session cookie. |
| Evidence | Screenshot: `screenshots/findings/F-14-notes-html-injection.png`. |

*Root cause in plain terms: `\|safe` tells the template "trust this HTML", and the HTML was built from user input. Fix: drop `\|safe` and render the notes through the template with auto-escaping.*

---

## 5. Remediation  *(25 pts)*

Per finding: the fix, **before/after** code, and the commit that implements it.

All fixes below were retested against a fresh build of the `remediation` branch (`docker compose up --build` with `TEAM_ID=1234Later` and a random 64-hex-character `APP_SECRET`), replaying the same requests used in §4.

### Fix for F-01 — Unsalted MD5 password storage
```diff
+ from argon2 import PasswordHasher
+ from argon2.exceptions import VerifyMismatchError, InvalidHashError
+ ph = PasswordHasher()
  ...
- [("alice", hashlib.md5(b"alicepw").hexdigest(), "user"),
-  ("admin", hashlib.md5(b"admin123").hexdigest(), "admin")]
+ [("alice", ph.hash("alicepw"), "user"),
+  ("admin", ph.hash("admin123"), "admin")]
  ...
- (username, hashlib.md5(password.encode()).hexdigest(), role))      # register()
+ (username, ph.hash(password), role))
  ...
- row = con.execute("SELECT * FROM users WHERE username = ? AND password = ?",   # login()
-                   (username, hashlib.md5((password or "").encode()).hexdigest())).fetchone()
+ row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
+ try:
+     if not row:
+         raise VerifyMismatchError()
+     ph.verify(row["password"], password or "")
+ except (VerifyMismatchError, InvalidHashError):
+     return "login failed", 401
```
Plus `argon2-cffi==23.1.0` added to `requirements.txt`.
- **Why this fixes it:** MD5 is built to be fast and here had no salt, so one dictionary pass cracked every account at once. argon2id gives each password its own random salt (the same password stored twice produces two different hashes, so precomputed tables are useless) and is deliberately slow and memory-hard, so each guess costs the attacker real time and RAM. Because the hash is salted, login can no longer compare hashes inside the SQL query; it now looks the user up by name and lets `ph.verify()` re-hash the attempt with that row's own salt.
- **Commit:** `677a232`
- **Proof the exploit now fails:** the `users` table now holds `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` values, each with a different salt, instead of the bare MD5 digests `0192023a…`/`15da1f78…` that cracked to `admin123`/`alicepw`. Normal login with the real password still works (302 + session cookie). Before: `screenshots/findings/F-01-crack-md5.png`. After: `screenshots/remediation/F-01-after-argon2id-hash.png`.

### Fix for F-02 — `alg: none` allowed in JWT verification
```diff
- data = jwt.decode(tok, SECRET, algorithms=["HS256", "none"])
+ data = jwt.decode(tok, SECRET, algorithms=["HS256"])
```
- **Why this fixes it:** the server, not the token, now decides which algorithm is acceptable. With only `HS256` on the list, an unsigned token is rejected by the allow-list itself rather than by the library's key-guard happening to catch it, so the design no longer depends on that accident surviving a refactor or a PyJWT upgrade.
- **Commit:** `dea8972`
- **Proof the exploit now fails:** the same forged `alg:none` token for `sub=admin` still returns `403 FORBIDDEN` on `/admin`, now for the right reason. Before: `screenshots/findings/F-02-none-rejected.png`. After: `screenshots/remediation/F-02-after-none-rejected.png`.

### Fix for F-03 — SQL injection in `/login`
```diff
- q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
-     username, hashlib.md5((password or "").encode()).hexdigest())
- row = con.execute(q).fetchone()
+ row = con.execute("SELECT * FROM users WHERE username = ? AND password = ?",
+                   (username, hashlib.md5((password or "").encode()).hexdigest())).fetchone()
```
*(Shown as committed in `ec481a9`; F-01's commit later reworked this query to a username-only lookup plus `ph.verify()`, which keeps the `?` parameter.)*
- **Why this fixes it:** with `%s` the username was pasted into the SQL text, so `'` and `--` in the input changed the shape of the query. With `?` the query and the data travel to SQLite separately; the input is only ever a value, so `admin'--` is just a strange username that matches no row. This is the same pattern `role_of()` already used.
- **Commit:** `ec481a9`
- **Proof the exploit now fails:** `username=admin'--` with a wrong password now returns `401 UNAUTHORIZED` / `login failed` instead of `302` + a session cookie. Before: `screenshots/findings/F-03-sqli-login-bypass.png`. After: `screenshots/remediation/F-03-after-sqli-blocked.png`.

### Fix for F-04 — Mass assignment of `role` at registration
```diff
- role = request.form.get("role") or (request.json or {}).get("role") or "user"
+ role = "user"
```
- **Why this fixes it:** the server no longer reads `role` from the request at all, so there is nothing for the client to tamper with. Every new account starts at the lowest privilege (least privilege); promoting someone to admin has to be a separate, admin-only action, not something a visitor can grant themselves.
- **Commit:** `c388c37`
- **Proof the exploit now fails:** registering `pwned` with `role=admin`, logging in, and requesting `/admin` with that session now returns `forbidden` (it returned the full users dump before). Before: `screenshots/findings/F-04-register-as-admin.png`. After: `screenshots/remediation/F-04-after-register-role-ignored.png`.

### Fix for F-05 — Hard-coded session-signing secret
```diff
# app.py
- SECRET = "notevault-dev-secret"
+ SECRET = os.environ.get("APP_SECRET", "")
+ if len(SECRET) < 32:
+     raise SystemExit("APP_SECRET is missing or shorter than 32 characters - refusing to start")
```
```diff
# docker-compose.yml
+ - APP_SECRET=${APP_SECRET:?set APP_SECRET to a long random value before docker compose up}
```
- **Why this fixes it:** the key is no longer in the source code, so reading the repository no longer hands anyone the ability to mint sessions. It is supplied at run time from the operator's shell (generated with `secrets.token_hex(32)`), and together with F-09's Dockerfile fix it is not in the image either. If the key is missing or too short the app **fails closed** and refuses to start, rather than quietly falling back to a guessable default, which would put the original bug back.
- **Commit:** `c3832a0`
- **Proof the exploit now fails:** the exact token from §4, signed with the old `notevault-dev-secret`, now gets `403 FORBIDDEN` on `/admin` (it returned every user's hash before). Running `docker compose up` without `APP_SECRET` set stops immediately with `required variable APP_SECRET is missing a value`. Before: `screenshots/findings/F-05-forge-token-admin-dump.png`. After: `screenshots/remediation/F-05-after-forged-token-rejected.png`, `screenshots/remediation/F-05-after-no-secret-refuses-start.png`.

### Fix for F-06 — Session cookie without security flags
```diff
- resp.set_cookie("session", tok)
+ resp.set_cookie("session", tok, httponly=True, secure=True, samesite="Lax")
```
- **Why this fixes it:** `HttpOnly` hides the cookie from page JavaScript, so an XSS can no longer read `document.cookie` and send the session to an attacker. It still can't stop injected script from acting inside the victim's open page, so the XSS itself must be fixed separately. `Secure` keeps the cookie off plain-HTTP connections, and `SameSite=Lax` stops other sites' cross-site POSTs from carrying it (CSRF).
- **Commit:** `dea8972` (together with F-02: both are one-line changes in the session code)
- **Proof the exploit now fails:** the login response now reads `Set-Cookie: session=…; Secure; HttpOnly; Path=/; SameSite=Lax` (before: `Path=/` only). Before: `screenshots/findings/F-06-cookie-no-flags.png`. After: `screenshots/remediation/F-06-after-cookie-flags.png`.

### Fix for F-07 — `/export` command injection
```diff
- out = subprocess.run("echo exporting notes as " + fmt, shell=True,
-                      capture_output=True, text=True)
+ ALLOWED_EXPORT_FORMATS = {"txt", "csv", "json"}
+ ...
+ if fmt not in ALLOWED_EXPORT_FORMATS:
+     return "unsupported format", 400
+ out = subprocess.run(["echo", "exporting notes as", fmt],
+                      shell=False, capture_output=True, text=True)
```
- **Why this fixes it:** `shell=True` was handing the whole, attacker-influenced string to `/bin/sh -c`, so shell metacharacters in `fmt` ran as separate commands. Passing an argument list with `shell=False` removes the shell entirely — there is nothing for `;`, `|`, or `` ` `` to be interpreted by. The allow-list check is defense in depth, so even a future refactor back toward a shell call can't reintroduce the bug via `fmt`.
- **Commit:** `821730d`
- **Proof the exploit now fails:** `GET /export?fmt=txt;id` as `alice` now returns `400 unsupported format` instead of `uid=0(root)...`; `GET /export?fmt=csv` still works normally. Before: `screenshots/findings/F-07-export-rce.png`. After: `screenshots/retest/F-07-after-export-blocked.png`.

### Fix for F-08 — `/admin` exposing password hashes
```diff
- rows = con.execute("SELECT id,username,password,role FROM users").fetchall()
+ rows = con.execute("SELECT id,username,role FROM users").fetchall()
```
- **Why this fixes it:** the `password` column is dropped at the SQL level, not filtered out afterward, so the hash never exists in the Python process or the JSON response at all — there is no later code path that could accidentally re-include it.
- **Commit:** `4d5df60`
- **Proof the exploit now fails:** `GET /admin` as the real `admin` account now returns only `id`/`username`/`role` for every user — no `password` field. Before: `screenshots/findings/F-08-admin-password-dump.png`. After: `screenshots/retest/F-08-after-admin-no-hashes.png`.

### Fix for F-09 — Dockerfile hardening (root user, baked secret, bloated image, debug mode)
```diff
- FROM python:3.12
- ENV APP_SECRET=notevault-dev-secret
- WORKDIR /app
- COPY . .
- RUN pip install -r requirements.txt
+ FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
+ WORKDIR /app
+ COPY requirements.txt .
+ RUN pip install --no-cache-dir -r requirements.txt
+ COPY app.py .
+ RUN useradd --no-create-home --uid 10001 notevault && chown -R notevault /app
+ USER notevault
```
```diff
- app.run(host="0.0.0.0", port=8080, debug=True)
+ debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
+ app.run(host="0.0.0.0", port=8080, debug=debug_mode)
```
- **Why this fixes it:** pinning the base image by digest makes builds reproducible and stops a retagged/compromised upstream `python:3.12` from being pulled silently. Dropping `ENV APP_SECRET` means no secret ever lands in an image layer (`docker history` has nothing to show). Copying only `requirements.txt` and `app.py`, instead of `COPY . .`, keeps `.git/`, `REPORT.md`, `PLAN.md`, and `screenshots/` out of the runtime image entirely. Adding a dedicated `notevault` user and `USER notevault` means code execution (e.g. a future F-07-class bug) lands with no root privileges in the container. Making `debug` opt-in removes the Werkzeug interactive debugger/console from the default run.
- **Commit:** `985d677`
- **Proof the exploit now fails:** rebuilt image — `docker exec ... whoami` → `notevault` (was `root`); `docker history ... | grep -i secret` → no match (was `ENV APP_SECRET=...`); `docker exec ... ls -la /app` → only `app.py`, `requirements.txt` (was `.git/`, docs, screenshots too); `GET /console` → `404` (was the Werkzeug debugger page). Before: `screenshots/findings/F-09-dockerfile-root-secret.png`. After: `screenshots/retest/F-09-after-dockerfile-hardened.png`.

### Fix for F-10 — Note ownership check on `/api/notes/<id>`
```diff
- if not current_user():
+ user = current_user()
+ if not user:
      return jsonify(error="auth required"), 401
  con = db()
- r = con.execute("SELECT id,owner,title,body FROM notes WHERE id = ?", (nid,)).fetchone()
+ r = con.execute(
+     "SELECT id,owner,title,body FROM notes WHERE id = ? AND owner = ?",
+     (nid, user)
+ ).fetchone()
```
- **Why this fixes it:** the lookup is now tied to the logged-in user, so a note id that belongs to someone else matches no row. The response is `404 not found` rather than `403`, so the API doesn't even confirm that the other user's note exists.
- **Commit:** `2b85028`
- **Proof the exploit now fails:** as `alice`, `/api/notes/3` (the admin's note) now returns `{"error":"not found"}`, while her own `/api/notes/1` still returns `200`. Before: `screenshots/findings/F-10-idor-before.png`. After: `screenshots/retest/F-10-idor-after.png`.

### Fix for F-11 — Vulnerable and unused dependencies
```diff
- Flask==2.0.1
- Werkzeug==2.0.1
- Jinja2==3.0.1
- PyJWT==1.7.1
- requests==2.25.1
- urllib3==1.26.4
- argon2-cffi==23.1.0
+ Flask==3.1.3
+ Werkzeug==3.1.9
+ Jinja2==3.1.6
+ PyJWT==2.15.1
+ argon2-cffi==25.1.0
```
- **Why this fixes it:** the four libraries the app actually imports (Flask, Werkzeug, Jinja2, PyJWT) plus argon2-cffi from F-01 are moved to their current releases, which contain the fixes for all 17 CVEs. `requests` and `urllib3` are removed outright: nothing in `app.py` imports them, so deleting them removes 8 CVEs and their whole attack surface without changing any behavior. The versions stay pinned exactly (`==`), so builds remain reproducible and the SBOM in §6 lists precisely what ships. No code changes were needed. PyJWT 2.x returns `str` from `jwt.encode()` and requires `algorithms=` on `decode()`, which F-02's fix already passes.
- **Commit:** `e58e342`
- **Proof the exploit now fails:** the same Trivy scan now reports **0 High/Critical** (exit code 0 with `--exit-code 1`), down from 17. Regression check on the rebuilt image: alice logs in, adds and searches notes, exports, reads her own note via the API (`200`) and not someone else's (`404`). The F-02/F-03/F-05 attacks still fail (`403`/`401`/`403`), so the upgrade did not undo any earlier fix. Before: `screenshots/findings/F-11-trivy-vulnerable-deps.png`. After: `screenshots/remediation/F-11-after-trivy-clean.png`.

### Fix for F-12 — Parameterized `/search` query
```diff
- q = "SELECT id,title,body FROM notes WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, term)
- rows = con.execute(q).fetchall()
+ q = """
+     SELECT id, title, body
+     FROM notes
+     WHERE owner = ?
+     AND body LIKE ?
+ """
+ rows = con.execute(q, (user, f"%{term}%")).fetchall()
```
- **Why this fixes it:** both the owner and the search term are bound as `?` values. The `%` wildcards are added to the *value*, so a `'` in the term is just a character to search for. It can't close the string or add `OR 1=1`.
- **Commit:** `2b85028` (same commit as F-10)
- **Proof the exploit now fails:** the same `' OR 1=1 -- ` search now returns an empty list instead of every user's notes. Before: `screenshots/findings/F-12-sqli-search-before.png`. After: `screenshots/retest/F-12-sqli-search-after.png`.

### Fix for F-13 — Search results rendered from a fixed template
```diff
+ SEARCH_PAGE = """<a href=/>back</a><ul>{% for r in rows %}<li>{{ r.title }}: {{ r.body }}</li>{% endfor %}</ul>"""
  ...
- return render_template_string(
-     "<a href=/>back</a><ul>" +
-     "".join("<li>%s: %s</li>" % (r["title"], r["body"]) for r in rows) +
-     "</ul>"
- )
+ return render_template_string(SEARCH_PAGE, rows=rows)
```
- **Why this fixes it:** the template is now a constant written by us, and the search results are passed in as the `rows` variable. Note text is never part of the template source, so Jinja only ever *prints* it. A `{{ ... }}` inside a note is shown literally instead of being evaluated, and auto-escaping turns any `<`/`>` into `&lt;`/`&gt;`. Templates are code and notes are data, and the fix keeps those two channels apart, which is the same idea as `?` parameters for SQL (F-03/F-12) and an argument list for the shell (F-07).
- **Commit:** `1644400`
- **Proof the exploit now fails:** the same `zz{{7*7}}` note now comes back from `/search?q=zz` as the literal text `zz{{7*7}}` (before: `zz49`). The `os.popen('id')` payload is printed as text, and no command runs. Normal searches (`milk`) still work, and the F-12 `' OR 1=1 -- ` search still returns nothing. Before: `screenshots/findings/F-13-ssti-before.png`. After: `screenshots/remediation/F-13-after-ssti-blocked.png`.

### Fix for F-14 — Notes escaped on the home page
```diff
- <h3>Your notes</h3>{{ notes_html|safe }}
+ <h3>Your notes</h3>{% for n in notes %}<li>#{{ n.id }} <b>{{ n.title }}</b>: {{ n.body }}</li>{% endfor %}
  ...
- notes_html = "".join(
-     "<li>#%d <b>%s</b>: %s</li>" % (r["id"], r["title"], r["body"]) for r in rows)
- return render_template_string(PAGE, ..., notes_html=notes_html)
+ return render_template_string(PAGE, ..., notes=rows)
```
- **Why this fixes it:** the notes are no longer pre-built into an HTML string and marked `|safe`. The rows go to the template, which auto-escapes every title and body. Only the `<li>`/`<b>` tags written in our template are real HTML. Anything a user types is text.
- **Commit:** `1644400` (same commit as F-13)
- **Proof the exploit now fails:** a note with body `<script>alert(1)</script>` is shown on the home page as the literal text `<script>alert(1)</script>`, and no script runs (no alert). Before: `screenshots/findings/F-14-notes-html-injection.png` (HTML tags rendered as bold). After: `screenshots/remediation/F-14-after-html-escaped.png`.

---

## 6. Supply-Chain Hardening  *(15 pts)*

### SBOM (CycloneDX)
- **Tool:** Syft (`anchore/syft`) on the hardened image `notevault:fixed` (built with `TEAM_ID=1234Later`).
- **Command:** `syft notevault:fixed -o cyclonedx-json > supply-chain/sbom.json`
- **File:** `supply-chain/sbom.json` — CycloneDX 1.7, 2801 components: 100 libraries (OS packages + Python packages such as `flask@2.0.1`), 7 applications, 1 operating-system, 2693 file entries. SHA-256: `be45026336288c396d652fb815192f3610b41765cb48b7a7b698aaf6e957bdc7`.
- **Screenshot:** `screenshots/supply-chain/F-06-sbom-cyclonedx.png` (real terminal capture; shows `TEAM_ID=1234Later`, user, Bangkok timestamp).

### Signing and verification (Cosign)
- Image pushed to a local registry, then signed **by digest** (a tag can be moved; a digest cannot):
  `cosign sign --key supply-chain/cosign.key localhost:5000/notevault@sha256:d2e2cd7d32b8175ccc77fe4a8854cae0063149142250c2dc642274c3335b802e`
- Verified with the public key `supply-chain/cosign.pub`:
  `cosign verify --key supply-chain/cosign.pub <same digest>`
- Output (full text in `supply-chain/cosign-verify.txt`):
  ```
  The following checks were performed on each of these signatures:
    - The cosign claims were validated
    - The signatures were verified against the specified public key
  [{"critical":{"identity":{"docker-reference":"localhost:5000/notevault@sha256:d2e2cd7d..."},"image":{"docker-manifest-digest":"sha256:d2e2cd7d32b8175ccc77fe4a8854cae0063149142250c2dc642274c3335b802e"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
  ```
- **Screenshot:** `screenshots/supply-chain/F-06-cosign-verify.png` (real terminal capture with `TEAM_ID=1234Later`).
- The private key is git-ignored. Rekor transparency log was skipped (local registry, key-based signing); keyless signing would need a public registry and OIDC identity.

### SLSA self-assessment
**SLSA Build L1.** The build is scripted (`Dockerfile`, base image pinned by digest) and produces provenance-like evidence (SBOM + signature over the exact digest). It is not L2: the image was built on a team laptop, not a hosted build service, and no signed provenance attestation is generated. Next step: build in GitHub Actions and attach a provenance attestation.

---

## 7. Security CI Pipeline  *(10 pts)*
**Workflow:** [`.github/workflows/security-ci.yml`](https://github.com/team-1234later/notevault-secure-build/blob/main/.github/workflows/security-ci.yml). It runs on every push and pull request to `main` and on manual dispatch.

### What it scans

| Job | Tool | Type | What it looks at |
|---|---|---|---|
| SAST (Semgrep) | Semgrep `1.184.0`, rulesets `p/default` + `p/owasp-top-ten` | Static analysis | Insecure patterns in our source (`app.py`, the Dockerfile, the workflow itself) |
| SCA + IaC (Trivy) | `trivy-action` v0.36.0 | Dependency + secret + config scan | Known CVEs in `requirements.txt`, secrets in the tree, misconfigurations in the `Dockerfile` |
| Secrets (Gitleaks) | Gitleaks `v8.30.1` | Secret scanning | The whole repository **and its full git history** (`fetch-depth: 0`), so a secret that was committed and later deleted is still caught |

### How the gate is configured (what fails the build)
Each job follows **report, then gate**. First the scanner runs in report mode (`exit-code 0` / `|| true`) and its full results are kept as a downloadable build artifact (`semgrep-report`, `trivy-reports`, `gitleaks-report`) by a step marked `if: always()`, so reviewers can read the findings even when the build is red. Then a separate gate step re-runs the scan with failing semantics:

| Gate | Fails the build when |
|---|---|
| Semgrep | any finding of **ERROR** severity (`--severity ERROR --error`) |
| Trivy SCA | any **HIGH or CRITICAL** vulnerability or secret (`exit-code: "1"`, `ignore-unfixed: false`) |
| Trivy IaC | any **HIGH or CRITICAL** Dockerfile/config misconfiguration |
| Gitleaks | **any** secret, at any point in history (`--exit-code 1`) |

The pipeline is hardened like any other piece of the supply chain. The token is least-privilege (`permissions: contents: read`, since nothing in the workflow writes). Every action is pinned to a full commit SHA and every container image to an exact version, so a moved tag can't change what runs. This was not hypothetical: the first version of this workflow referenced `aquasecurity/trivy-action@0.24.0`, a tag that has since been deleted upstream, and the Trivy job could not even start. Semgrep also flagged 11 mutable action tags in the workflow itself; after pinning, it reports none. Because this repository is private without GitHub Advanced Security, SARIF upload to the Security tab is unavailable, so reports are kept as artifacts instead.

### The build failing on a real finding, then passing
1. **Red.** We pushed the working pipeline to `remediation` *before* the F-11 dependency upgrade and opened a pull request to `main`. Semgrep and Gitleaks passed. The **Trivy SCA gate failed on the 17 HIGH/CRITICAL CVEs in the old pins** (PyJWT 1.7.1, urllib3 1.26.4, Werkzeug 2.0.1, Flask 2.0.1), so the build blocked the merge for the right reason. Screenshot: `screenshots/CI/ci-fail-trivy.png`.
2. **Green.** We then pushed the F-11 commit to the same pull request. The re-run passed all three jobs, and the PR could merge. Screenshot: `screenshots/CI/ci-pass.png`.

### What the gate does not catch (and why we chose this threshold)
Semgrep reports six WARNING-level findings in `app.py` that do not block the build. Two of them point at real bugs: `render-template-string` at the `/search` handler, which is the template injection described in §8, and `raw-html-format` in `/export`. We set the Semgrep gate at ERROR so the build lines up with the HIGH/CRITICAL policy used for the other scanners and doesn't block every push on style-level warnings. The cost is that F-13, the template injection that gave remote code execution, passed the gate until we fixed it by hand. That is a real limitation: a severity threshold is only as good as the rule's own severity label, so the WARNING report still needs a human reading it. A next step would be a small custom Semgrep rule at ERROR severity for `render_template_string` called on anything but a constant, which would have blocked it.

---

## 8. Conclusion & Reflection  *(5 pts — clarity)*
### Residual risks and what we would harden next

1. **Template and HTML injection (F-13, F-14), fixed late.** Both were found while compiling this report, after the other fixes were in, and both are now fixed (§5). They are a reminder that a fix in one place (`?` parameters in SQL) doesn't protect the same mistake elsewhere: anywhere user data meets an interpreter (SQL, shell, template engine, browser) needs the same separation of code and data. A code review checklist entry for `render_template_string`, `|safe` and `shell=True` would have caught all three.
2. **Semgrep gate threshold.** Our CI gate blocks only ERROR-severity Semgrep findings (§7), and F-13 was rated WARNING. *Next:* add a custom ERROR rule for `render_template_string` with non-constant input.
3. **Sessions never expire and logout does not revoke them.** The JWT has no `exp` claim and `/logout` only deletes the browser's copy, so a stolen token works forever. *Fix:* add a short `exp`, and keep a server-side deny-list or session id that logout invalidates.
4. **No brute-force protection on `/login`.** argon2id makes offline cracking slow, but online guessing is unlimited. *Fix:* rate-limit by account and IP, and lock out after repeated failures.
5. **Usernames are not unique.** `register()` accepted `pwned` three times during our retest (three rows in the `users` table). *Fix:* add a `UNIQUE` constraint on `username` and handle the error.
6. **Dependencies will go stale again.** F-11 brought every library to a clean scan today, but new CVEs are published every week. The CI Trivy gate (§7) catches them on each push, and a scheduled weekly scan plus Dependabot would catch them between pushes.
7. **No audit logging** of logins, failed logins or admin-panel access, so an attack like ours would leave no trail (STRIDE *Repudiation*).

### Lessons learned

1. **Prevention matters, but plan for the day it fails: whatever an attacker gets should be the least privilege possible.** We fixed every bug we found, and we still discovered a new one (the `/search` template injection) while writing this report. It will not be the last. What decided how bad that bug was had nothing to do with the bug itself. It came down to the privileges already in place. Before F-09 the same kind of command execution (F-07) ran as `uid=0(root)`. After F-09, the template injection ran as `uid=10001(notevault)`, an account that owns nothing but the app. The same idea runs through our other fixes: new accounts start as `user` (F-04), `/admin` no longer hands out password hashes (F-08), and even a stolen hash is now slow to crack (F-01). Each layer shrinks what a successful attacker walks away with.
2. **A vulnerability that looks scary is not always the one that works, so test before you rank.** On paper the `alg:none` JWT (F-02) and the login SQL injection (F-03) looked like the worst bugs. When we actually ran them, F-02 was blocked by the library and F-03 logged in as a fake user with no admin role. The quiet-looking ones, a form field the backend didn't ignore (F-04) and a string constant in the source (F-05), were the ones that made us admin. Only trying each attack against the running app showed us which risks were real, and that is what our severity ratings are based on.


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
