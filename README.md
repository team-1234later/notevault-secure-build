# NoteVault — Term Project (Team 1234Later)

A small team note-sharing web app + JSON API, used as our term-project target.
It looks like a normal app and works end-to-end — but it was built quickly,
without a security review. Our job is to find, document, and fix its weaknesses.

> ⚠️ Sandbox only. Run it locally; never deploy this as-is.

- **Team:** 1234Later · **`TEAM_ID`:** `1234Later`
- **Deadline:** Fri 6 Nov 2026, 16:59 (team target: submit by noon)
- **Submit:** report PDF + video link → `learn.zcr.ai/submit`
- **In this repo:** code, fixes (branch `remediation`), SBOM, signatures, and CI
- **Plan & daily checklist:** [PLAN.md](PLAN.md) · **Report:** [REPORT.md](REPORT.md)

## What it does
- Register / log in (cookie session)
- Create and view your own notes
- Search your notes
- Admin panel listing users
- "Export" convenience endpoint

## Run it
```bash
# Windows (cmd):   set TEAM_ID=1234Later
# PowerShell:      $env:TEAM_ID="1234Later"
export TEAM_ID=1234Later   # bash
docker compose up          # http://localhost:8080
# seeded logins:  alice / alicepw   ·   admin / admin123
```
Local (no Docker): `pip install -r requirements.txt`, then run `python app.py` with `TEAM_ID=1234Later` set.

> **Set `TEAM_ID` before your first build.** It seeds a small marker derived from the team
> name into the app's own data. It doesn't change app behavior; it exists so our evidence
> (screenshots, dumped data, git history) is provably ours. **Every screenshot must show
> our `TEAM_ID`.**

## Roles

| | Find + fix vulnerabilities in | Infrastructure work | Report sections |
|---|---|---|---|
| **A** Sorrawit | `/register` `/login` `/logout`, cookie, passwords (F-01) | Threat model + compile report | Cover, §1, §3, §8 |
| **B** ____ | `/notes` `/api/notes/<id>` `/search` | CI pipeline + compile demo video | §7 |
| **C** Sutapat | `/admin` `/export` `Dockerfile` | SBOM + Cosign | §6 |
| **D** ____ | `requirements.txt` (Trivy) | §2 + collect AI disclosure | §2, AI disclosure |

## Workflow — each member, for their own findings
1. **Find** — attack the part you own.
2. **Document** — CWE, OWASP, severity, reproduction, impact, screenshot → `REPORT.md` §4.
3. **Fix** — commit yourself on branch `remediation`, e.g. `Fix F-03: parameterize search query`.
4. **Retest** — repeat the same attack to show it now fails; before/after screenshots → §5.
5. **Explain** — record your own clip: attack → root cause → fix.

## Deliverables (maps to `REPORT.md`)
1. **Threat model** — DFD + STRIDE, trust boundaries, top risks. *(A, §3)*
2. **Findings** — input handling, access control, sessions, crypto, dependencies,
   container/config; each with CWE + OWASP, reproduction, impact, evidence. *(all, §4)*
3. **Remediation + retest** — fixes on `remediation` with clear commits. *(all, §5)*
4. **Supply-chain hardening** — fixed `Dockerfile`, SBOM (CycloneDX), image signed with Cosign. *(C, §6)*
5. **Security CI** — `.github/workflows/security-ci.yml` (SAST + SCA + secret scanning)
   that fails on HIGH/CRITICAL; capture it failing first, then passing. *(B, §7)*
6. **Demo video** — unlisted link on the report cover. *(B compiles, A links)*

## Supply chain (SBOM + signature)
Files live in [`supply-chain/`](supply-chain/); details in [REPORT.md](REPORT.md) §6.
```bash
docker build -t notevault:fixed .
# SBOM (CycloneDX) — Syft
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/syft notevault:fixed -o cyclonedx-json > supply-chain/sbom.json
# Verify the signed image (use the digest from supply-chain/cosign-verify.txt)
cosign verify --key supply-chain/cosign.pub <image@digest>
```
`cosign.key` (private) is git-ignored and is not in this repo.

## Evidence and extras
- [`screenshots/findings/`](screenshots/findings/) — before-fix evidence; [`screenshots/retest/`](screenshots/retest/) — after-fix retests
- [`screenshots/supply-chain/`](screenshots/supply-chain/) — SBOM and Cosign verify captures
- [`docs/`](docs/) — video scripts

## Attack surface to probe
The login, register, note, search, admin, and export endpoints; the session
cookie; `requirements.txt`; and the `Dockerfile`. Use the tools from the weekly
labs (Burp, sqlmap, Trivy, Semgrep, Gitleaks, Cosign).

## Team rules
- **Commit your own work from your own account** — commit history shows who did what.
- **Every screenshot must show our `TEAM_ID`.**
- **Running late?** Tell the group first, then log the handover in the notes table in [PLAN.md](PLAN.md).
- **Everyone must be able to explain their own work** — the instructor may ask live.
- Mark finished tasks `[x]` in [PLAN.md](PLAN.md).
