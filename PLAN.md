# Term Project Plan — Team 1234Later

**App:** NoteVault · **Due:** Fri 6 Nov 2026, 16:59 (team target: submit by noon)
**Submit to:** report PDF + video link → `learn.zcr.ai/submit` · code, SBOM, signatures and CI live in this repo

> When a task is done, change `[ ]` to `[x]` in this file and commit from your own account.

## Everyone does these 5 steps for their own vulnerabilities

1. **Find** — attack the part you own.
2. **Document** — CWE, OWASP, severity, reproduction, impact, screenshot → `REPORT.md` §4.
3. **Fix** — commit yourself on branch `remediation`, e.g. `Fix F-03: parameterize search query`.
4. **Retest** — repeat the same attack to show it now fails; before/after screenshots → §5.
5. **Explain** — record your own clip: attack → root cause → fix.

## Roles

| | Find + fix vulnerabilities in | Infrastructure work | Report sections |
|---|---|---|---|
| **A** Sorrawit | `/register` `/login` `/logout`, cookie, passwords (F-01) | Threat model + compile report | Cover, §1, §3, §8 |
| **B** ____ | `/notes` `/api/notes/<id>` `/search` | CI pipeline + compile demo video | §7 |
| **C** Sutapat | `/admin` `/export` `Dockerfile` | SBOM + Cosign | §6 |
| **D** ____ | `requirements.txt` (Trivy) | §2 + collect AI disclosure | §2, AI disclosure |

## Daily checklist

### Fri 30 Oct
- [ ] Everyone: clone repo, `set TEAM_ID=1234Later`, `docker compose up` works (A / B / C / D)

### Sat 31 Oct
- [ ] A: DFD + STRIDE shared with the team

### Sun 1 Nov
- [ ] A: login/session/password findings in §4
- [ ] B: notes/api/search findings in §4
- [x] C: admin/export/Dockerfile findings in §4
- [ ] D: findings from the Trivy scan of `requirements.txt` in §4
- [ ] D: write §2 System Scope
- [ ] B: push `.github/workflows/security-ci.yml` (should fail — capture screenshot)

### Mon 2 Nov
- [ ] A: commit fixes on `remediation`
- [ ] B: commit fixes on `remediation`
- [x] C: commit fixes on `remediation` (committed on branch Wicked-Blues)
- [ ] D: upgrade library versions and commit on `remediation`

### Tue 3 Nov
- [ ] A / B / C / D: retest, capture before/after screenshots in §5
- [ ] B: CI passes (green) — capture screenshot
- [x] C: fix Dockerfile, build SBOM (CycloneDX), sign the fixed image with Cosign

### Wed 4 Nov
- [ ] B: write §7
- [x] C: write §6
- [ ] D: collect everyone's AI disclosure
- [ ] Everyone: write the script for your own video part
- [ ] A: write Cover, §1, §8 and compile the report into one document

### Thu 5 Nov
- [ ] Everyone: record your own video clip
- [ ] B: combine clips, upload as an unlisted link, check that others can open it
- [ ] A: put the video link on the cover, export PDF

### Fri 6 Nov
- [ ] A: submit the PDF at `learn.zcr.ai/submit` before noon
- [ ] Everyone: fill in the peer evaluation

## Team rules

- **Commit your own work from your own account** — the instructor uses commit history to see who did what.
- **Every screenshot must show our `TEAM_ID`.**
- **Running late?** Tell the group first, then log in the notes table below who took over.
- **Everyone must be able to explain their own work** — the instructor may ask live.

## Notes / handovers

| Date | Task | Original owner | Taken over by | Reason |
|---|---|---|---|---|
| | | | | |
