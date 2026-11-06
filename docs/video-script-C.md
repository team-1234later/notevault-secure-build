# Video Script — C (Sutapat) · target length ~3 minutes

Part C: `/export` (F-07), `/admin` (F-08), `Dockerfile` (F-09), SBOM + Cosign (§6)
Before recording: `export TEAM_ID=1234Later` in the terminal and keep `TEAM_ID` visible in every scene.
Live demo: `bash docs/demo-C.sh` (see the header of that file for setup).

---

## 0. Introduction (~10 s)
**[Screen: terminal showing TEAM_ID]**
> "Hello, I'm Sutapat (C) from team 1234Later. I'm responsible for three areas: the `/export` endpoint, the `/admin` endpoint and the `Dockerfile`, plus the SBOM and signing the image with Cosign."

## 1. F-07 — Command injection in `/export` (~50 s)
**[Screen: `screenshots/findings/F-07-export-rce.png` or run curl live]**
- **Attack:** "I log in as alice, an ordinary user, and call `/export?fmt=txt;id`. The response shows `uid=0(root)`, so I can run any command as root."
- **Root cause:** "The code pastes `fmt` from the query string into a string and runs it with `subprocess.run(..., shell=True)`. The shell cannot tell the app's command from the attacker's input, so `;` starts a second command. This is CWE-78, severity Critical."
- **Fix:** "I removed `shell=True` and pass the arguments as a list, and added an allow-list so only txt, csv and json are accepted."
- **Retest:** **[Screen: retest]** "The same attack with `fmt=txt;id` now returns `400 unsupported format`, while `fmt=csv` still works normally."

## 2. F-08 — `/admin` exposes password hashes (~35 s)
**[Screen: `F-08-admin-password-dump.png`]**
- **Attack:** "I log in as the real admin and call `/admin`. The response contains every user's MD5 password hash."
- **Root cause:** "The query selects the `password` column and the handler serializes the whole row to JSON, even though this endpoint only needs to list users. If an admin session ever leaks, the attacker can crack every password offline. This is CWE-200."
- **Fix:** "I changed the query to `SELECT id, username, role`, so the password column is dropped at the SQL level."
- **Retest:** **[Screen: retest]** "The response now contains only id, username and role."

## 3. F-09 — Dockerfile (~45 s)
**[Screen: `F-09-dockerfile-root-secret.png`, then cut to the new Dockerfile]**
- **Attack:** "`docker exec ... whoami` returns root, and `docker history | grep -i secret` finds `APP_SECRET` baked into the image."
- **Root cause:** "The Dockerfile has no `USER`, bakes a secret in with `ENV`, copies the whole repo with `COPY . .`, and uses a base image tag that can change. That turns the F-07 bug into full root access. CWE-250 and CWE-798."
- **Fix:** "I create a non-root user `notevault`, remove the secret from the image, copy only `app.py` and the requirements, pin the base image by digest and turn debug mode off."
- **Retest:** **[Screen: retest]** "`whoami` now returns `notevault`, `docker history` shows no secret, and `/console` returns 404."

## 4. SBOM + Cosign (~45 s)
**[Screen: `screenshots/supply-chain/F-06-sbom-cyclonedx.png`]**
> "After the fixes I rebuilt the image and generated a CycloneDX SBOM with Syft. It lists 2,795 components, 100 of them libraries, including the upgraded Flask 3.1.3, and no longer contains the unused requests and urllib3. If a new vulnerability is published, we immediately know which packages our image contains."

**[Screen: `F-06-cosign-verify.png`]**
> "Then I signed the image with Cosign by digest, not by tag, because a tag can be moved but a digest cannot. Verifying with the public key succeeds: the claims are validated and the signature matches the key."

> "My SLSA self-assessment is Build L1. The build is scripted and we have SBOM and signature evidence, but it is not L2 because the image was built on our own machine rather than a hosted build service, and there is no signed provenance yet."

## 5. Closing (~10 s)
> "To summarize: three vulnerabilities fixed and proven by retesting, and the fixed image is backed by an SBOM and a signature. Thank you."

---

## Prepare for live questions
- **Why an allow-list when `shell=False` already fixes it?** Defense in depth. If someone later goes back to a shell call, `fmt` is still restricted.
- **Why drop the password column in SQL instead of at output?** The data never enters the Python process, so no other code path can leak it.
- **Why sign by digest?** A tag can point to a different image later; a digest is bound to the exact content.
- **Why not keyless signing?** We use a local registry with no public identity, so we used a key pair and skipped the Rekor transparency log.
- **What are the 2,687 file entries in the SBOM?** Syft also lists files in the image. The real packages are the 100 libraries.
