# Read-aloud script — C (Sutapat) · ~3 minutes

Matches `bash docs/demo-C.sh` step by step. **[ENTER]** = press Enter in the demo terminal at that moment.
Start recording with the demo terminal open and `TEAM_ID=1234Later` visible on the first line.

---

**Intro** *(demo header on screen)*

Hello, I'm Sutapat, member C of team 1234Later. My part covers three areas of NoteVault: the export endpoint, the admin endpoint and the Dockerfile. I also built the SBOM and signed the final image with Cosign. **[ENTER]**

---

**F-07, command injection in /export, before the fix**

First, the vulnerable version. I log in as alice, an ordinary user, and call export with `fmt` equal to `txt;id`. The server answers with `uid=0(root)`, so any logged-in user can run commands as root. I can even read the application secret from the environment. **[ENTER]**

The cause is that the code pastes `fmt` into a shell string and runs it with `shell=True`. The shell cannot tell the app's command from the attacker's input, so the semicolon starts a second command. This is CWE-78 and I rated it Critical.

**After the fix** *(F-07 AFTER on screen)*

I removed `shell=True`, pass the arguments as a list, and added an allow-list that accepts only txt, csv and json. The same attack now returns 400 unsupported format, and a normal csv export still works with status 200. **[ENTER]**

---

**F-08, /admin leaks password hashes, before**

Next, the admin endpoint. I log in as the real admin and call `/admin`. The response contains every user's MD5 password hash. The query selects the password column and the handler returns the whole row, although this page only needs to list users. If an admin session ever leaks, every password can be cracked offline. This is CWE-200. **[ENTER]**

**After the fix**

I changed the query to select only id, username and role, so the hash is dropped at the SQL level and never reaches the response. The output now shows no password field. **[ENTER]**

---

**F-09, Dockerfile, before**

Third, the Dockerfile. In the vulnerable image, `whoami` returns root, and `docker history` shows the application secret baked into the image. The image also contains the whole repository, and the debug console answers with HTTP 200. That turns the F-07 bug into full root access. These are CWE-250 and CWE-798. **[ENTER]**

**After the fix**

The hardened image runs as the non-root user `notevault`, the history contains no secret, only `app.py` and the requirements file are copied in, the base image is pinned by digest, and the console now returns 404. **[ENTER]**

---

**SBOM**

After all fixes were merged, I rebuilt the image and generated a CycloneDX SBOM with Syft. It lists 2,795 components, 100 of them libraries, including the upgraded Flask 3.1.3. The unused requests and urllib3 packages are gone. If a new vulnerability is published, we can see at once whether our image contains the affected package. **[ENTER]**

**Cosign**

Finally, I signed the image with Cosign by digest, not by tag, because a tag can be moved but a digest cannot. Verification with the public key succeeds: the claims are validated and the signature matches the key. For SLSA, I assess us at Build level 1, because the build is scripted and has SBOM and signature evidence, but it ran on our own machine and has no signed provenance yet.

**Closing**

In summary, three vulnerabilities were fixed and proven by retesting, and the final image is backed by an SBOM and a signature. Thank you.

---

### Delivery tips
- Pause one second after each **[ENTER]** so the output is readable before you speak.
- Say "F-07", "F-08", "F-09" clearly so the grader can match them to the report.
- If you stumble, keep going; trim it when you edit.
