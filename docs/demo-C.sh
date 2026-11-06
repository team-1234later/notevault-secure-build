#!/bin/bash
# Live demo for section C: F-07 /export, F-08 /admin, F-09 Dockerfile, SBOM + Cosign.
# Usage: bash docs/demo-C.sh setup    (once, before recording)
#        bash docs/demo-C.sh          (the demo; press Enter between steps)
#        DEMO_AUTO=1 bash docs/demo-C.sh   (no pauses, for a dry run)
#        bash docs/demo-C.sh clean    (remove demo containers)
export TEAM_ID=1234Later
cd "$(dirname "$0")/.." || exit 1
DIG=localhost:5000/notevault@sha256:d2e2cd7d32b8175ccc77fe4a8854cae0063149142250c2dc642274c3335b802e

pause(){ [ -n "$DEMO_AUTO" ] || read -rp "   [Enter] " _; echo; }
step(){ echo; echo "=== $1 ==="; }
run(){ echo "\$ $*"; eval "$@"; echo; }

if [ "$1" = clean ]; then docker rm -f nv-vuln nv-fixed >/dev/null 2>&1; echo cleaned; exit; fi

if [ "$1" = setup ]; then
  tmp=$(mktemp -d); git archive 6fe6f2e | tar -x -C "$tmp"
  docker build -q -t notevault:vulnerable "$tmp" && docker build -q -t notevault:fixed .
  docker rm -f nv-vuln nv-fixed >/dev/null 2>&1
  docker run -d --name nv-vuln  -e TEAM_ID=$TEAM_ID -p 8081:8080 notevault:vulnerable >/dev/null
  docker run -d --name nv-fixed -e TEAM_ID=$TEAM_ID -p 8082:8080 notevault:fixed >/dev/null
  docker start reg >/dev/null 2>&1
  sleep 4; echo "ready: vulnerable :8081, fixed :8082"; exit
fi

clear
echo "$(whoami) | 6531503085 | $(TZ=Asia/Bangkok date '+%F %T %z') | TEAM_ID=$TEAM_ID"
echo "Part C: /export, /admin, Dockerfile, SBOM + Cosign"; pause

step "F-07 BEFORE: command injection in /export (vulnerable)"
run "curl -s -o /dev/null -c /tmp/a.j -d 'username=alice&password=alicepw' localhost:8081/login"
run "curl -s -b /tmp/a.j 'localhost:8081/export?fmt=txt;id'"
run "curl -s -b /tmp/a.j 'localhost:8081/export?fmt=txt;env%7Cgrep%20APP_SECRET'"
pause
step "F-07 AFTER: fixed"
run "curl -s -o /dev/null -c /tmp/b.j -d 'username=alice&password=alicepw' localhost:8082/login"
run "curl -s -w ' [HTTP %{http_code}]\n' -b /tmp/b.j 'localhost:8082/export?fmt=txt;id'"
run "curl -s -w ' [HTTP %{http_code}]\n' -b /tmp/b.j 'localhost:8082/export?fmt=csv'"
pause

step "F-08 BEFORE: /admin leaks password hashes (vulnerable)"
run "curl -s -o /dev/null -c /tmp/c.j -d 'username=admin&password=admin123' localhost:8081/login"
run "curl -s -b /tmp/c.j localhost:8081/admin | python3 -m json.tool"
pause
step "F-08 AFTER: fixed"
run "curl -s -o /dev/null -c /tmp/d.j -d 'username=admin&password=admin123' localhost:8082/login"
run "curl -s -b /tmp/d.j localhost:8082/admin"
pause

step "F-09 BEFORE: Dockerfile (vulnerable)"
run "docker exec nv-vuln whoami"
run "docker history --no-trunc --format '{{.CreatedBy}}' notevault:vulnerable | grep -i secret"
run "docker exec nv-vuln ls -a /app"
run "curl -s -o /dev/null -w 'GET /console -> HTTP %{http_code}\n' localhost:8081/console"
pause
step "F-09 AFTER: hardened"
run "docker exec nv-fixed whoami"
run "docker history --no-trunc --format '{{.CreatedBy}}' notevault:fixed | grep -i secret || echo '(no output)'"
run "docker exec nv-fixed ls -a /app"
run "curl -s -o /dev/null -w 'GET /console -> HTTP %{http_code}\n' localhost:8082/console"
run "grep -E '^FROM|^USER' Dockerfile | cut -c1-100"
pause

step "SBOM (CycloneDX) from the fixed image"
run "python3 -I -c \"import json,collections;d=json.load(open('supply-chain/sbom.json'));print(d['bomFormat'],d['specVersion'],'total',len(d['components']),dict(collections.Counter(c['type'] for c in d['components'])))\""
pause
step "Cosign: verify signed image (by digest)"
run "docker run --rm --network host --user \$(id -u):\$(id -g) -e HOME=/tmp -v \$PWD/supply-chain:/w -w /w ghcr.io/sigstore/cosign/cosign:latest verify --key cosign.pub --allow-insecure-registry --insecure-ignore-tlog $DIG 2>&1 | grep -E 'checks|claims|signatures|transparency'"
echo "TEAM_ID=$TEAM_ID  done."
