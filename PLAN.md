# แผนงาน Term Project — ทีม 1234Later

**แอป:** NoteVault · **ส่ง:** ศ. 6 พ.ย. 2026 16:59 (ทีมตั้งเป้าส่งภายในเที่ยงวัน)
**ส่งที่:** รายงาน PDF + ลิงก์วิดีโอ → `learn.zcr.ai/submit` · โค้ด, SBOM, ลายเซ็น และ CI อยู่ใน repo นี้

> ทำงานเสร็จแล้วให้แก้ `[ ]` เป็น `[x]` ในไฟล์นี้ และ commit ด้วยบัญชีของตัวเอง

## ทุกคนทำ 5 ขั้นนี้กับช่องโหว่ของตัวเอง

1. **หา** — ลองเจาะส่วนที่ตัวเองรับผิดชอบ
2. **เขียนรายงาน** — CWE, OWASP, ความรุนแรง, วิธีทำซ้ำ, ผลกระทบ, screenshot ลง `REPORT.md` §4
3. **แก้** — commit เองใน branch `remediation` เช่น `Fix F-03: parameterize search query`
4. **ทดสอบซ้ำ** — เจาะแบบเดิมอีกรอบให้เห็นว่าเข้าไม่ได้ เก็บภาพก่อน/หลัง ลง §5
5. **อธิบาย** — อัดคลิปส่วนของตัวเอง: เจาะ → สาเหตุ → แก้

## หน้าที่

| | ส่วนที่หาช่องโหว่ + แก้ | งานโครงสร้าง | บทในรายงาน |
|---|---|---|---|
| **A** Sorrawit | `/register` `/login` `/logout` cookie, รหัสผ่าน (F-01) | Threat model + รวมรายงาน | Cover, §1, §3, §8 |
| **B** ____ | `/notes` `/api/notes/<id>` `/search` | CI pipeline + รวมคลิปวิดีโอ | §7 |
| **C** Sutapat | `/admin` `/export` `Dockerfile` | SBOM + Cosign | §6 |
| **D** ____ | `requirements.txt` (Trivy) | §2 + รวบรวม AI disclosure | §2, AI disclosure |

## Checklist รายวัน

### ศ. 30 ต.ค.
- [ ] ทุกคน: clone repo, `set TEAM_ID=1234Later`, `docker compose up` รันได้ (A / B / C / D)

### ส. 31 ต.ค.
- [ ] A: DFD + STRIDE ส่งให้ทีมดู

### อา. 1 พ.ย.
- [ ] A: finding ส่วน login/session/รหัสผ่าน ลง §4
- [ ] B: finding ส่วน notes/api/search ลง §4
- [ ] C: finding ส่วน admin/export/Dockerfile ลง §4
- [ ] D: finding จาก Trivy สแกน `requirements.txt` ลง §4
- [ ] D: เขียน §2 System Scope
- [ ] B: push `.github/workflows/security-ci.yml` (ควรล้ม — capture ภาพ)

### จ. 2 พ.ย.
- [ ] A: commit fix ใน `remediation`
- [ ] B: commit fix ใน `remediation`
- [ ] C: commit fix ใน `remediation`
- [ ] D: อัปเวอร์ชัน library แล้ว commit ใน `remediation`

### อ. 3 พ.ย.
- [ ] A / B / C / D: ทดสอบซ้ำ เก็บภาพก่อน/หลัง ลง §5
- [ ] B: CI ผ่าน (สีเขียว) — capture ภาพ
- [x] C: แก้ Dockerfile, ทำ SBOM (CycloneDX), เซ็น image ที่แก้แล้วด้วย Cosign

### พ. 4 พ.ย.
- [ ] B: เขียน §7
- [ ] C: เขียน §6
- [ ] D: รวบรวม AI disclosure ของทุกคน
- [ ] ทุกคน: เขียนบทพูดส่วนของตัวเอง
- [ ] A: เขียน Cover, §1, §8 แล้วรวมรายงานเป็นเล่มเดียว

### พฤ. 5 พ.ย.
- [ ] ทุกคน: อัดคลิปส่วนของตัวเอง
- [ ] B: รวมคลิป อัปเป็นลิงก์ unlisted แล้วเช็กว่าคนอื่นเปิดได้
- [ ] A: ใส่ลิงก์วิดีโอในหน้าปก แล้ว export PDF

### ศ. 6 พ.ย.
- [ ] A: ส่ง PDF ที่ `learn.zcr.ai/submit` ภายในเที่ยงวัน
- [ ] ทุกคน: ทำแบบประเมินเพื่อนร่วมทีม

## กติกาของทีม

- **commit งานของตัวเองจากบัญชีตัวเอง** อาจารย์ใช้ประวัติ commit ดูว่าใครทำอะไร
- **ทุก screenshot ต้องเห็นรหัส TEAM_ID ของทีมเรา**
- **งานเลยกำหนด** ให้บอกในกลุ่มก่อน แล้วจดไว้ในหมายเหตุข้างล่างว่าใครรับไปทำแทน
- **ทุกคนต้องอธิบายงานของตัวเองได้** อาจารย์อาจเรียกถามสด

## หมายเหตุ / งานที่เปลี่ยนมือ

| วันที่ | งาน | เดิม | ทำแทนโดย | เหตุผล |
|---|---|---|---|---|
| | | | | |
