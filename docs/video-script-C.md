# บทพูดวิดีโอ — C (Sutapat) · ความยาวเป้าหมาย ~3 นาที

ส่วนของ C: `/export` (F-07), `/admin` (F-08), `Dockerfile` (F-09), SBOM + Cosign (§6)
ก่อนอัด: `export TEAM_ID=1234Later` ใน terminal และให้เห็น TEAM_ID ทุกฉาก

---

## 0. แนะนำตัว (~10 วิ)
**[จอ: terminal มี TEAM_ID]**
> "สวัสดีครับ/ค่ะ ชื่อ สุธาภัทร (C) ทีม 1234Later ส่วนของผมรับผิดชอบ 3 จุดคือ endpoint `/export`, `/admin`, และ `Dockerfile` กับงาน SBOM และการเซ็น image ด้วย Cosign ครับ/ค่ะ"

## 1. F-07 — Command Injection ที่ `/export` (~50 วิ)
**[จอ: `screenshots/findings/F-07-export-rce.png` หรือรัน curl สด]**
- **เจาะ:** "ล็อกอินเป็น alice ซึ่งเป็นผู้ใช้ธรรมดา แล้วเรียก `/export?fmt=txt;id` ผลลัพธ์ได้ `uid=0(root)` แปลว่าสั่งคำสั่งอะไรก็ได้ในฐานะ root"
- **สาเหตุ:** "โค้ดเอา `fmt` จาก query string ไปต่อสตริงแล้วรันด้วย `subprocess.run(..., shell=True)` shell แยกไม่ออกว่าอะไรคือคำสั่งของแอป อะไรคือของผู้โจมตี เครื่องหมาย `;` จึงรันเป็นอีกคำสั่ง ความเสี่ยงคือ CWE-78, ระดับ Critical"
- **แก้:** "เลิกใช้ `shell=True` ส่งเป็น list แทน และเพิ่ม allow-list ให้รับแค่ txt, csv, json"
- **ทดสอบซ้ำ:** **[จอ: retest]** "เจาะซ้ำด้วย `fmt=txt;id` ได้ `400 unsupported format` ส่วน `fmt=csv` ยังใช้งานได้ปกติ"

## 2. F-08 — `/admin` เปิดเผย password hash (~35 วิ)
**[จอ: `F-08-admin-password-dump.png`]**
- **เจาะ:** "ล็อกอินเป็น admin จริง เรียก `/admin` แล้วได้ MD5 hash ของทุกคนใน response"
- **สาเหตุ:** "query ดึงคอลัมน์ `password` มาด้วย แล้ว serialize ทั้งแถวเป็น JSON ทั้งที่ endpoint นี้แค่ไว้ดูรายชื่อ ถ้า session admin รั่ว ผู้โจมตีเอา hash ไปแคร็กต่อได้ทั้งระบบ CWE-200"
- **แก้:** "เปลี่ยนเป็น `SELECT id, username, role` ตัดคอลัมน์ password ออกที่ระดับ SQL เลย"
- **ทดสอบซ้ำ:** **[จอ: retest]** "ตอนนี้ได้แค่ id, username, role"

## 3. F-09 — Dockerfile (~45 วิ)
**[จอ: `F-09-dockerfile-root-secret.png` แล้วตัดไป Dockerfile ใหม่]**
- **เจาะ:** "`docker exec ... whoami` ได้ root และ `docker history | grep -i secret` เจอ `APP_SECRET` ฝังอยู่ใน image"
- **สาเหตุ:** "Dockerfile ไม่มี `USER`, ใช้ `ENV` ฝัง secret, `COPY . .` เอาทั้ง repo ไปใน image และใช้ base image แบบ tag ที่เปลี่ยนได้ ทำให้ช่องโหว่ F-07 กลายเป็น root เต็มตัว CWE-250 และ CWE-798"
- **แก้:** "สร้าง user `notevault` ไม่ใช่ root, เอา secret ออกจาก image, copy เฉพาะ `app.py` กับ requirements, pin base image ด้วย digest และปิด debug mode"
- **ทดสอบซ้ำ:** **[จอ: retest]** "`whoami` ได้ `notevault`, `docker history` ไม่เจอ secret, `/console` ได้ 404"

## 4. SBOM + Cosign (~45 วิ)
**[จอ: `screenshots/supply-chain/F-06-sbom-cyclonedx.png`]**
> "หลังแก้ ผม build image ใหม่แล้วใช้ Syft สร้าง SBOM รูปแบบ CycloneDX ได้ 2,801 components เป็น library 100 ตัว รวม Flask 2.0.1 ที่ pin ไว้ จุดประสงค์คือถ้ามีช่องโหว่ใหม่ในอนาคต เรารู้ทันทีว่า image ของเราใช้ package ไหนอยู่"

**[จอ: `F-06-cosign-verify.png`]**
> "จากนั้นเซ็น image ด้วย Cosign ที่ digest ไม่ใช่ tag เพราะ tag ย้ายได้แต่ digest ย้ายไม่ได้ แล้ว verify ด้วย public key ผลคือ claims ผ่านและ signature ตรงกับ key ครับ/ค่ะ"

> "ระดับ SLSA ที่ประเมินคือ Build L1 เพราะ build ด้วยสคริปต์และมีหลักฐาน SBOM กับลายเซ็น แต่ยังไม่ถึง L2 เพราะ build บนเครื่องของเรา ไม่ใช่ build service และยังไม่มี provenance"

## 5. ปิด (~10 วิ)
> "สรุป: ปิด 3 ช่องโหว่ พิสูจน์ด้วยการเจาะซ้ำ และมี SBOM กับลายเซ็นรองรับ image ที่แก้แล้ว ขอบคุณครับ/ค่ะ"

---

## เตรียมตอบถ้าอาจารย์ถามสด
- **ทำไม allow-list ทั้งที่ `shell=False` แล้ว?** กันไว้สองชั้น ถ้าอนาคตมีคนกลับไปใช้ shell อีก `fmt` ก็ยังถูกจำกัด
- **ทำไมตัด password ที่ SQL ไม่ใช่ตอน output?** ข้อมูลจะไม่เคยเข้ามาในโปรเซส ไม่มีทางหลุดจากโค้ดอื่น
- **ทำไมเซ็นที่ digest?** tag ชี้ไป image อื่นได้ digest ผูกกับเนื้อหาจริง
- **ทำไมไม่ใช้ keyless?** ใช้ local registry ไม่มี public identity จึงใช้ key pair และข้าม Rekor
- **SBOM มี file 2,693 รายการคืออะไร?** Syft นับไฟล์ใน image ด้วย ตัว package จริงคือ 100 library
