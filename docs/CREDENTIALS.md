# NusaBank Lab — Kredensial Dummy

> **PERINGATAN:** Semua akun di bawah ini fiktif dan hanya untuk lab lokal.
> Jangan gunakan password ini di sistem nyata.

PIN transaksi seluruh akun: **`123456`**

## Akun Administrator

| Username | Password | Role | Email |
|----------|----------|------|-------|
| `admin` | `NusaAdmin!2024` | `admin` (super-admin) | admin@example.com |
| `cs123` | `NusaCS!2024` | `admin_cs` | cs@example.com |
| `finance456` | `NusaFinance!2024` | `admin_finance` | finance@example.com |

## Akun Nasabah (30)

Password lemah (cocok untuk latihan brute-force / dictionary):

| Username | Nama | Password |
|----------|------|----------|
| `budi01` | Budi Santoso | `password` |
| `ani02` | Ani Wijaya | `123456` |
| `dewi03` | Dewi Lestari | `qwerty` |
| `eko04` | Eko Prasetyo | `nusabank` |
| `fitri05` | Fitri Handayani | `admin123` |

Password kuat (25 akun):

| Username | Nama | Password |
|----------|------|----------|
| `gunawan06` | Gunawan Saputra | `NusaBank!2024#06` |
| `herlina07` | Herlina Kusuma | `NusaBank!2024#07` |
| `indra08` | Indra Nugroho | `NusaBank!2024#08` |
| `joko09` | Joko Setiawan | `NusaBank!2024#09` |
| `kiki10` | Kiki Purnomo | `NusaBank!2024#10` |
| `lina11` | Lina Wibowo | `NusaBank!2024#11` |
| `mario12` | Mario Susanto | `NusaBank!2024#12` |
| `nana13` | Nana Saputra | `NusaBank!2024#13` |
| `odi14` | Odi Mulyadi | `NusaBank!2024#14` |
| `putri15` | Putri Hidayat | `NusaBank!2024#15` |
| `qori16` | Qori Rizky | `NusaBank!2024#16` |
| `raka17` | Raka Darmawan | `NusaBank!2024#17` |
| `sari18` | Sari Suryadi | `NusaBank!2024#18` |
| `tino19` | Tino Hakim | `NusaBank!2024#19` |
| `uli20` | Uli Ardiansyah | `NusaBank!2024#20` |
| `vina21` | Vina Oktaviani | `NusaBank!2024#21` |
| `wira22` | Wira Kurniawan | `NusaBank!2024#22` |
| `xavi23` | Xavi Ramadhan | `NusaBank!2024#23` |
| `yuni24` | Yuni Anggraini | `NusaBank!2024#24` |
| `zaki25` | Zaki Firmansyah | `NusaBank!2024#25` |
| `adi26` | Adi Kurnia | `NusaBank!2024#26` |
| `cici27` | Cici Marlina | `NusaBank!2024#27` |
| `deni28` | Deni Maulana | `NusaBank!2024#28` |
| `eni29` | Eni Yuliana | `NusaBank!2024#29` |
| `faisal30` | Faisal Abdurrahman | `NusaBank!2024#30` |

Email mengikuti pola `<username>@example.com`. Nomor rekening dibuat acak
10 digit saat seeding; lihat tabel `accounts` atau dashboard nasabah.

## Catatan Level

- `easy` / `medium`: password disimpan sebagai MD5 (`md5:<hash>`), sehingga
  hash dapat di-crack dengan wordlist.
- `hard` / `patched`: password dan PIN disimpan dengan bcrypt.
- Jika Anda mengganti `LAB_LEVEL` setelah database dibuat, reset database agar
  format hash sesuai: `python db/seed.py --force`.

## Lokasi Flag Lab

| Flag | Lokasi |
|------|--------|
| `FLAG{flag_in_database}` | kolom `users.address` milik `admin` |
| `FLAG{flag_in_file_system}` | `uploads/legacy/flag.txt` |
| `FLAG{flag_in_admin_panel}` | `settings.flag_admin_panel`, tampil di panel admin |
| `FLAG{ssrf_internal_metadata_reached}` | endpoint internal `/internal/metadata` |
| `FLAG{backup_archive_leaked}` | `/backup.zip` (easy/medium) |