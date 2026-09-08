# GP-SQLi

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

GP-SQLi adalah tool otomatis deteksi dan verifikasi celah keamanan **SQL Injection (SQLi)** berbasis Python murni yang sangat ringan. Tool ini beroperasi secara asinkron/cepat untuk mengidentifikasi celah Error-based dan Boolean-based blind pada parameter GET aplikasi web.

![GP-SQLi Terminal Preview](assets/sqli-preview.svg)

---

## Fitur Utama

- **Menu Interaktif**: Cukup jalankan `python3 gp_sqli.py` tanpa argumen untuk masuk ke menu interaktif dengan logo personal **By Gopyr**.
- **Deteksi Heuristik Cepat**: Mengirim payload khusus untuk memicu respons error database yang umum (MySQL, PostgreSQL, MS SQL, SQLite, Oracle).
- **Boolean-Blind Validation**: Menguji variasi logika logika benar/salah secara otonom untuk memvalidasi kerentanan blind SQLi.
- **Laporan JSON**: Menyimpan seluruh hasil pengujian dan data bukti eksploitasi dalam skema JSON terstruktur.

---

## Cara Penggunaan

### Mode Interaktif
```bash
python3 gp_sqli.py
```

### Mode Command Line
```bash
python3 gp_sqli.py "http://testphp.vulnweb.com/listproducts.php?cat=1" --output report.json
```

---

## Disclaimer & Tanggung Jawab

GP-SQLi adalah tool pengujian keamanan ofensif. Anda hanya diizinkan untuk menguji sistem yang Anda miliki secara sah atau sistem yang telah memberikan izin tertulis penuh kepada Anda. Penyalahgunaan tool ini untuk aktivitas ilegal berada sepenuhnya di bawah tanggung jawab pengguna pribadi.

## Lisensi

[MIT License](LICENSE) - Bebas digunakan dan dikembangkan oleh komunitas.
