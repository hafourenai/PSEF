# 💥  Post-Scanning Exploitation Framework (PSEF)


## Fitur Utama

- **Deterministic Exploitation**: Hasil yang dapat direproduksi, bukan sekadar menebak.
- **Multi-Signal Verification**: Verifikasi kerentanan menggunakan analisis statistik (time-based, boolean-based, error-based).
- **Security-First Design**: Sanitasi URL dan payload untuk mencegah self-exploitation dan SSRF.
- **Thread-Safe Orchestration**: Manajemen state yang aman untuk eksekusi paralel.
- **Interactive Mode**: Masukkan target dan detail kerentanan secara manual melalui prompt terminal.
- **Professional Reporting**: Output laporan dalam format HTML, JSON, dan Markdown yang siap dikirim ke klien.

## 📁 Struktur Proyek

```
exploit_framework/
├── core/          # Engine utama dan HTTP client
├── models/        # Data models (Finding, Exploit, Enum)
├── analyzers/     # Analisis parameter dan konteks
├── exploits/      # Modul eksploitasi (SQLi, dll)
├── verification/  # Mesin verifikasi kerentanan
├── reporting/     # Sistem pembuatan laporan
├── utils/         # Utilitas keamanan dan logging
├── templates/     # Template JSON untuk input
└── scripts/       # Script pembantu (generator, validator)
```

## Instalasi

1. **Clone repository:**
   ```bash
   git clone <repository-url>
   cd PSEF
   ```

2. **Setup Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Pengunaan Cepat

### 1. Siapkan Findings
Buat file `findings.json` berdasarkan hasil scan Anda (lihat folder `templates/` untuk contoh).

```json
[
  {
    "target": "https://example.com",
    "endpoint": "/product.php",
    "method": "GET",
    "parameter": "id",
    "value": "1",
    "vulnerability_type": "SQL_INJECTION"
  }
]
```

### 2. Jalankan Framework

Anda bisa menjalankan framework dengan dua cara:

#### A. Mode Otomatis (Menggunakan File JSON)
```bash
python main.py --findings findings.json --output audit_report --verbose
```

#### B. Mode Interaktif (Input Manual)
```bash
python main.py --interactive
```
Dalam mode ini, Anda akan diminta memasukkan detail target secara langsung di terminal.

### 3. Cek Laporan
Laporan akan tersedia di:
- `audit_report.html` (Laporan interaktif)
- `audit_report.json` (Raw data)
- `audit_report.md` (Dokumentasi teknis)

## Konfigurasi
Sesuaikan perilaku framework melalui file `config.yaml`. Anda dapat mengatur timeout, rate limiting, threads, dan daftar path yang dilarang.

## Testing
Jalankan uji coba menggunakan findings contoh:
```bash
python main.py --findings examples/example_findings.json
```

---
**⚠ Disclaimer**: Gunakan alat ini hanya pada sistem yang Anda miliki izin tertulis untuk mengujinya. Penyalahgunaan alat ini dapat berakibat hukum.
