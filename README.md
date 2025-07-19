# SecurityAuditTool

## Description

SecurityAuditTool is a domain security assessment utility that supports both command-line and API-based usage. It performs DNS resolution, RTT checks, HTTPS analysis, certificate chain inspection, reverse DNS, and geolocation checks across multiple domains.

### Components

- **`dist/domain-scan`**: A self-contained executable CLI scanner built via PyInstaller. No Python install required.
- **`src/domains_scanner/`**: Modular Python package containing all domain scanning logic, now cleanly split into class-based modules like `certificate_checker.py`, `dns_checker.py`, `rtt_checker.py`, etc.
- **`src/api/server.py`**: A FastAPI server that exposes a `/audit` POST API for domain scanning.
- **`src/iacs_scanner/`**: ⚠️ *Work in progress* — will enable security scanning of Infrastructure-as-Code files (e.g., Terraform, Kubernetes manifests).

---

## Getting Started

### ✅ Easiest Way (recommended)

Use the bundled executable built via PyInstaller:

```bash
./dist/domain-scan input_file.txt output_file.txt --output-log log.txt --log-level {DEBUG, INFO, WARNING, ERROR, CRITICAL}
``` 
> The executable should be self-contained and portable for Unix based systems.

---

### 🐍 Python Developer Setup

#### 1. Requirements

- Python 3.12.10
- pip/poetry/hatch/pdm

#### 2. Install dependencies

Using pip (modern versions, PEP 517/518 compatible):
```bash
pip install -e .  # For development/editable install(For example - if you are constantly modifying the code and do not want to reinstall every time)
pip install .     # For regular installation
```
Using poetry:
```bash
poetry install     # Install all dependencies
```
Using Hatch:
```bash
hatch env create
hatch shell
```
Using PDM:
```bash
pdm install
```

#### 3. GeoLite2 Setup

Set the MaxMind license key via environment variable. The database will be downloaded automatically on first run.

```bash
export MAXMIND_LICENSE_KEY=your_key_here
```

Or on Windows:

```powershell
$env:MAXMIND_LICENSE_KEY="your_key_here"
```

---

## Usage


Output-log flag is optional, however, if passed, the log level flag can be used to control the log level. If log level is not passed, INFO will be used by default.

### 🔹 CLI (via Python)

```bash
python src/domains_scanner/scan.py input_file.txt output_file.txt --output-log log.txt --log-level {DEBUG, INFO, WARNING, ERROR, CRITICAL}
```

### 🔹 CLI (via PyInstaller binary)

```bash
./dist/domain-scan input_file.txt output_file.txt --output-log log.txt --log-level {DEBUG, INFO, WARNING, ERROR, CRITICAL}
```

### 🔹 Server API

Run:

```bash
uvicorn src.api.server:app --reload
```

Then call:

```bash
curl -X POST "http://localhost:8000/audit" \
  -H "accept: text/plain" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@domain_inputs.txt" \
  --output report.txt
```

---

## Security Stats Reported

| Field                         | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| **Domain Name**              | Name of domain scanned                                                      |
| **Scan Time**                | Unix Epoch timestamp at scan start                                          |
| **IPv4 / IPv6 Addresses**    | Resolved IP addresses                                                       |
| **HTTP Server**              | HTTP server type (from headers)                                             |
| **Insecure HTTP**            | Whether the domain supports HTTP (even if redirected)                       |
| **Redirect to HTTPS**        | Whether HTTP redirects to HTTPS within 10 hops                              |
| **RTT Range**                | Min/Max round-trip times for ports 443, 80, and 20                          |
| **Root CA Name**             | Certificate Authority for HTTPS cert                                        |
| **Reverse DNS**              | PTR records for IPv4 addresses                                              |
| **Geolocation of IPs**       | Location metadata via GeoLite2                                              |
| **Domain Enforces HSTS**     | Checks for HSTS (Strict Transport Security) via HTTPS headers              |

---

## Project Structure

```
project-root/
├── dist/                         # PyInstaller binary (domain-scan)
├── src/
│   ├── domains_scanner/         # Domain scanner package (modular classes)
│   ├── api/                     # FastAPI server
│   └── iacs_scanner/            # Infra-as-Code scanner (WIP)
├── geolite_ip_data/             # GeoLite2 database (auto-downloaded)
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
