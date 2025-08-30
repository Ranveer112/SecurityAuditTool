# SecurityAuditTool

## Description

SecurityAuditTool is a domain security assessment utility that supports both command-line and API-based usage. It performs DNS resolution, RTT checks, HTTPS analysis, certificate chain inspection, reverse DNS, and geolocation checks across multiple domains.

It can also do security scanning of Infrastructure-as-Code files (only Terraform is supported at the moment) using a LLM. Although this exists, it is an experiment and for production use, I would recommend static checkers such as checkov.


### Components

- **`dist/domain-scan`**: A self-contained executable CLI scanner built via PyInstaller. No Python install required.
- **`src/domains_scanner/`**: Modular Python package containing all domain scanning logic, now cleanly split into class-based modules like `certificate_checker.py`, `dns_checker.py`, `rtt_checker.py`, etc.
- **`src/api/server.py`**: A FastAPI server that exposes a `/audit` POST API for domain scanning.
- **`src/iacs_scanner/`**: A basic Infrastructure-as-Code files scanner for Terraform files.

---

## Getting Started

### Easiest Way (recommended)


#### For Domain Scanning:

Set the MaxMind license key via environment variable. The database will be downloaded automatically on first run.

```bash
export MAXMIND_LICENSE_KEY=your_key_here
```

Or on Windows:

```powershell
$env:MAXMIND_LICENSE_KEY="your_key_here"
```
Use the bundled executable built via PyInstaller(available within `dist` directory:

```bash
./dist/domain-scan input_file.txt output_file.txt --output-log log.txt --log-level {DEBUG, INFO, WARNING, ERROR, CRITICAL}
``` 
> The executable should be self-contained and portable for Unix based systems.


#### For Infrastructure-as-Code Scanning:

Use the bundled executable built via PyInstaller(available within `dist` directory:

```bash
./dist/iacs-scan iac_file.tf output_file.txt

``` 
> The executable should be self-contained and portable for Unix based systems.

---

### Using these tools via Python

#### 1. Requirements

- Python 3.12.10
- pip(hatch, pdm, poetry might also work)

#### 2. Install dependencies

Using pip (modern versions, PEP 517/518 compatible):

To install all dependencies:
```bash
pip install -e .  # For development/editable install(For example - if you are constantly modifying the code and do not want to reinstall every time)
```

To install only domain scanner dependencies:
```bash
pip install -e .[domains]
```

To install only iac scanner dependencies:
```bash
pip install -e .[iac]
```

#### 3. GeoLite2 Setup(For Domain Scanner)

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

### Domain Scanning

Output-log flag is optional, however, if passed, the log level flag can be used to control the log level. If log level is not passed, INFO will be used by default.

#### 🔹 CLI (via Python)

```bash
python src/domains_scanner/scan.py input_file.txt output_file.txt --output-log log.txt --log-level {DEBUG, INFO, WARNING, ERROR, CRITICAL}
```

#### 🔹 CLI (via PyInstaller binary)

```bash
./dist/domain-scan input_file.txt output_file.txt --output-log log.txt --log-level {DEBUG, INFO, WARNING, ERROR, CRITICAL}
```

#### 🔹 Server API

There is also a FastAPI server that exposes a `/audit` POST API for domain scanning, that you can choose to run. To run that server, first install the dependencies:

```bash
pip install -e .[domains]
pip install -e .[api]
```

Run:

```bash
uvicorn src.api.server:app --reload
```

Then call, if running the server locally:

```bash
curl -X POST "http://localhost:8000/audit" \
  -H "accept: text/plain" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@domain_inputs.txt" \
  --output report.txt
```
### Infrastructure-as-Code Scanning

#### 🔹 CLI (via Python)

```bash
python src/iacs_scanner/infra_security_scan.py iac_file.tf output_file.txt
```

#### 🔹 CLI (via PyInstaller binary)

```bash
./dist/iacs-scan iac_file.tf output_file.txt
```

---

## Security Stats Reported (Domain Scanner)

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
