##SecurityAuditTool

## Description

This project consists of two main Python scripts: `scan.py` and `server.py`. Below is an overview of their purposes:

- **scan.py**: A program with a CLI and a module interface that can accept a list of domain names and reports security stats associated with the domains.
- **server.py**: A FastAPI server with a single POST API call /auditFile that takes a list of domain names and returns back a file with a table of security stats associated with the domains.

## Requirement

Make sure you satisfy the following:

- Python 3.12.10 installed
- The following Python packages:
    - `pip`
- scan.py should run in a POSIX compliant OS with utilities such as nslookup and openssl installed.
- Availability of MaxMind GeoLite2 City database file within a subdirectory named geolite_ip_data inside the running directory of scan.py
  - To download it manually, download it from https://dev.maxmind.com/geoip/geolite2/ using your own MaxMind license key.
  - Ensure you place the downloaded file in geolite_ip_data subdirectory inside the running directory of scan.py.

You can install required packages using pip:

```bash
pip install -r requirements.txt
```
  

## Usage

### scan.py

To scan domain names specified in an input_file.txt and output their security stats in an output_file.txt, run the following command:

```bash
python scan.py input_file.txt output_file.txt
```

If you want to turn on logging, pass an `--error-log` flag followed by the name of the file on which to output error log. 
For example -

```bash
python scan.py input_file.txt output_file.txt --error-log log.txt
```
#### Caveat

1) All the files specified in the command should reside in the same directory as scan.py.

### server.py

You can also choose to just host server.py instead by running the following command

```bash
uvicorn server:app --reload
```
Assuming above is successful, POST requests to URL `/audit` with the file consisting of domain names to scan should return a text/plain content 
file of the report as illustrated by an example request by `curl` below

```bash
curl -X POST "http://localhost:8000/audit"   -H "accept: text/plain"   -H "Content-Type: multipart/form-data"   -F "file=@domain_inputs.txt" --output report.txt
```

## Security stats reported

1) Domain Name - Name of domain scanned
2) Scan Time - Unix Epoch time at the moment of scan of that domain.
3) IPv4 Addresses - IPv4 addresses associated with the domain.
4) IPv6 Addresses  - IPv6 addresses associated with the domain.
5) HTTP Server  - Name of HTTP server of one of the IPs associated with the domain.
6) Insecure HTTP - Boolean denoting whether domain name supports HTTP calls. Considered True even when HTTP calls are redirected to HTTPs
7) Redirect to HTTPS -  Boolean denoting whether HTTP calls are redirected to HTTPs within 10 redirects.
8) RTT Range  - A range of decimals denoting the minimum and maximum round trip time in seconds among all IPv4 addresses and ports: (443, 80, 20) combination associated with the domain.
9) Root CA Name - The name of Root Certificate Authority along the chain of certificates associated with the certificate of the domain.
10) Reverse DNS - A list of reverse DNS values for each IPv4 address associated with the domain. 
11) Geolocation of IPs - A list of geolocations associated with the IPv4 addresses associated with the domain.
12) Domain Enforces Strict Transport - Boolean denoting whether the domain enforces browser to shift any HTTP call to HTTPS. Works by checking the presence of `hsts` header.

## Contributing

If you want to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch for your changes.
3. Submit a pull request.

## License

Specify the project's license here. For example:

This project is licensed under the MIT License. See the `LICENSE` file for details.

