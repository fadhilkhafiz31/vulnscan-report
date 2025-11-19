[![Live Demo](https://img.shields.io/badge/Live_Demo-Online-brightgreen)](https://fadhilkhafiz31.github.io/vulnscan-report/) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg) ![GitHub stars](https://img.shields.io/github/stars/fadhilkhafiz31/vulnscan-report?style=social)

# vulnscan-report
# 🔍 vulnscan-report  
*A lightweight Nmap-based vulnerability scanner with automated HTML report generation.*

`vulnscan-report` is a Python tool that runs vulnerability scans using **Nmap**, parses the results, and generates a clean **HTML security report**.  

This project demonstrates real-world cybersecurity skills, including scanning, parsing XML, automating reports, and designing cybersecurity tooling — perfect for portfolio and early-career security roles.

## 🔗 Live Demo

- **Project Site:** https://fadhilkhafiz31.github.io/vulnscan-report/
- **Sample Report:** https://fadhilkhafiz31.github.io/vulnscan-report/demo-report.html

---

## 🚀 Features

- ✔ **Automated Nmap scanning** (`-sV` service detection)  
- ✔ **XML parsing** using `lxml`  
- ✔ **Clean HTML report generation** using `Jinja2`  
- ✔ **Port/Service analysis**  
- ✔ **Automatically adds recommendations for detected services**  
- ✔ **Modular code structure** (easy to extend)  
- ✔ Beginner-friendly, yet professional enough for GitHub and resumes  

---

## 🛠 Tech Stack

| Component | Technology |
|----------|------------|
| Scanner | Nmap |
| Programming Language | Python 3 |
| XML Parser | lxml |
| Report Engine | Jinja2 |
| OS Compatibility | Windows / Linux / macOS |

---

## 📖 Usage

Run a vulnerability scan and generate an HTML report:

```bash
py run_scan.py --target 127.0.0.1 --output reports/my_report.html
```

---

## 🔧 Scan Profiles

Choose from multiple scan profiles to suit your needs:

| Profile | Description | Nmap Flags |
|---------|-------------|------------|
| `default` | Standard scan with service detection (default) | `-sV -T4` |
| `fast` | Quick scan of most common ports | `-F` |
| `full` | Comprehensive scan of all 65535 TCP ports | `-sV -T4 -p-` |
| `top100` | Scan top 100 most common ports | `--top-ports 100` |
| `udp` | UDP port scan | `-sU` |

### Examples

**Quick scan:**
```bash
py run_scan.py --target 127.0.0.1 --profile fast --output reports/quick_scan.html
```

**Full port scan:**
```bash
py run_scan.py --target 192.168.1.1 --profile full --output reports/full_scan.html
```

**UDP scan:**
```bash
py run_scan.py --target localhost --profile udp --output reports/udp_scan.html
```

**Top 100 ports:**
```bash
py run_scan.py --target 10.0.0.1 --profile top100 --output reports/top100_scan.html
```
