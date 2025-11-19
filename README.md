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

## 📽️ Demo

Here is a short demo of vulnscan-report in action:

![Tool Demo](docs/demo.gif)

---

## 📁 Project Structure

