# 🛡️ CyberShield AI

### An AI-Powered Unified Cybersecurity Protection Platform

\<p align="center">   \<img src="[https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white](https://img.shields.io/badge/Python-3.x-blue?logo=python\&logoColor=white)" alt="Python"/>   \<img src="[https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask](https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask)" alt="Flask"/>   \<img src="[https://img.shields.io/badge/SQLite-Database-blue?logo=sqlite&logoColor=white](https://img.shields.io/badge/SQLite-Database-blue?logo=sqlite\&logoColor=white)" alt="SQLite"/>   \<img src="[https://img.shields.io/badge/Scikit--learn-Machine%20Learning-orange?logo=scikitlearn&logoColor=white](https://img.shields.io/badge/Scikit--learn-Machine%20Learning-orange?logo=scikitlearn\&logoColor=white)" alt="Scikit-learn"/>   \<img src="[https://img.shields.io/badge/Bootstrap-Frontend-7952B3?logo=bootstrap&logoColor=white](https://img.shields.io/badge/Bootstrap-Frontend-7952B3?logo=bootstrap\&logoColor=white)" alt="Bootstrap"/>   \<img src="[https://img.shields.io/badge/Status-Developed-success](https://img.shields.io/badge/Status-Developed-success)" alt="Project Status"/> \</p>

---

## 🌐 Overview

**CyberShield AI** is a web-based cybersecurity platform designed to bring multiple security tools together in one unified application.

It helps users identify potential digital security threats through different scanning modules, analyze security results, and receive meaningful security recommendations.

With an integrated approach to malware detection, phishing analysis, password security, network monitoring, and AI-based threat analysis, CyberShield AI aims to make cybersecurity monitoring more accessible and organized.

## ✨ Key Features

| 🔐 Module                   | 📝 Description                                                         |
| --------------------------- | ---------------------------------------------------------------------- |
| 🦠 Malware Detection        | Scan files to identify potential malware threats.                      |
| 📁 Folder Scanner           | Analyze folders for suspicious files and security risks.               |
| 🌐 URL & Phishing Scanner   | Examine URLs for potential phishing threats.                           |
| 📧 Email Phishing Detection | Analyze email content for suspicious patterns.                         |
| 🔑 Password Security        | Evaluate password strength and identify weaknesses.                    |
| 📡 Network Monitor          | Monitor network-related security information.                          |
| 🤖 AI Threat Analyzer       | Analyze scan results and generate threat insights and recommendations. |
| 📊 Security Analytics       | Present security-related scan information and insights.                |
| 📝 Incident Reporting       | Generate reports for detected security incidents.                      |
| 🗂️ Scan History            | Store and review previous scan records using SQLite.                   |

## 🤖 AI-Powered Threat Analysis

CyberShield AI includes a dedicated threat analysis module that helps interpret security scan results.

- Analyzes available scan information.
- Identifies potential threat indicators.
- Provides security insights.
- Generates recommendations to improve digital safety.

## 🧰 Technology Stack

**Frontend**

- HTML5
- CSS3
- JavaScript
- Bootstrap
- Chart.js

**Backend**

- Python
- Flask
- REST-based application routes

**AI & Security**

- Scikit-learn
- ClamAV
- Python-based security analysis modules

**Database & Tools**

- SQLite
- Git
- GitHub

## 📂 Project Structure

```text
CyberShieldAI/
│
├── app.py
│
├── data/
│   └── threat_hashes.json
│
├── database/
│   ├── folder_scan_history.py
│   └── scan_history.py
│
├── routes/
│   └── main_routes.py
│
├── services/
│   ├── ai_threat_analyzer.py
│   ├── email_scanner.py
│   ├── file_scanner.py
│   ├── folder_scanner.py
│   ├── incident_reporter.py
│   ├── network_scanner.py
│   ├── password_scanner.py
│   ├── security_reports.py
│   └── url_scanner.py
│
├── static/
│   ├── css/
│   └── js/
│
├── templates/
│
└── .gitignore
```

## ⚙️ Installation & Setup

Follow these steps to run CyberShield AI locally.

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/vaishnavipandurangbelote/CyberShieldAI.git
```

### 2️⃣ Navigate to the Project Directory

```bash
cd CyberShieldAI
```

### 3️⃣ Create a Virtual Environment

```bash
python -m venv .venv
```

### 4️⃣ Activate the Virtual Environment

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

### 5️⃣ Install Dependencies

Install the Python packages required by the project.

### 6️⃣ Run the Application

```bash
python app.py
```

### 7️⃣ Open in Browser

Visit the following address:

```text
http://127.0.0.1:5000/
```

## 🎯 Project Goals

- 🔹 Integrate multiple cybersecurity tools into one platform.
- 🔹 Identify potential security threats through scanning modules.
- 🔹 Provide AI-assisted threat analysis and security recommendations.
- 🔹 Maintain scan records for easier monitoring.
- 🔹 Promote awareness of digital security and safe online practices.

## 🚀 Future Enhancements

- Improve threat detection and analysis capabilities.
- Expand AI-based security analysis.
- Integrate additional threat intelligence sources.
- Enhance security dashboards and visualizations.
- Introduce more advanced monitoring capabilities.

---

## 👩‍💻 Developer

**Vaishnavi Pandurang Belote**



---

\<p align="center">   \<b>🛡️ CyberShield AI — Making Digital Security Smarter.\</b>   \<br/>   \<sub>Built with Python, Flask, and a focus on cybersecurity.\</sub> \</p>
