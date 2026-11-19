# 🛡️ CyberShield AI
### An AI-Powered Unified Cybersecurity Protection Platform

CyberShield AI is a web-based cybersecurity platform designed to help users identify potential security threats and improve their digital safety through multiple security scanning and analysis modules.

The platform brings different cybersecurity tools together in one place, providing users with threat analysis, security recommendations, and scan history.

## ✨ Key Features

- **Malware Detection:** Scan files for potential malware threats.
- **Folder Scanning:** Scan folders to identify suspicious files.
- **URL & Phishing Detection:** Analyze URLs for potential phishing threats.
- **Email Phishing Detection:** Examine email content for suspicious patterns.
- **Password Security:** Evaluate password strength and identify security weaknesses.
- **Network Monitoring:** Monitor network-related security information.
- **AI Threat Analyzer:** Analyze scan results and provide threat insights and security recommendations.
- **Incident Reporting:** Generate reports for detected security incidents.
- **Security Analytics:** View security-related scan information.
- **Scan History:** Store and review previous scan records using SQLite.

## 🛠️ Technologies Used

| Category | Technologies |
|---|---|
| Frontend | HTML, CSS, JavaScript, Bootstrap |
| Backend | Python, Flask |
| Data Analysis / AI | Python, Scikit-learn |
| Database | SQLite |
| Visualization | Chart.js |
| Antivirus Integration | ClamAV |
| Version Control | Git & GitHub |

## 📂 Project Structure

```text
CyberShieldAI/
│
├── app.py
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
├── reports/
└── .gitignore
```

## ⚙️ Installation & Setup

### Prerequisites
- Python 3
- Git
- ClamAV (for antivirus scanning functionality)

### 1. Clone the repository

```bash
git clone https://github.com/vaishnavipandurangbelote/CyberShieldAI.git
```

### 2. Navigate to the project directory

```bash
cd CyberShieldAI
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the virtual environment

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

### 5. Install the project dependencies

Install the required Python packages used by the project.

### 6. Run the application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000/
```

## 🎯 Project Objectives

- Bring multiple cybersecurity tools into a unified platform.
- Help users identify potential digital security threats.
- Provide useful threat analysis and security recommendations.
- Maintain records of previous security scans.
- Promote awareness of cybersecurity practices.

## 🔮 Future Enhancements

- Improve threat detection accuracy.
- Expand AI-based threat analysis capabilities.
- Add real-time threat intelligence integration.
- Enhance security analytics and visualization.
- Introduce additional security monitoring features.

## ⚠️ Disclaimer

CyberShield AI is an educational project developed for cybersecurity learning and demonstration purposes. Its scan results should not be considered a replacement for professional antivirus software or a comprehensive security audit.

## 👩‍💻 Developer

**Vaishnavi Pandurang Belote**

B.Sc. Information Technology

GitHub: [@vaishnavipandurangbelote](https://github.com/vaishnavipandurangbelote)

---

⭐ If you find this project interesting, consider giving the repository a star!
