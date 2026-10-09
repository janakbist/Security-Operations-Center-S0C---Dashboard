# 🛡️ Security Operations Center (SOC) Dashboard

An AI-powered Security Operations Center (SOC) dashboard built with Python and Streamlit to help monitor system logs, identify potential security threats, analyze Indicators of Compromise (IOCs), and map suspicious activities to the MITRE ATT&CK framework.

Designed to make security monitoring and threat analysis more accessible to small organizations and nonprofits.

## 📸 Dashboard Preview

### 1. Main Dashboard
![SOC Dashboard Overview](screenshots/dashboard.png)

### 2. Security Log Analysis
![Security Log Analysis](screenshots/log-analysis.png)

### 3. Indicators of Compromise (IOCs)
![IOC Analysis](screenshots/ioc-analysis.png)

### 4. MITRE ATT&CK Mapping
![MITRE ATT&CK Mapping](screenshots/mitre-attack.png)

## ✨ Key Features

- **Log Analysis:** Upload and analyze system and security logs.
- **Threat Detection:** Identify suspicious activities and potential security threats.
- **IOC Analysis:** Extract and review Indicators of Compromise.
- **MITRE ATT&CK Mapping:** Associate detected behaviors with relevant attack techniques.
- **Interactive Dashboard:** Explore security findings through an intuitive interface.
- **Multiple File Formats:** Support for JSON, CSV, TXT, TSV, and LOG files.

## 🛠️ Technology Stack

- Python
- Streamlit
- Pandas
- AI-powered security analysis
- MITRE ATT&CK Framework

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or later
- pip package manager
- Git

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/janakbist/Security-Operations-Center-S0C---Dashboard.git
cd Security-Operations-Center-S0C---Dashboard
```

**2. Create a virtual environment**

```bash
python3 -m venv venv
```

**3. Activate the environment**

macOS/Linux:

```bash
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

**4. Install dependencies**

If your repository includes a `requirements.txt` file:

```bash
pip install -r requirements.txt
```

**5. Run the application**

```bash
streamlit run app.py
```

If your main Python file has a different name, replace `app.py` with the correct filename.

## 📂 Supported Log Formats

- JSON (`.json`)
- CSV (`.csv`)
- Plain text (`.txt`)
- Tab-separated values (`.tsv`)
- Log files (`.log`)

Actual parsing and detection capabilities depend on the implemented application features and the uploaded log structure.

## 🎯 Project Objectives

- Improve visibility into system and security events.
- Simplify security log analysis.
- Help identify potential threats and indicators of compromise.
- Support security investigations using MITRE ATT&CK techniques.
- Make basic SOC capabilities more accessible to smaller organizations.

## 🔒 Security Notice

This project is intended for educational and defensive cybersecurity purposes. Use authorized log data, validate uploaded files, and avoid uploading sensitive information or credentials to untrusted environments.

AI-generated findings should be reviewed by a security analyst before taking action.

## 👨‍💻 Authors

**Janak Bist** , **Omar Aouled** , **Bhanu Teja Konduru**

Developed as an academic cybersecurity project.

⭐ If you find this project useful, consider starring the repository.
