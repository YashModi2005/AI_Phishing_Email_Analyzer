# 🛡️ AI Phishing Email Analyzer

> An Enterprise-Grade, Local AI-Powered Security Operations Center (SOC) Application for Phishing Threat Detection, Risk Scoring, and Payload Analysis.

---

## 📌 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features & Functionalities](#-key-features--functionalities)
3. [Technology Stack](#-technology-stack)
   - [Frontend Architecture](#frontend-architecture)
   - [Backend Architecture](#backend-architecture)
4. [Risk Engine & Scoring Model](#-risk-engine--scoring-model)
5. [Prerequisites](#-prerequisites)
6. [First-Time Installation & Setup](#-first-time-installation--setup)
7. [How to Re-Access & Restore the Project (If Deleted Locally)](#-how-to-re-access--restore-the-project-if-deleted-locally)
8. [Author & GitHub Profile](#-author--github-profile)
9. [License](#-license)

---

## 📖 Project Overview

The **AI Phishing Email Analyzer** is an end-to-end security platform designed to assist SOC Analysts, Security Engineers, and Enterprise IT teams in identifying, analyzing, and explaining phishing threats embedded in raw or pasted email payloads.

Combining deterministic multi-vector heuristics with **Privacy-First Local Large Language Models (LLMs)** via **Ollama**, the platform evaluates suspicious emails without sending confidential payload data to third-party cloud APIs.

---

## ⚡ Key Features & Functionalities

1. **🛡️ Weighted Phishing Risk Engine (0–20 Index)**:
   - Evaluates email payloads across 23 distinct indicator vectors.
   - Categorizes findings into **Critical**, **High**, **Medium**, **Low**, and **Negative (Trust/Authentication)** severity levels.
   - Automatically clamps composite scores from `0` (Clean/Legitimate) to `20` (Critical Threat).

2. **🧠 Local AI SOC Threat Assessment**:
   - Generates structured executive briefings (*Verdict*, *Indicators Found*, *Why It Is Suspicious*, *Recommended Action Protocol*).
   - Fully local LLM execution via Ollama (`qwen2.5:1.5b`, `llama3.1`) ensures zero data leakage.

3. **🔍 Advanced Link & Domain Intelligence**:
   - **Lookalike & Typosquatting Detection**: Identifies character substitution and brand spoofing.
   - **Hyphenated Phishing Domain Patterns**: Flags multi-keyword domain structures (e.g., `company-benefits-update.com`).
   - **WHOIS Registration Age**: Flags unverified or newly registered domains (<90 days).
   - **TLD Risk Vetting**: Highlights high-risk top-level domains (`.xyz`, `.top`, `.click`, `.zip`).

4. **📋 Smart Header Parsing & Metadata Inference**:
   - Extracts standard RFC headers (`From:`, `To:`, `Subject:`, `Date:`).
   - **Intelligent Inference**: When raw headers are missing, infers sender identity from sign-off signatures (e.g. *"Human Resources - Benefits Team"*) and recipient context from greetings (*"Dear Employee"*).

5. **📊 Interactive Telemetry Diagnostics**:
   - Displays dynamic Threat Saturation percentages, Link Integrity status, and Behavioral Urgency levels.

6. **💬 Interactive AI Security Analyst Chatbot**:
   - Embedded context-aware assistant allowing analysts to ask follow-up questions about the analyzed payload in real time.

---

## 🛠️ Technology Stack

### Frontend Architecture
- **Framework**: [Streamlit](https://streamlit.io/) (v1.30+)
- **Styling**: Custom Vanilla CSS (Dark Mode Design Tokens, Glassmorphic Panels, Dynamic Animations, Custom Telemetry Badges)
- **UI Components**: Custom HTML/CSS iFrames, Dynamic Progress Bars, Carousel Panels

### Backend Architecture
- **Language**: Python 3.10+
- **Local AI Engine**: [Ollama](https://ollama.com/) Python Client (`ollama-python`)
- **Domain Intelligence**: `tldextract` (URL parsing), `python-whois` (Registry age lookup)
- **Data & Dataframes**: `pandas`, `pydantic`
- **Testing & Verification**: `pytest`

---

## 📊 Risk Engine & Scoring Model

| Composite Score | Verdict Level | Threat Saturation | Recommended Action Protocol |
| :--- | :--- | :--- | :--- |
| **0 – 3** | 🟢 **LOW** | `0% - 15%` | Deliver email. |
| **4 – 8** | 🟡 **MEDIUM** | `20% - 40%` | Deliver with caution. |
| **9 – 12** | 🟠 **HIGH** | `45% - 60%` | Quarantine and review. |
| **13 – 16** | 🔴 **VERY HIGH** | `65% - 80%` | Quarantine immediately and notify SOC. |
| **17 – 20** | 🟣 **CRITICAL** | `85% - 100%` | Block sender, quarantine email, alert SOC, investigate organization-wide. |

---

## ⚙️ Prerequisites

Before running the application, ensure you have installed:
1. **Python 3.10+**: [Download Python](https://www.python.org/downloads/)
2. **Ollama**: [Download Ollama](https://ollama.com/)
3. **Git**: [Download Git](https://git-scm.com/)

---

## 🚀 First-Time Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/YashModi2005/AI_Phishing_Email_Analyzer.git
   cd AI_Phishing_Email_Analyzer
   ```

2. **Create & Activate a Virtual Environment**:
   ```bash
   # Windows PowerShell
   python -m venv venv
   .\venv\Scripts\activate

   # Linux/macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Download an AI Model via Ollama**:
   ```bash
   # Fast model (1-3 seconds CPU response time):
   ollama pull qwen2.5:1.5b

   # Standard model:
   ollama pull llama3.1
   ```

5. **Launch the Application**:
   ```bash
   streamlit run app.py
   ```
   Open your browser at `http://localhost:8501`.

---

## 🔄 How to Re-Access & Restore the Project (If Deleted Locally)

If you delete this project folder from your laptop after uploading it to GitHub, **don't worry!** You can completely restore it onto any computer in **under 2 minutes** by following these steps:

### Step 1: Open Terminal / Command Prompt
Open PowerShell, Command Prompt, or Terminal on your computer.

### Step 2: Clone the Project from GitHub
Navigate to the directory where you want to store the project (e.g. Desktop) and run:
```bash
cd Desktop
git clone https://github.com/YashModi2005/AI_Phishing_Email_Analyzer.git
cd AI_Phishing_Email_Analyzer
```

### Step 3: Re-create Virtual Environment & Re-install Dependencies
```bash
# Re-create virtual environment
python -m venv venv

# Activate it (Windows)
.\venv\Scripts\activate

# Install all required packages
pip install -r requirements.txt
```

### Step 4: Run the Application Again
```bash
streamlit run app.py
```
Your application will immediately start up with all features, styling, and scoring rules intact!

---

## 👤 Author & GitHub Profile

**Yash Modi**
- **GitHub Profile**: [@YashModi2005](https://github.com/YashModi2005)
- **Project Repository**: [https://github.com/YashModi2005/AI_Phishing_Email_Analyzer](https://github.com/YashModi2005/AI_Phishing_Email_Analyzer)

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
