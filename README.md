# URL Risk Analyzer

A lightweight, passive Python script designed for security auditing, reconnaissance, and bug bounty hunting. It parses large lists of URLs to flag high-risk file extensions, hidden administrative paths, and sensitive information leaked in query parameters.

## 🚀 Features

- **File Extension Check:** Detects exposed backups, databases, and environment configuration files (`.env`, `.sql`, `.bak`, etc.).
- **Path Keyword Scanning:** Identifies structural folders tied to administrative sections or internal setups (`/admin`, `/swagger`, `.git`, etc.).
- **Query Parameter Audit:** Flags sensitive credentials and keys passed insecurely via the URL (`?token=`, `?secret=`, etc.).
- **Zero Dependencies:** Uses Python's native standard library—no external packages required.

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/janagamvinaykumar15/url-risk-analyzer
   cd url-risk-analyzer
   chmod +x analyze.py
   ```

2. Ensure you have Python 3.x installed:
   ```bash
   python --version
   ```

## 💻 Usage

Prepare a text file (`urls.txt`) containing one URL per line, then run the script:

```bash
python analayze.py urls.txt
```

### Example Output
```text
[*] Analysis complete. Found 2 high-risk URLs out of 150 total.

[!] Reason: High-risk file extension
   URL: https://example.com

[!] Reason: Parameter contains sensitive keyword: 'api_secret'
   URL: https://example.com
```

## ⚙️ Customization
You can easily add your own risk vectors by modifying the variables at the top of `analayze.py`:
- `RISK_EXTENSIONS`: Add file types you want to block or detect.
- `RISK_KEYWORDS`: Add internal directory naming conventions unique to your targets.

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
