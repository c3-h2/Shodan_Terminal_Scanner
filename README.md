# Shodan Terminal Scanner 🔍 - STS

Advanced security scanning tool that brings Shodan's web interface experience to your terminal.

## 🌟 Features

- **Target Types:** IP Address or Domain
- **Shodan Web UI Format:** Real-time ASCII tables
- **Vulnerability Reporting:** Port-specific and aggregated CVE lists
- **SSL/TLS Analysis:** Encryption details and certificate information
- **Banner Preview:** First 3 lines of service banners
- **Smart Formatting:** Text wrapping and error tolerance
- **JSON Output:** Save raw data to file

## 🛠️ Installation

1. **Ensure Python 3.8+** is installed:

Install required libraries:
 pip install shodan

 Get Shodan API Key:
 https://account.shodan.io/

 🚀 Usage
python shodan_scanner.py <target> --api-key <API_KEY> [OPTIONS]

Options

Parameter	Description	Default
--threshold	Maximum results per service	10
--output	Output filename	shodan_scan.json


Examples

Basic Scan:
python shodan_scanner.py 8.8.8.8 --api-key ABC123

Domain Scan (5 Results):
python shodan_scanner.py example.com --api-key ABC123 --threshold 5


📊 Sample Output

![image](https://github.com/user-attachments/assets/37c96c0a-80fc-460a-827a-e150089a6ae0)



[+] Results saved to shodan_scan.json



📌 Notes

Requires valid Shodan API key
Use threshold to manage API usage
Full technical details available in JSON output


⚠️ Disclaimer

This tool is intended for ethical hacking and security research only. The developer is not responsible for illegal use.


