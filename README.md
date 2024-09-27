# OSINTify

 ██████╗ ███████╗██╗███╗   ██╗████████╗██╗███████╗██╗   ██╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██║██╔════╝╚██╗ ██╔╝
██║   ██║███████╗██║██╔██╗ ██║   ██║   ██║█████╗   ╚████╔╝ 
██║   ██║╚════██║██║██║╚██╗██║   ██║   ██║██╔══╝    ╚██╔╝  
╚██████╔╝███████║██║██║ ╚████║   ██║   ██║██║        ██║   
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝        ╚═╝   
       
       Author: D4rk_H0rs3
       Github: https://github.com/d4rkh0rse
       Version: 1.0.1       

[![OSINTify CI Pipeline](https://github.com/d4rkh0rse/OSINTify/actions/workflows/ci.yml/badge.svg)](https://github.com/d4rkh0rse/OSINTify/actions/workflows/ci.yml)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/d4rkh0rse/OSINTify/issues)
[![Version](https://img.shields.io/badge/version-1.0.1-blue)](https://github.com/d4rkh0rse/OSINTify/releases)



OSINTify is a powerful Open Source Intelligence (OSINT) reconnaissance tool designed to gather essential information about a given domain. It performs various lookups and searches to provide insights from WHOIS data to GitHub profiles, DNS records, and more.

## 🚀 What's New in v1.0.1

- **WHOIS Lookup**: Retrieve registration details of a domain.
- **DNS Records**: Fetch A records and other DNS entries.
- **Reverse IP Lookup**: Find other domains hosted on the same IP.
- **GitHub Recon**: Search for related GitHub users and organizations.
- **Google Dorking**: Generate and display Google dorks tailored to the target domain.
- **SSL Certificate Details**: Get information about the domain's SSL certificate.
- **Subdomain Enumeration**: Enhanced output formatting and improved accuracy.

## Installation

To use OSINTify, ensure you have Python 3.x installed. Clone the repository and install the required packages:

```bash
git clone https://github.com/YourGitHub/OSINTify.git
cd OSINTify
pip install -r requirements.txt
```
## Usage
```bash
python OSINTify.py -d example.com -subs -ssl -whois -dns -revip -github -dorks
```
### Example Commands

- **Run All Features**:
    ```bash
    python OSINTify.py -d example.com -subs -ssl -whois -dns -revip -github -dorks
    ```

- **Run Specific Features**:
    - Subdomain enumeration and WHOIS lookup:
        ```bash
        python OSINTify.py -d example.com -subs -whois
        ```

    - GitHub reconnaissance and DNS lookup:
        ```bash
        python OSINTify.py -d example.com -github -dns
        ```

## Contribution
Contributions are welcome! If you have suggestions for improvements or new features, please open an issue or submit a pull request.

## Author
[D4rk_H0rs3](https://github.com/d4rkh0rse)
