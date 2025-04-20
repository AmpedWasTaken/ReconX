# ReconX

ReconX is a powerful subdomain reconnaissance tool that helps security researchers and penetration testers discover and analyze subdomains of target domains. It features service detection, subdomain takeover checks, and comprehensive scanning capabilities.

## Features

- Fast subdomain enumeration using subfinder
- Detection of common services:
  - Webmail systems
  - Admin panels
  - File managers
  - Login portals
  - Development endpoints
  - Monitoring systems
  - Database administration
  - cPanel instances
- Subdomain takeover vulnerability detection
- Multi-threaded scanning for improved performance
- Beautiful console output using Rich
- JSON export capability
- Configurable service scanning

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ReconX.git
cd ReconX
```

2. Install the required Python packages:
```bash
pip install -r requirements.txt
```

3. Install subfinder:
```bash
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
```

## Usage

Basic usage:
```bash
python reconx.py --domain example.com
```

Scan for specific services:
```bash
python reconx.py --domain example.com --webmail --admin --login
```

Scan all services and check for takeover vulnerabilities:
```bash
python reconx.py --domain example.com --all --takeover
```

Export results to JSON:
```bash
python reconx.py --domain example.com --all --json results.json
```

### Command Line Arguments

- `--domain`: Target domain (required)
- `--webmail`: Check for webmail services
- `--admin`: Check for admin panels
- `--filemanager`: Check for file managers
- `--login`: Check for login portals
- `--dev`: Check for development endpoints
- `--monitoring`: Check for monitoring systems
- `--dbadmin`: Check for database administration panels
- `--cpanel`: Check for cPanel instances
- `--all`: Check for all services
- `--takeover`: Check for subdomain takeover vulnerabilities
- `--json`: Export results to JSON file
- `--onlylive`: Only scan live subdomains

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and research purposes only. Users are responsible for complying with applicable laws and regulations. The author is not responsible for any misuse or damage caused by this tool. 