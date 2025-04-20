import subprocess
import requests
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from colorama import Fore, Style, init
import argparse
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# Initialize
init(autoreset=True)
console = Console()

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                  " (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
}

SERVICE_PATHS = {
    "webmail": ["/webmail", "/mail", "/roundcube", "/owa", "/squirrelmail", "/horde"],
    "admin": ["/admin", "/administrator", "/admin/login", "/adminpanel", "/wp-admin", "/cms", "/backend"],
    "filemanager": ["/filemanager", "/fm", "/files", "/uploads", "/browser", "/net2ftp"],
    "login": ["/login", "/signin", "/account/login", "/user/login", "/auth", "/portal/login"],
    "dev": ["/debug", "/phpinfo", "/server-status", "/server-info", "/test", "/dev", "/staging"],
    "monitoring": ["/zabbix", "/nagios", "/status", "/uptime", "/monitor", "/grafana", "/dashboard"],
    "dbadmin": ["/phpmyadmin", "/pma", "/adminer", "/dbadmin", "/mysql", "/sql"],
    "cpanel": ["/cpanel", ":2083", ":2087"]
}

SERVICE_KEYWORDS = {
    "webmail": ["webmail", "roundcube", "email", "outlook", "mail client", "compose", "inbox"],
    "admin": ["admin", "dashboard", "control panel", "admin login", "cms", "backend"],
    "filemanager": ["file manager", "upload", "browse files", "select file", "file list", "drop files"],
    "login": ["login", "sign in", "username", "password", "authentication", "credentials"],
    "dev": ["debug", "phpinfo", "error log", "development", "testing", "xdebug", "dev mode"],
    "monitoring": ["monitoring", "zabbix", "nagios", "metrics", "uptime", "performance", "grafana"],
    "dbadmin": ["phpmyadmin", "mysql", "sql", "database", "import", "export", "run query"],
    "cpanel": ["cpanel", "whm", "webhost manager"]
}

FINGERPRINTS_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/refs/heads/master/fingerprints.json"
fingerprint_signatures = []

def load_fingerprints():
    global fingerprint_signatures
    try:
        res = requests.get(FINGERPRINTS_URL)
        if res.status_code == 200:
            fingerprint_signatures = res.json()
    except Exception as e:
        console.print(f"[red][!] Failed to load takeover fingerprints: {e}[/red]")

def run_subfinder(domain: str) -> List[str]:
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-silent"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        return list(filter(None, result.stdout.strip().split('\n')))
    except Exception as e:
        console.print(f"[red][!] Error running subfinder: {e}[/red]")
        return []

def is_live(subdomain: str) -> bool:
    for proto in ["http://", "https://"]:
        try:
            r = requests.get(proto + subdomain, headers=HEADERS, timeout=5, allow_redirects=True, verify=False)
            if 200 <= r.status_code < 500:
                return True
        except:
            continue
    return False

def check_access_denied(body: str) -> bool:
    denied_messages = [
        "You don't have permission to access", "Access Denied", "403 Forbidden",
        "401 Unauthorized", "Forbidden", "500 Internal Server Error"
    ]
    return any(denied_message.lower() in body.lower() for denied_message in denied_messages)

def check_service(subdomain: str, service: str) -> str:
    for proto in ["http://", "https://"]:
        for path in SERVICE_PATHS[service]:
            try:
                full_url = proto + subdomain + path
                r = requests.get(full_url, headers=HEADERS, timeout=5, allow_redirects=True, verify=False)
                body = r.text.lower()
                if check_access_denied(body):
                    continue
                if r.status_code in [401, 403, 200]:
                    if any(keyword in body for keyword in SERVICE_KEYWORDS[service]):
                        return full_url
            except:
                continue
    return None

def check_takeover(subdomain: str) -> Dict:
    try:
        r = requests.get("http://" + subdomain, timeout=5, headers=HEADERS)
        content = r.text.lower()
        for fp in fingerprint_signatures:
            cname = fp.get("cname")
            if isinstance(cname, str) and cname in subdomain:
                return {
                    "service": fp.get("service", "Unknown"),
                    "issue": fp.get("fingerprint", "No fingerprint"),
                    "discussion": fp.get("discussion", "No discussion link")
                }
            elif isinstance(cname, list):
                for item in cname:
                    if item in subdomain:
                        return {
                            "service": fp.get("service", "Unknown"),
                            "issue": fp.get("fingerprint", "No fingerprint"),
                            "discussion": fp.get("discussion", "No discussion link")
                        }
            for indicator in fp.get("fingerprint", []):
                if indicator.lower() in content:
                    return {
                        "service": fp.get("service", "Unknown"),
                        "issue": fp.get("fingerprint", "No fingerprint"),
                        "discussion": fp.get("discussion", "No discussion link")
                    }
    except:
        pass
    return None

def scan_subdomain(sub: str, args) -> Dict:
    result = {"subdomain": sub, "live": False, "services": {}, "takeover": None}
    if is_live(sub):
        result["live"] = True
        for service in SERVICE_PATHS:
            if getattr(args, service, False) or args.all:
                url = check_service(sub, service)
                if url:
                    result["services"][service] = url
        if args.takeover:
            takeover = check_takeover(sub)
            if takeover:
                result["takeover"] = takeover
    return result

def main():
    parser = argparse.ArgumentParser(description="ReconX - Subdomain Scanner by Amped")
    parser.add_argument("--domain", required=True, help="Target domain")
    for s in SERVICE_PATHS:
        parser.add_argument(f"--{s}", action="store_true", help=f"Check for {s} services")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--takeover", action="store_true", help="Check for subdomain takeover")
    parser.add_argument("--json", help="Output to JSON file")
    parser.add_argument("--onlylive", action="store_true", help="Only scan for live subdomains")
    args = parser.parse_args()

    load_fingerprints()

    console.print(f"[yellow][*] Enumerating subdomains for {args.domain}...[/yellow]")
    subs = run_subfinder(args.domain)
    console.print(f"[green][+] Found {len(subs)} subdomains[/green]")

    results = []
    table = Table(title="ReconX Results", show_lines=True)
    table.add_column("Subdomain", style="bold white")
    table.add_column("Services", style="cyan")
    table.add_column("Takeover?", style="magenta")

    with Progress(SpinnerColumn(), BarColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("Scanning subdomains...", total=len(subs))
        with ThreadPoolExecutor(max_workers=150) as executor:
            futures = [executor.submit(scan_subdomain, sub, args) for sub in subs]
            for future in as_completed(futures):
                data = future.result()
                progress.advance(task)
                if args.onlylive and not data["live"]:
                    continue
                if data["live"] and (data["services"] or data["takeover"]):
                    svc_str = ", ".join([f"{k}: {v}" for k, v in data["services"].items()]) or "-"
                    if data["takeover"]:
                        takeover = f"{data['takeover']['service']} | {data['takeover']['issue']} | {data['takeover']['discussion']}"
                    else:
                        takeover = "-"
                    table.add_row(data["subdomain"], svc_str, takeover)
                    results.append(data)

    if results:
        console.print(table)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green][✔] Results saved to {args.json}[/green]")
    else:
        console.print("\n[green][✔] Scan complete[/green]")

if __name__ == "__main__":
    main()
