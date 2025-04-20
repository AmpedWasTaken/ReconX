import subprocess
import requests
import sys
import json
import os
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

class Config:
    def __init__(self):
        self.settings = self._load_json("config/settings.json")
        self.services = self._load_json("config/services.json")
        
        # Initialize from settings
        self.headers = self.settings.get("headers", {})
        self.timeout = self.settings.get("timeout", 5)
        self.max_workers = self.settings.get("max_workers", 150)
        self.fingerprints_url = self.settings.get("fingerprints_url", "")
        self.access_denied_messages = self.settings.get("access_denied_messages", [])
        
        # Initialize service-related data
        self.service_paths = {service: data["paths"] for service, data in self.services.items()}
        self.service_keywords = {service: data["keywords"] for service, data in self.services.items()}

    def _load_json(self, path: str) -> Dict:
        try:
            if not os.path.exists(path):
                console.print(f"[red][!] Configuration file not found: {path}[/red]")
                return {}
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[red][!] Error loading configuration file {path}: {e}[/red]")
            return {}

    def get_all_services(self) -> List[str]:
        return list(self.services.keys())

# Global configuration
config = Config()
fingerprint_signatures = []

def load_fingerprints():
    global fingerprint_signatures
    try:
        res = requests.get(config.fingerprints_url)
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
            r = requests.get(proto + subdomain, headers=config.headers, timeout=config.timeout, allow_redirects=True, verify=False)
            if 200 <= r.status_code < 500:
                return True
        except:
            continue
    return False

def check_access_denied(body: str) -> bool:
    return any(denied_message.lower() in body.lower() for denied_message in config.access_denied_messages)

def check_service(subdomain: str, service: str) -> str:
    for proto in ["http://", "https://"]:
        for path in config.service_paths[service]:
            try:
                full_url = proto + subdomain + path
                r = requests.get(full_url, headers=config.headers, timeout=config.timeout, allow_redirects=True, verify=False)
                body = r.text.lower()
                if check_access_denied(body):
                    continue
                if r.status_code in [401, 403, 200]:
                    if any(keyword in body for keyword in config.service_keywords[service]):
                        return full_url
            except:
                continue
    return None

def check_takeover(subdomain: str) -> Dict:
    try:
        r = requests.get("http://" + subdomain, timeout=config.timeout, headers=config.headers)
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
        for service in config.get_all_services():
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
    for service in config.get_all_services():
        parser.add_argument(f"--{service}", action="store_true", help=f"Check for {service} services")
    parser.add_argument("--all", action="store_true", help="Check all services")
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
        with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
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
