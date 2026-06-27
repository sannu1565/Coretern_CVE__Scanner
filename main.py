import requests
import time
import csv
import json
import os
from datetime import datetime

# ── Config ─────────────────────────────────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
RATE_LIMIT_SLEEP = 1.5   # seconds between requests (public limit: 5 req/30 s)
RESULTS_PER_PAGE = 10

# ── NVD API ────────────────────────────────────────────────────────────────────
def search_cves(product: str, version: str, retries: int = 3) -> dict:
    """Query the NVD API for CVEs matching product + version.
    Retries up to `retries` times on 503 Service Unavailable."""
    query = f"{product} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": RESULTS_PER_PAGE,
    }
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(
                NVD_API_URL, params=params, headers=HEADERS, timeout=10
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 503:
                wait = attempt * 5
                print(f"[!] NVD unavailable (503) — retrying in {wait}s… (attempt {attempt}/{retries})")
                time.sleep(wait)
            elif response.status_code == 403:
                print(f"[!] 403 Forbidden — set NVD_API_KEY environment variable for access.")
                return {}
            else:
                print(f"[!] API Error: {response.status_code} – {response.text[:120]}")
                return {}
        except requests.RequestException as e:
            print(f"[!] Request error: {e}")
            return {}
    print(f"[!] Failed after {retries} attempts. NVD may be down — try again later.")
    return {}


def parse_cve_results(data: dict) -> list[tuple]:
    """Extract (cve_id, severity, description) tuples from raw NVD response."""
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        desc = cve["descriptions"][0]["value"]
        severity = "N/A"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "N/A")
        elif "cvssMetricV30" in metrics:
            severity = metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity", "N/A")
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            severity = m.get("baseSeverity") or m["cvssData"].get("baseSeverity", "N/A")
        results.append((cve_id, severity, desc))
    return results


# ── Output ─────────────────────────────────────────────────────────────────────
def print_results(product: str, version: str, cves: list[tuple]) -> None:
    """Pretty-print CVE results to stdout."""
    print(f"\n{'─' * 60}")
    print(f"  {product} {version}")
    print(f"{'─' * 60}")
    if not cves:
        print("  ✔  No known CVEs found for this software and version.")
        return
    for cve_id, severity, desc in cves:
        badge = f"[{severity}]".ljust(12)
        print(f"\n  {badge} {cve_id}")
        print(f"  ↳ {desc[:150]}{'…' if len(desc) > 150 else ''}")


def save_results_json(all_results: list[dict], path: str = "data/results.json") -> None:
    """Persist all scan results to JSON."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "results": all_results,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n[✔] Results saved → {path}")


# ── Entry points ───────────────────────────────────────────────────────────────
def scan_one(product: str, version: str) -> list[tuple]:
    """Scan a single product/version and return CVE tuples."""
    print(f"\n🔍 Scanning: {product} {version}")
    data = search_cves(product, version)
    cves = parse_cve_results(data)
    print_results(product, version, cves)
    return cves


def scan_from_file(filepath: str = "data/software_list.txt") -> None:
    """Read a CSV of product,version pairs and scan each one."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return

    all_results = []
    print(f"=== CVE Scanner — batch mode ===")
    print(f"    Source: {filepath}\n")

    with open(filepath, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            product = row[0].strip()
            version = row[1].strip() if len(row) > 1 else ""
            cves = scan_one(product, version)
            all_results.append({
                "product": product,
                "version": version,
                "cves": [
                    {"id": c[0], "severity": c[1], "description": c[2]}
                    for c in cves
                ],
            })
            time.sleep(RATE_LIMIT_SLEEP)

    save_results_json(all_results)


def main() -> None:
    """Interactive single-scan mode."""
    print("=== CVE Scanner ===")
    product = input("Enter software/product name: ").strip()
    version = input("Enter version number: ").strip()
    scan_one(product, version)
    time.sleep(RATE_LIMIT_SLEEP)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--batch":
        filepath = sys.argv[2] if len(sys.argv) > 2 else "data/software_list.txt"
        scan_from_file(filepath)
    else:
        main()