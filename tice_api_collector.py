# tice_api_collector.py - API Calling and CLI Execution

from typing import Dict, Any, Optional
import json
import os
import time
import sys
import argparse
import re

try:
    # Ensure 'requests' is installed: pip install requests
    import requests
except Exception:
    requests = None

try:
    # Ensure 'python-dotenv' is installed: pip install python-dotenv
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: 'python-dotenv' not found. API keys must be set manually.", file=sys.stderr)

# Import processing logic from the other file
try:
    from tice_processor import process_raw_data, UNIFIED_SCHEMA
except ImportError as e:
    print(f"❌ Error: Could not import tice_processor. Details: {e}", file=sys.stderr)
    sys.exit(1)


# --- API Configuration and Handlers ---

def _safe_get(url: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None,
              timeout: float = 8.0) -> Dict[str, Any]:
    """HTTP GET wrapper that returns {'error': '...'} on failure."""
    if requests is None:
        return {"error": "requests library not available"}
    try:
        r = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
        if r.status_code >= 400:
            try:
                body = r.json()
            except Exception:
                body = r.text
            return {"error": f"HTTP {r.status_code}", "details": body}
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def get_raw_threat_data(
        ip_address: str,
        *,
        max_age_days: int = 90,
        timeout: float = 8.0
) -> Dict[str, Any]:
    """
    Fetch raw threat intel from AbuseIPDB, VirusTotal, and IPinfo for a given IP.
    API keys are read from environment variables (loaded from .env).
    """
    # Keys must match the names in your .env file
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
    virustotal_key = os.getenv("VT_API_KEY")
    ipinfo_token = os.getenv("IPINFO_TOKEN")

    results: Dict[str, Any] = {}

    # --- AbuseIPDB ---
    if abuseipdb_key:
        abuse_headers = {"Key": abuseipdb_key, "Accept": "application/json"}
        abuse_params = {"ipAddress": ip_address, "maxAgeInDays": max_age_days}
        abuse = _safe_get("https://api.abuseipdb.com/api/v2/check", headers=abuse_headers, params=abuse_params,
                          timeout=timeout)
        results["AbuseIPDB"] = abuse.get("data", abuse) # Retrieve nested data
        time.sleep(0.1)
    else:
        results["AbuseIPDB"] = {"error": "Missing ABUSEIPDB_API_KEY"}

    # --- VirusTotal (v3) ---
    if virustotal_key:
        vt_headers = {"x-apikey": virustotal_key}
        vt = _safe_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers=vt_headers,
                       timeout=timeout)
        results["VirusTotal"] = vt.get("data", vt) # Retrieve nested data
        time.sleep(0.1)
    else:
        results["VirusTotal"] = {"error": "Missing VT_API_KEY"}

    # --- IPinfo ---
    if ipinfo_token:
        ipinfo = _safe_get(f"https://ipinfo.io/{ip_address}", params={"token": ipinfo_token}, timeout=timeout)
        results["IPinfo"] = ipinfo
    else:
        results["IPinfo"] = {"error": "Missing IPINFO_TOKEN"}

    return results


def is_valid_ip(ip_address: str) -> bool:
    """Simple check for basic IPv4 format validity."""
    # Strips any trailing periods or whitespace
    ip_address = ip_address.strip().rstrip('.') 
    ipv4_regex = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    
    if re.match(ipv4_regex, ip_address):
        try:
            return all(0 <= int(octet) <= 255 for octet in ip_address.split('.'))
        except ValueError:
            return False
    return False


def display_report(report: dict):
    """Formats and prints the unified threat intelligence report."""
    print("\n" + "=" * 70)
    print(f"🕵️  THREAT INTELLIGENCE REPORT FOR: {report.get('ip_address', 'N/A')}")
    print("=" * 70)

    # --- Summary and Scores ---
    print(f"\n**SUMMARY:** {report.get('summary')}")
    print("-" * 30)
    print(f"**Reputation:** {report.get('reputation')}")
    print(f"**Severity Score:** {report.get('severity_score'):>3}/100")
    print(f"**Confidence:** {report.get('confidence_score') * 100:.0f}%")

    # --- Scoring Breakdown ---
    breakdown = report.get('score_breakdown', {})
    if breakdown and sum(breakdown.values()) > 0:
        print("\n**📊 SCORING BREAKDOWN**")
        for metric, score in breakdown.items():
            print(f"  - {metric:<25}: +{score}")

    # --- Geolocation ---
    geo = report.get('geolocation', {})
    if geo:
        print("\n**🌐 GEOLOCATION & NETWORK**")
        print(f"  Country/Region: {geo.get('country', 'N/A')} / {geo.get('region', 'N/A')}")
        print(f"  City:           {geo.get('city', 'N/A')}")
        print(f"  Organization:   {geo.get('org', 'N/A')}")
        print(f"  ASN:            {geo.get('asn', 'N/A')}")

    # --- Categories ---
    categories = report.get('categories', [])
    if categories:
        print("\n**🚨 THREAT CATEGORIES**")
        for cat in sorted(set(categories)):
            print(f"  - {cat}")

    # --- Raw Data (Optional) ---
    if os.environ.get("RICE_DEBUG") == "True":
        print("\n" + "=" * 70)
        print("🔍 RAW API RESULTS (DEBUG MODE)")
        print(json.dumps(report.get('raw_api_results', {}), indent=2))

    print("\n" + "=" * 70)


def main():
    """Main function to run the IP analysis CLI."""
    parser = argparse.ArgumentParser(
        description="RICE Threat Intelligence CLI: Collects, processes, and scores threat intel for an IP address."
    )
    parser.add_argument(
        "ip_address",
        type=str,
        help="The IPv4 address to check (e.g., 8.8.8.8)."
    )
    parser.add_argument(
        "-d", "--debug", 
        action="store_true", 
        help="Enable debug mode to display raw API responses."
    )
    
    args = parser.parse_args()
    ip_address = args.ip_address
    
    if args.debug:
        os.environ["RICE_DEBUG"] = "True"

    if not is_valid_ip(ip_address):
        print(f"❌ Error: '{ip_address}' is not a valid IPv4 address format.")
        sys.exit(1)
        
    ip_address_cleaned = ip_address.strip().rstrip('.') 
    
    print(f"Collecting threat intelligence data for {ip_address_cleaned}...")

    try:
        raw_results = get_raw_threat_data(ip_address_cleaned)
    except Exception as e:
        print(f"Critical error during API collection: {e}")
        sys.exit(1)

    if all(r.get('error', '').startswith('Missing') for r in raw_results.values()):
        print("🚨 WARNING: All API keys are missing or invalid.")
        print("Please set ABUSEIPDB_API_KEY, VT_API_KEY, and IPINFO_TOKEN environment variables to run live analysis.")
        print("--- Proceeding with processing to show key errors in raw results. ---")

    try:
        final_report = process_raw_data(ip_address_cleaned, raw_results)
    except Exception as e:
        print(f"Critical error during data processing/scoring: {e}")
        print("\n--- Raw Data Before Processing Failure ---")
        print(json.dumps(raw_results, indent=2))
        sys.exit(1)

    display_report(final_report)


if __name__ == "__main__":
    main()