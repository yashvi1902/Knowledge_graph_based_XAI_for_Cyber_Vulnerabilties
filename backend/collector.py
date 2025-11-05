import requests
import pandas as pd
from pyattck import Attck
import os
import json
from pathlib import Path

DATA_DIR = "/Users/yashvinavadia/Desktop/CSUF/ctrp/data"
os.makedirs(DATA_DIR, exist_ok=True)


# --- 1. CISA KEV ---
def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    kev = r.json()
    out_file = os.path.join(DATA_DIR, "cisa_kev.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(kev, f, indent=2)
    print(f" Saved CISA KEV: {out_file}")


# --- 2. MITRE ATT&CK (via pyattck) ---
def fetch_mitre_attack():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    resp = requests.get(url)
    resp.raise_for_status()

    data = resp.json()

    out_path = Path(__file__).resolve().parents[1] / "data" / "mitre_attack.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"Saved MITRE ATT&CK: {out_path}")


# --- 3. ExploitDB ---
def fetch_exploitdb():
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    df = pd.read_csv(url, low_memory=False)
    out_file = os.path.join(DATA_DIR, "exploitdb.csv")
    df.to_csv(out_file, index=False)
    print(f"Saved ExploitDB: {out_file}")


if __name__ == "__main__":
    print("Fetching external datasets...")
    # fetch_cisa_kev()
    fetch_mitre_attack()
    fetch_exploitdb()
    print(" All external datasets collected")
