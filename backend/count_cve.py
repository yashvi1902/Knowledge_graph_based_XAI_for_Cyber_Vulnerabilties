import json
import pandas as pd
import re

CVE_FILE = "/Users/yashvinavadia/Desktop/CSUF/ctrp/data/merged_cves_dedup.json"   # your master CVE dataset
EXPLOIT_FILE = "/Users/yashvinavadia/Desktop/CSUF/ctrp/data/exploitdb.csv"  # or however you load it


# -------------------------------------
# 1. LOAD EXPLOITDB & EXTRACT CVE IDs
# -------------------------------------
def extract_cve_ids(codes_field):
    if pd.isna(codes_field):
        return []
    return re.findall(r"CVE-\d{4}-\d+", codes_field)

def load_exploit_cve_set(csv_path):
    df = pd.read_csv(csv_path)

    cve_set = set()

    for codes in df["codes"]:
        for cve in extract_cve_ids(codes):
            cve_set.add(cve)

    return cve_set


# -------------------------------------
# 2. CHECK IF A CVE HAS ANY CVSS SCORE
# -------------------------------------
def has_any_cvss(cve):
    cvss_section = cve.get("cvss", {})

    # check all possible metric arrays
    possible = ["cvssMetricV3", "cvssMetricV31", "cvssMetricV4"]

    for field in possible:
        metrics = cvss_section.get(field)
        if metrics and len(metrics) > 0:
            return True

    return False


# -------------------------------------
# 3. COUNT INGESTIBLE CVEs
# -------------------------------------
def count_ingestible_cves(cve_path, exploit_set):
    with open(cve_path, "r") as f:
        cve_list = json.load(f)

    count = 0

    for cve in cve_list:
        cid = cve["cve_id"]

        if cid in exploit_set and has_any_cvss(cve):
            count += 1

    return count


# -------------------------
# RUN COUNT
# -------------------------
exploit_ids = load_exploit_cve_set(EXPLOIT_FILE)
total = count_ingestible_cves(CVE_FILE, exploit_ids)

print("Total CVEs that WILL be ingested:", total)