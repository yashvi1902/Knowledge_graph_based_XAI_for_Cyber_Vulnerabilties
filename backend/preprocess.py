import json
import csv
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


#Load raw CVE JSON
with open(DATA_DIR / "merged_cves_dedup.json", "r", encoding="utf-8") as f:
    cves_raw = json.load(f)

# -------------------------------
# Flatten CVE table
cve_rows = []
cwe_set = set()
cve_cwe_rows = []
product_set = set()
cve_product_rows = []

for cve in cves_raw:
    cve_id = cve["cve_id"]
    cve_meta = cve["cvss"]

    metrics = cve_meta.get("metrics", {})

    cvss_v2  = None
    cvss_v3  = None
    cvss_v31 = None
    cvss_v40 = None

        # CVSS v2
    if "cvssMetricV2" in cve_meta:
        cvss_v2 = cve_meta["cvssMetricV2"][0].get("details", {}).get("baseScore") \
                or cve_meta["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

    # CVSS v3.0
    if "cvssMetricV30" in cve_meta:
        cvss_v3 = cve_meta["cvssMetricV30"][0].get("details", {}).get("baseScore") \
                or cve_meta["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")

    # CVSS v3.1
    if "cvssMetricV31" in cve_meta:
        cvss_v31 = cve_meta["cvssMetricV31"][0].get("details", {}).get("baseScore") \
                or cve_meta["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")

    # CVSS v4.0
    if "cvssMetricV40" in cve_meta:
        cvss_v40 = cve_meta["cvssMetricV40"][0].get("details", {}).get("baseScore") \
                or cve_meta["cvssMetricV40"][0].get("cvssData", {}).get("baseScore")
        
    descriptions = cve.get("descriptions", {})
    if isinstance(descriptions, dict):
        descriptions_en = descriptions.get("en")
        descriptions_es = descriptions.get("es")
    else:
        descriptions_en = descriptions_es = None

    cve_rows.append({
        "cve_id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("status"),
        "source": cve.get("source"),
        "descriptions_en":descriptions_en,
        "descriptions_es": descriptions_es,
        "custom_risk_score": cve.get("custom_risk_score"),
        "cvss_v2": cvss_v2,
        "cvss_v3": cvss_v3,
        "cvss_v31": cvss_v31,
        "cvss_v40": cvss_v40
    })
    
    # CWEs
    for cwe in cve.get("weaknesses", []):
        cwe_set.add(cwe)
        cve_cwe_rows.append({"cve_id": cve_id, "cwe": cwe})
    
    # Products from configurations
    for cpe in cve.get("configurations", []):
        product_set.add(cpe)
        cve_product_rows.append({"cve_id": cve_id, "product": cpe})

# -------------------------------
# Write CVE table (now with CVSS scores)
pd.DataFrame(cve_rows).to_csv(DATA_DIR / "cves_table.csv", index=False)
print(f" CVEs table written: {len(cve_rows)} rows")

# -------------------------------
# CWE tables
pd.DataFrame([{"cwe": c} for c in cwe_set]).to_csv(DATA_DIR / "cwe_table.csv", index=False)
pd.DataFrame(cve_cwe_rows).to_csv(DATA_DIR / "cve_has_cwe.csv", index=False)
print(f" CWE tables: {len(cwe_set)} CWEs, {len(cve_cwe_rows)} mappings")

# -------------------------------
# Products table
pd.DataFrame([{"product": p} for p in product_set]).to_csv(DATA_DIR / "products.csv", index=False)
pd.DataFrame(cve_product_rows).to_csv(DATA_DIR / "cve_affects_product.csv", index=False)
print(f" Products table: {len(product_set)} products, {len(cve_product_rows)} mappings")

# -------------------------------
# CISA KEV JSON → CSV
cisa_path = DATA_DIR / "cisa_kev.json"
if cisa_path.exists():
    with open(cisa_path, "r", encoding="utf-8") as f:
        cisa_json = json.load(f)
    
    kev_rows = []
    for item in cisa_json.get("vulnerabilities", []):
        kev_rows.append({
            "cve_id": item.get("cveID"),
            "date_added": item.get("dateAdded"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product")
        })
    pd.DataFrame(kev_rows).to_csv(DATA_DIR / "cisa_kev.csv", index=False)
    print(f" CISA KEV table: {len(kev_rows)} rows")
else:
    print(" CISA KEV JSON not found!")

# -------------------------------------------
# MITRE STIX JSON → techniques + relationships

mitre_path = DATA_DIR / "mitre_attack.json"
if mitre_path.exists():
    with open(mitre_path, "r", encoding="utf-8") as f:
        mitre_json = json.load(f)
    
    techniques_rows = []
    relations_rows = []
    
    for obj in mitre_json.get("objects", []):
        if obj.get("type") == "attack-pattern":  # techniques
            techniques_rows.append({
                "technique_id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description")
            })
        elif obj.get("type") == "relationship":
            relations_rows.append({
                "source_id": obj.get("source_ref"),
                "target_id": obj.get("target_ref"),
                "type": obj.get("relationship_type")
            })

    pd.DataFrame(techniques_rows).to_csv(DATA_DIR / "mitre_techniques.csv", index=False)
    pd.DataFrame(relations_rows).to_csv(DATA_DIR / "mitre_relations.csv", index=False)
    print(f" MITRE tables: {len(techniques_rows)} techniques, {len(relations_rows)} relations")
else:
    print(" MITRE JSON not found!")

