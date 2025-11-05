import json
import glob
import os
from pathlib import Path

def extract_cve_data(cve_obj):
    cve = cve_obj["cve"]

    # --- Basic info ---
    cve_id = cve["id"]
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    vuln_status = cve.get("vulnStatus")
    source_identifier = cve.get("sourceIdentifier")

    # --- Descriptions ---
    descriptions = {d["lang"]: d["value"] for d in cve.get("descriptions", [])}

    # --- Weaknesses ---
    weaknesses = [w["description"][0]["value"] for w in cve.get("weaknesses", []) if w.get("description")]

    # --- Configurations (CPEs) ---
    cpes = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpes.append(match["criteria"])

    # --- References ---
    references = [{"url": ref["url"], "tags": ref.get("tags", [])} for ref in cve.get("references", [])]

    # --- CVSS Metrics ---
    metrics = cve.get("metrics", {})
    cvss_data = {}

    for version in ["cvssMetricV2", "cvssMetricV31", "cvssMetricV40"]:
        if version in metrics:
            cvss_data[version] = []
            for metric in metrics[version]:
                entry = {
                    "source": metric.get("source"),
                    "type": metric.get("type"),
                    "baseScore": metric.get("cvssData", {}).get("baseScore"),
                    "baseSeverity": metric.get("cvssData", {}).get("baseSeverity"),
                    "vectorString": metric.get("cvssData", {}).get("vectorString"),
                    "details": metric.get("cvssData", {})  # full sub-metrics for explainability
                }
                cvss_data[version].append(entry)

    return {
        "cve_id": cve_id,
        "published": published,
        "last_modified": last_modified,
        "status": vuln_status,
        "source": source_identifier,
        "descriptions": descriptions,
        "weaknesses": weaknesses,
        "configurations": cpes,
        "references": references,
        "cvss": cvss_data,
        "custom_risk_score": None
    }

def merge_and_dedup_cves(input_folder, output_file):
    all_cves = []
    unique = {}

    for file_path in glob.glob(os.path.join(input_folder, "*.json")):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for vuln in data.get("vulnerabilities", []):
                cve_entry = extract_cve_data(vuln)
                cid = cve_entry["cve_id"]

                # Deduplicate by CVE ID, keeping the one with the latest last_modified
                if cid not in unique or (cve_entry["last_modified"] or "") > (unique[cid]["last_modified"] or ""):
                    unique[cid] = cve_entry
                all_cves.append(cve_entry)

    deduped = list(unique.values())

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2, ensure_ascii=False)

    print(f" Total merged: {len(all_cves)}")
    print(f" Deduplicated: {len(deduped)} (removed {len(all_cves) - len(deduped)})")
    print(f" Saved to {output_file}")


# Example usage
if __name__ == "__main__":
    merge_and_dedup_cves(
        input_folder="/Users/yashvinavadia/Desktop/CSUF/ctrp/data/CVEyearWise",
        output_file="/Users/yashvinavadia/Desktop/CSUF/ctrp/data/merged_cves_dedup.json"
    )
