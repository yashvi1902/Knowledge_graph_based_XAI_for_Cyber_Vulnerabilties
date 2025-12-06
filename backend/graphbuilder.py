import os
import time
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, SessionExpired, TransientError
import pandas as pd
import json
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

DATA_DIR = "/Users/yashvinavadia/Desktop/CSUF/ctrp/data/"
CHECKPOINT_FILE = os.path.join(DATA_DIR, "kg_checkpoint.json")  # NEW


class GraphBuilder:
    def __init__(self, uri, user, password):
        # store creds so we can recreate driver on reconnect  # NEW
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.checkpoint = {
            "cve_idx": 0,
            "cwe_idx": 0,
            "kev_idx": 0,
            "exploit_idx": 0,
        }

    def close(self):
        self.driver.close()

    # -----------------------------------------
    # CHECKPOINT HELPERS (NEW)
    # -----------------------------------------
    def _load_checkpoint(self):
        if os.path.exists(CHECKPOINT_FILE):
            try:
                with open(CHECKPOINT_FILE, "r") as f:
                    self.checkpoint = json.load(f)
                    print(f"[INFO] Loaded checkpoint: {self.checkpoint}")
            except Exception as e:
                print(f"[WARN] Failed to read checkpoint file: {e}. Starting from 0.")
        else:
            print("[INFO] No checkpoint file found. Starting from 0.")

    def _save_checkpoint(self):
        try:
            with open(CHECKPOINT_FILE, "w") as f:
                json.dump(self.checkpoint, f)
            # You can comment this out if too noisy:
            print(f"[INFO] Checkpoint saved: {self.checkpoint}")
        except Exception as e:
            print(f"[WARN] Failed to write checkpoint file: {e}")

    # -----------------------------------------
    # SAFE WRITE WRAPPER (NEW)
    # -----------------------------------------
    def _safe_write(self, func, *args):
        """
        Execute a write transaction with infinite retry and automatic reconnection.
        """
        while True:
            try:
                with self.driver.session() as session:
                    return session.execute_write(func, *args)
            except (ServiceUnavailable, SessionExpired, TransientError) as e:
                print(f"[WARN] Neo4j connection error: {e}. Retrying in 5 seconds...")
                time.sleep(5)
                # Recreate driver in case it is dead
                try:
                    self.driver.close()
                except Exception:
                    pass
                self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))

    # -----------------------------------------
    # LOAD ALL DATA
    # -----------------------------------------
    def load_data(self):
        # CVE data
        with open(f"{DATA_DIR}merged_cves_dedup.json") as f:
            self.cve_data = json.load(f)

        # CWE data
        self.cwe_df = pd.read_csv(f"{DATA_DIR}merged_unique_cwe.csv")

        # CISA KEV
        with open(f"{DATA_DIR}cisa_kev.json") as f:
            self.kev_data = json.load(f)

        # ExploitDB
        self.exploit_df = pd.read_csv(f"{DATA_DIR}exploitdb.csv")

        # Create a set of all CVE IDs present in ExploitDB
        self.exploit_cve_set = set()
        for codes in self.exploit_df["codes"].dropna():
            for code in str(codes).split(";"):
                code = code.strip()
                if code.startswith("CVE-"):
                    self.exploit_cve_set.add(code)

    # -----------------------------------------
    # INGEST FUNCTIONS
    # -----------------------------------------
    def _extract_valid_cvss(self, cve: dict):
        cvss = cve.get("cvss") or {}

        def extract(metric):
            if not metric:
                return None
            m = metric[0]  # always take first metric
            details = m.get("details") or {}

            return {
                "score": m.get("baseScore"),
                "severity": m.get("baseSeverity"),
                "vector": m.get("vectorString") or details.get("vectorString"),
                "attackVector": details.get("attackVector"),
                "attackComplexity": details.get("attackComplexity"),
                "privilegesRequired": details.get("privilegesRequired"),
                "userInteraction": details.get("userInteraction"),
                "scope": details.get("scope"),
                "confidentialityImpact": details.get("confidentialityImpact"),
                "integrityImpact": details.get("integrityImpact"),
                "availabilityImpact": details.get("availabilityImpact"),
            }

        # PRIORITY: v4.0 → v3.1 → v3.0
        if cvss.get("cvssMetricV40"):
            return extract(cvss["cvssMetricV40"]), "v4_0"

        if cvss.get("cvssMetricV31"):
            return extract(cvss["cvssMetricV31"]), "v3_1"

        if cvss.get("cvssMetricV30"):
            return extract(cvss["cvssMetricV30"]), "v3_0"

        return None, None

    def ingest_cve(self, tx, cve):
        cve_id = cve["cve_id"]

        # --- Filter: ExploitDB only ---
        if cve_id not in self.exploit_cve_set:
            return

        # --- Extract CVSS data (v4 or v3 only) ---
        cvss_props, version_key = self._extract_valid_cvss(cve)
        if not cvss_props or cvss_props["score"] is None:
            return  # skip if no v4/v3 scores

        # --- Build property map ---
        props = {
            "cve_id": cve_id,
            "published": cve.get("published"),
            "last_modified": cve.get("last_modified"),
            "status": cve.get("status"),
            "source": cve.get("source"),
            "desc_en": cve.get("descriptions", {}).get("en"),
            "desc_es": cve.get("descriptions", {}).get("es"),

            # CVSS main
            "cvss_version": version_key,
            "cvss_score": cvss_props["score"],
            "cvss_severity": cvss_props["severity"],
            "cvss_vector": cvss_props["vector"],

            # CVSS full details
            "cvss_attackVector": cvss_props["attackVector"],
            "cvss_attackComplexity": cvss_props["attackComplexity"],
            "cvss_privilegesRequired": cvss_props["privilegesRequired"],
            "cvss_userInteraction": cvss_props["userInteraction"],
            "cvss_scope": cvss_props["scope"],
            "cvss_confidentialityImpact": cvss_props["confidentialityImpact"],
            "cvss_integrityImpact": cvss_props["integrityImpact"],
            "cvss_availabilityImpact": cvss_props["availabilityImpact"]
        }

        # --- Save CVE node ---
        tx.run("""
            MERGE (c:CVE {cve_id: $cve_id})
            SET c.published = $published,
                c.last_modified = $last_modified,
                c.status = $status,
                c.source = $source,
                c.description_en = $desc_en,
                c.description_es = $desc_es,

                c.cvss_version = $cvss_version,
                c.cvss_score = $cvss_score,
                c.cvss_severity = $cvss_severity,
                c.cvss_vector = $cvss_vector,

                c.cvss_attackVector = $cvss_attackVector,
                c.cvss_attackComplexity = $cvss_attackComplexity,
                c.cvss_privilegesRequired = $cvss_privilegesRequired,
                c.cvss_userInteraction = $cvss_userInteraction,
                c.cvss_scope = $cvss_scope,
                c.cvss_confidentialityImpact = $cvss_confidentialityImpact,
                c.cvss_integrityImpact = $cvss_integrityImpact,
                c.cvss_availabilityImpact = $cvss_availabilityImpact
        """, props)

        # CWEs
        for w in cve.get("weaknesses", []):
            tx.run("""
                MERGE (c:CVE {cve_id: $cve_id})
                MERGE (w:CWE {cwe_id: $cwe_id})
                MERGE (c)-[:HAS_WEAKNESS]->(w)
            """, {"cve_id": cve_id, "cwe_id": w})

        # CPEs
        for cpe_uri in cve.get("configurations", []):
            parts = cpe_uri.split(":")

            # CPE 2.3 must have at least 13 components
            if len(parts) < 13:
                print(f"Skipping invalid CPE: {cpe_uri}")
                continue

            def norm(v):
                return v if v not in ["*", "-"] else "Not Specified"

            cpe_props = {
                "cpe_uri": cpe_uri,
                "part": norm(parts[2]),
                "vendor": norm(parts[3]),
                "product": norm(parts[4]),
                "version": norm(parts[5]),
                "update": norm(parts[6]),
                "edition": norm(parts[7]),
                "language": norm(parts[8]),
                "sw_edition": norm(parts[9]),
                "target_sw": norm(parts[10]),
                "target_hw": norm(parts[11]),
                "other": norm(parts[12]),
            }

            tx.run("""
                MERGE (cpe:CPE {cpe_uri: $cpe_uri})
                SET 
                    cpe.part = $part,
                    cpe.vendor = $vendor,
                    cpe.product = $product,
                    cpe.version = $version,
                    cpe.update = $update,
                    cpe.edition = $edition,
                    cpe.language = $language,
                    cpe.sw_edition = $sw_edition,
                    cpe.target_sw = $target_sw,
                    cpe.target_hw = $target_hw,
                    cpe.other = $other
                WITH cpe
                MERGE (c:CVE {cve_id: $cve_id})
                MERGE (c)-[:AFFECTS]->(cpe)
            """, {**cpe_props, "cve_id": cve_id})

        # References
        for ref in cve.get("references", []):
            tx.run("""
                MERGE (r:Reference {url: $url})
                SET r.tags = $tags
                MERGE (c:CVE {cve_id: $cve_id})
                MERGE (c)-[:HAS_REFERENCE]->(r)
            """, {"cve_id": cve_id, "url": ref["url"], "tags": ref.get("tags", [])})

    def ingest_cwe(self, tx, row):
        # Normalize CWE-ID to "CWE-71" style
        raw_id = str(row["CWE-ID"]).strip()
        if not raw_id:
            return

        if raw_id.startswith("CWE-"):
            cwe_id = raw_id
        else:
            cwe_id = f"CWE-{raw_id}"

        tx.run("""
            MERGE (w:CWE {cwe_id: $cwe_id})
            SET w.name = $name,
                w.abstraction = $abstraction,
                w.description = $description
        """, {
            "cwe_id": cwe_id,
            "name": row["Name"],
            "abstraction": row["Weakness Abstraction"],
            "description": row["Description"]
        })


    def ingest_kev(self, tx, kev):
        """
        Ingest a single CISA KEV entry and link it to the CVE node.
        """
        tx.run(
            """
            MERGE (k:KEV {cve_id: $cve_id})
            SET k.vendor                         = $vendor,
                k.product                        = $product,
                k.name                           = $name,
                k.date_added                     = $date_added,
                k.due_date                       = $due_date,
                k.short_description              = $short_description,
                k.required_action                = $required_action,
                k.known_ransomware_campaign_use  = $known_ransomware_campaign_use,
                k.notes                          = $notes,
                k.cwes                           = $cwes
            """,
            {
                "cve_id": kev["cveID"],
                "vendor": kev.get("vendorProject"),
                "product": kev.get("product"),
                "name": kev.get("vulnerabilityName"),
                "date_added": kev.get("dateAdded"),
                "due_date": kev.get("dueDate"),
                "short_description": kev.get("shortDescription"),
                "required_action": kev.get("requiredAction"),
                "known_ransomware_campaign_use": kev.get("knownRansomwareCampaignUse"),
                "notes": kev.get("notes"),
                "cwes": kev.get("cwes"),
            },
        )

        tx.run(
            """
            MATCH (c:CVE {cve_id: $cve_id})
            MATCH (k:KEV {cve_id: $cve_id})
            MERGE (c)-[:LISTED_IN_KEV]->(k)
            """,
            {"cve_id": kev["cveID"]},
        )


    def ingest_exploit(self, tx, row):
        tx.run("""
            MERGE (e:Exploit {exploitdb_id: $id})
            SET e.file = $file,
                e.description = $desc,
                e.date_published = $date_published,
                e.author = $author,
                e.platform = $platform,
                e.port = $port
        """, {
            "id": row["id"],
            "file": row["file"],
            "desc": row["description"],
            "date_published": row["date_published"],
            "author": row["author"],
            "platform": row["platform"],
            "port": row["port"]
        })

        # Link exploits → CVEs
        if "codes" in row and pd.notna(row["codes"]):
            for code in str(row["codes"]).split(";"):
                code = code.strip()
                if code.startswith("CVE-"):
                    tx.run("""
                        MATCH (e:Exploit {exploitdb_id: $id})
                        MERGE (c:CVE {cve_id: $cve})
                        MERGE (e)-[:EXPLOITS]->(c)
                        MERGE (c)-[:HAS_EXPLOIT]->(e)
                    """, {"id": row["id"], "cve": code})

    # -----------------------------------------
    # BUILD GRAPH (Main Pipeline)  — UPDATED TO USE CHECKPOINTS
    # -----------------------------------------
    def build_graph(self):
        self.load_data()
        self._load_checkpoint()

        try:
            # # Ingest CVEs
            # print("Ingesting CVEs…")
            # total_cves = len(self.cve_data)
            # for idx in range(self.checkpoint["cve_idx"], total_cves):
            #     cve = self.cve_data[idx]
            #     self._safe_write(self.ingest_cve, cve)
            #     self.checkpoint["cve_idx"] = idx + 1
            #     if idx % 100 == 0:  # save every 100 records (tune as you like)
            #         self._save_checkpoint()

            # Ingest CWEs
            print("Ingesting CWEs…")
            total_cwes = len(self.cwe_df)
            for idx in range(self.checkpoint["cwe_idx"], total_cwes):
                row = self.cwe_df.iloc[idx]
                self._safe_write(self.ingest_cwe, row)
                self.checkpoint["cwe_idx"] = idx + 1
                if idx % 100 == 0:
                    self._save_checkpoint()

            # Ingest CISA KEV
            # print("Ingesting CISA KEV…")
            # kev_list = self.kev_data["vulnerabilities"]
            # total_kev = len(kev_list)
            # for idx in range(self.checkpoint["kev_idx"], total_kev):
            #     kev = kev_list[idx]
            #     self._safe_write(self.ingest_kev, kev)
            #     self.checkpoint["kev_idx"] = idx + 1
            #     if idx % 100 == 0:
            #         self._save_checkpoint()

            # Ingest ExploitDB
            # print("Ingesting ExploitDB…")
            # total_exploits = len(self.exploit_df)
            # for idx in range(self.checkpoint["exploit_idx"], total_exploits):
            #     row = self.exploit_df.iloc[idx]
            #     self._safe_write(self.ingest_exploit, row)
            #     self.checkpoint["exploit_idx"] = idx + 1
            #     if idx % 100 == 0:
            #         self._save_checkpoint()

            # Final save
            self._save_checkpoint()
            print("🎉 Knowledge Graph Created Successfully!")

        except KeyboardInterrupt:
            print("\n[INFO] Interrupted by user, saving checkpoint...")
            self._save_checkpoint()
            raise


# -----------------------------------------
# MAIN RUNNER
# -----------------------------------------
def build_knowledge_graph():
    builder = GraphBuilder(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    try:
        builder.build_graph()
    finally:
        builder.close()
