from neo4j import GraphDatabase
import pandas as pd
import json
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

DATA_DIR = "/Users/yashvinavadia/Desktop/CSUF/ctrp/data/"

class GraphBuilder:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

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

            # Ensure valid CPE
            if len(parts) < 13:
                print(f"Skipping invalid CPE: {cpe_uri}")
                continue

            cpe_props = {
                "cpe_uri": cpe_uri,
                "part": parts[2],               # a/o/h
                "vendor": parts[3],
                "product": parts[4],
                "version": parts[5] if parts[5] not in ["*", "-"] else 'Not Specified',
                "update": parts[6] if parts[6] not in ["*", "-"] else 'Not Specified',
            }

            tx.run("""
                MERGE (cpe:CPE {cpe_uri: $cpe_uri})
                SET 
                    cpe.part = $part,
                    cpe.vendor = $vendor,
                    cpe.product = $product,
                    cpe.version = $version,
                    cpe.update = $update,
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
        tx.run("""
            MERGE (w:CWE {cwe_id: $cwe_id})
            SET w.name = $name,
                w.abstraction = $abstraction,
                w.description = $description
        """, {
            "cwe_id": row["CWE-ID"],
            "name": row["Name"],
            "abstraction": row["Weakness Abstraction"],
            "description": row["Description"]
        })

    def ingest_kev(self, tx, kev):
        tx.run("""
            MERGE (k:KEV {cve_id: $cve_id})
            SET k.vendor = $vendor,
                k.product = $product,
                k.name = $name,
                k.date_added = $date_added,
                k.due_date = $due_date
        """, {
            "cve_id": kev["cveID"],
            "vendor": kev["vendorProject"],
            "product": kev["product"],
            "name": kev["vulnerabilityName"],
            "date_added": kev["dateAdded"],
            "due_date": kev["dueDate"]
        })

        tx.run("""
            MATCH (c:CVE {cve_id: $cve_id})
            MATCH (k:KEV {cve_id: $cve_id})
            MERGE (c)-[:LISTED_IN_KEV]->(k)
        """, {"cve_id": kev["cveID"]})

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
    # BUILD GRAPH (Main Pipeline)
    # -----------------------------------------
    def build_graph(self):
        self.load_data()

        with self.driver.session() as session:

            print("Ingesting CVEs…")
            for cve in self.cve_data:
                session.execute_write(self.ingest_cve, cve)

            print("Ingesting CWEs…")
            for _, row in self.cwe_df.iterrows():
                session.execute_write(self.ingest_cwe, row)

            print("Ingesting CISA KEV…")
            for kev in self.kev_data["vulnerabilities"]:
                session.execute_write(self.ingest_kev, kev)

            print("Ingesting ExploitDB…")
            for _, row in self.exploit_df.iterrows():
                session.execute_write(self.ingest_exploit, row)

        print("🎉 Knowledge Graph Created Successfully!")

# -----------------------------------------
# MAIN RUNNER
# -----------------------------------------
def build_knowledge_graph():
    builder = GraphBuilder(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    builder.build_graph()
    builder.close()
