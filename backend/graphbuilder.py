from neo4j import GraphDatabase
import pandas as pd
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

DATA_DIR = "/Users/yashvinavadia/Desktop/CSUF/ctrp/data/"

class GraphBuilder:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def load_csv(self, filename):
        """Helper to load CSV safely"""
        return pd.read_csv(f"{DATA_DIR}{filename}")

    def create_indexes(self):
        """Index CVE, Product, CWE, Exploit, Technique for uniqueness"""
        with self.driver.session() as session:
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (p:Product) REQUIRE p.name IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (w:CWE) REQUIRE w.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (e:Exploit) REQUIRE e.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE")

    def filter_cves(self, cves_df, cisa_df):
        """Filter CVEs to only those in CISA KEV"""
        cisa_cves = set(cisa_df["cve_id"])
        return cves_df[cves_df["cve_id"].isin(cisa_cves)]

    def build_graph(self):
        with self.driver.session() as session:
            # Load CSVs
            cves = self.load_csv("cves_table.csv")
            cisa = self.load_csv("cisa_kev.csv")
            cves = self.filter_cves(cves, cisa)  # Filter CVEs to CISA KEV
            cwe_links = self.load_csv("cve_has_cwe.csv")
            cwe_links = cwe_links[cwe_links["cve_id"].isin(cves["cve_id"])]
            product_links = self.load_csv("cve_affects_product.csv")
            product_links = product_links[product_links["cve_id"].isin(cves["cve_id"])]
            exploits = self.load_csv("exploitdb.csv")
            techniques = self.load_csv("mitre_techniques.csv")
            mitre_rel = self.load_csv("mitre_relations.csv")

            # CVE nodes
            for _, row in cves.iterrows():
                session.run("""
                    MERGE (c:CVE {id: $id})
                    SET c.published = $published,
                        c.last_modified = $last_modified,
                        c.status = $status,
                        c.source = $source,
                        c.descriptions_en = $desc_en,
                        c.descriptions_es = $desc_es,
                        c.cvss_v2 = $cvss_v2,
                        c.cvss_v3 = $cvss_v3,
                        c.cvss_v31 = $cvss_v31,
                        c.cvss_v40 = $cvss_v40,
                        c.custom_risk_score = $risk
                """, {
                    "id": row["cve_id"],
                    "published": row.get("published"),
                    "last_modified": row.get("last_modified"),
                    "status": row.get("status"),
                    "source": row.get("source"),
                    "desc_en": row.get("descriptions_en"),
                    "desc_es": row.get("descriptions_es"),
                    "cvss_v2": row.get("cvss_v2"),
                    "cvss_v3": row.get("cvss_v3"),
                    "cvss_v31": row.get("cvss_v31"),
                    "cvss_v40": row.get("cvss_v40"),
                    "risk": row.get("custom_risk_score")
                })

            # CWE nodes & relationships
            for _, row in cwe_links.iterrows():
                session.run("""
                    MERGE (c:CVE {id: $cve_id})
                    MERGE (w:CWE {id: $cwe})
                    MERGE (c)-[:HAS_CWE]->(w)
                """, {"cve_id": row["cve_id"], "cwe": row["cwe"]})

            # Product nodes & relationships
            for _, row in product_links.iterrows():
                session.run("""
                    MERGE (c:CVE {id: $cve_id})
                    MERGE (p:Product {name: $product})
                    MERGE (c)-[:AFFECTS]->(p)
                """, {"cve_id": row["cve_id"], "product": row["product"]})

            # ExploitDB nodes
            for _, row in exploits.iterrows():
                session.run("""
                    MERGE (e:Exploit {id: $id})
                    SET e.description = $desc,
                        e.date_published = $published,
                        e.author = $author,
                        e.type = $type,
                        e.platform = $platform,
                        e.verified = $verified
                """, {
                    "id": row["id"],
                    "desc": row.get("description"),
                    "published": row.get("date_published"),
                    "author": row.get("author"),
                    "type": row.get("type"),
                    "platform": row.get("platform"),
                    "verified": row.get("verified")
                })

            # CISA KEV relationships
            for _, row in cisa.iterrows():
                session.run("""
                    MERGE (c:CVE {id: $cve_id})
                    MERGE (p:Product {name: $product})
                    MERGE (c)-[:EXPLOITED_IN_WILD {date_added: $date_added, vendor: $vendor}]->(p)
                """, {
                    "cve_id": row["cve_id"],
                    "vendor": row.get("vendor"),
                    "product": row.get("product"),
                    "date_added": row.get("date_added")
                })

            # MITRE Techniques
            for _, row in techniques.iterrows():
                session.run("""
                    MERGE (t:Technique {id: $technique_id})
                    SET t.name = $name,
                        t.description = $desc
                """, {
                    "technique_id": row["technique_id"],
                    "name": row["name"],
                    "desc": row["description"]
                })

            # MITRE Relations
            for _, row in mitre_rel.iterrows():
                session.run("""
                    MERGE (s:Technique {id: $source_id})
                    MERGE (t:Technique {id: $target_id})
                    MERGE (s)-[r:RELATION {type: $type}]->(t)
                """, {
                    "source_id": row["source_id"],
                    "target_id": row["target_id"],
                    "type": row["type"]
                })

            print(" Knowledge graph successfully built (CISA KEV only)!")

# -----------------------------
# Main runner
# -----------------------------
if __name__ == "__main__":
    builder = GraphBuilder(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    builder.create_indexes()
    builder.build_graph()
    builder.close()
