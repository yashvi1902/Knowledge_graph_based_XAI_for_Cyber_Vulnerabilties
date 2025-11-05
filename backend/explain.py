# backend/explain.py
import math
from neo4j import GraphDatabase
from openai import OpenAI
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, OPENROUTER_API_KEY

OPENROUTER_MODEL = "nvidia/nemotron-nano-9b-v2:free"

class CVEExplainer:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.client = OpenAI(api_key=OPENROUTER_API_KEY, base_url="https://openrouter.ai/api/v1")

    def close(self):
        self.driver.close()

    def get_dynamic_cvss(self, record):
        """Return the first non-NaN CVSS value"""
        for key in ["cvss_v40", "cvss_v31", "cvss_v3", "cvss_v2"]:
            value = record.get(key)
            if value is not None and not (isinstance(value, float) and math.isnan(value)):
                return value
        return "N/A"

    def fetch_cve_details(self, cve_id):
        """Fetch CVE node details from Neo4j including exploited info and MITRE relations"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (c:CVE {id: $cve_id})
                OPTIONAL MATCH (c)-[:HAS_CWE]->(w:CWE)
                OPTIONAL MATCH (c)-[:AFFECTS]->(p:Product)
                OPTIONAL MATCH (c)-[e:EXPLOITED_IN_WILD]->(prod:Product)
                OPTIONAL MATCH (c)-[:HAS_CWE]->(w2:CWE)-[:RELATION]->(t:Technique)
                OPTIONAL MATCH (t)-[r:RELATION]->(t2:Technique)
                RETURN c,
                       collect(DISTINCT w.id) AS cwes,
                       collect(DISTINCT p.name) AS products,
                       collect(DISTINCT {vendor: e.vendor, date: e.date_added, product: prod.name}) AS exploited_info,
                       collect(DISTINCT {technique: t.name, related: t2.name, relation_type: r.type}) AS technique_relations
            """, {"cve_id": cve_id})

            record = result.single()
            if record:
                cve_data = dict(record["c"])
                cve_data["cwes"] = record["cwes"]
                cve_data["products"] = record["products"]
                cve_data["exploited_info"] = record["exploited_info"]
                cve_data["technique_relations"] = record["technique_relations"]
                cve_data["dynamic_cvss"] = self.get_dynamic_cvss(cve_data)
                return cve_data
            return None

    def generate_llm_explanation(self, cve_data):
        """Use Nemotron Nano 9B to generate explanation"""
        exploited_str = ", ".join([f"{x['vendor']} ({x['product']}) on {x['date']}" for x in cve_data.get("exploited_info", [])])
        technique_str = ", ".join([f"{x['technique']} -> {x['related']} ({x['relation_type']})" for x in cve_data.get("technique_relations", [])])

        prompt = f"""
        Explain this vulnerability in simple terms for a security analyst:

        CVE ID: {cve_data['id']}
        CVSS Score: {cve_data['dynamic_cvss']}
        Description: {cve_data.get('descriptions_en', 'N/A')}
        Status: {cve_data.get('status')}
        Source: {cve_data.get('source')}
        Affected Products: {', '.join(cve_data.get('products', []))}
        Related CWEs: {', '.join(cve_data.get('cwes', []))}
        Exploited in the Wild: {exploited_str or 'None'}
        Related MITRE Techniques and Relations: {technique_str or 'None'}
        
        answer pattern to follow:
        cvss score : <cvss_score>
        status : <status>
        source : <source>
        affected products : <affected_products>
        related cwes : <related_cwes>
        exploited in wild : <exploited_in_wild>
        mitre techniques : <mitre_techniques>
        <new paragraph>
        description : <description>
        <new paragraph>
        reasoning : <concise explanation of why this vulnerability has a specific severe/non-severe score based on data>
        <new paragraph>
        mitigation steps : <possible mitigation steps>
        
        Note : Avoid using bold words. Give possible reasonings from the data provided. do not mention lines like - "Certainly! Here's a simplified explanation of **CVE-2020-0646** for a security analyst:" in the response. Just pure explanation.
        """

        response = self.client.chat.completions.create(
            model=OPENROUTER_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content

    def explain_cve(self, cve_id):
        cve_data = self.fetch_cve_details(cve_id)
        if not cve_data:
            return {"error": "CVE not found"}

        explanation = {
            "cve_id": cve_id,
            "cvss_score": cve_data["dynamic_cvss"],
            "description": cve_data.get("descriptions_en", "No description available"),
            "status": cve_data.get("status"),
            "source": cve_data.get("source"),
            "affected_products": cve_data.get("products"),
            "related_cwes": cve_data.get("cwes"),
            "exploited_in_wild": cve_data.get("exploited_info"),
            "mitre_techniques": cve_data.get("technique_relations"),
            "llm_summary": self.generate_llm_explanation(cve_data)
        }
        return explanation


# -----------------------------
# Test / CLI usage
# -----------------------------
if __name__ == "__main__":
    explainer = CVEExplainer()
    cve_id_test = "CVE-2020-3118"
    result = explainer.explain_cve(cve_id_test)
    print(result["llm_summary"])
    explainer.close()


# Possible updates :
# 1. Dynamic reasoning hints – include CVSS components (Impact/Exploitability metrics) in the prompt for more precise reasoning.