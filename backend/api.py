from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase

from backend.config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

# -----------------------------
# Neo4j driver (shared)
# -----------------------------
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI(title="CVE Knowledge Graph API")

# Allow frontend (adjust origins later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # during dev; tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Helpers
# -----------------------------
def node_to_dict(node):
    """Convert a Neo4j Node to a plain dict."""
    if node is None:
        return None
    d = dict(node)  # properties
    # You can also include labels if useful
    d["labels"] = list(node.labels)
    return d

def clean_cpe_node(cpe_node):
    """
    Convert a CPE Neo4j node to a dict and drop any fields that are
    'not specified', '*', '-', empty, or None. Keeps labels.
    """
    if cpe_node is None:
        return None

    raw = node_to_dict(cpe_node)   # includes properties + labels
    labels = raw.pop("labels", []) # keep labels separate

    cleaned_props = {}

    INVALID_STRINGS_LOWER = {
        "not specified",
        "n/a",
        "none",
        "",          # empty after strip
    }
    INVALID_EXACT = {"*", "-"}

    for key, value in raw.items():
        # Always keep non-scalar stuff (just in case), but most CPE fields are strings
        if value is None:
            continue

        if isinstance(value, str):
            v = value.strip()
            # Skip clearly non-real values
            if v.lower() in INVALID_STRINGS_LOWER:
                continue
            if v in INVALID_EXACT:
                continue
            # If it survives the checks, keep it
            cleaned_props[key] = v
        else:
            # Non-string values (if any) are kept as-is
            cleaned_props[key] = value

    # If nothing meaningful remains, you can decide whether to drop this CPE entirely
    if not cleaned_props:
        return None

    cleaned_props["labels"] = labels
    return cleaned_props


# -----------------------------
# Lifespan events
# -----------------------------
@app.on_event("shutdown")
def shutdown_event():
    driver.close()


# -----------------------------
# Endpoints
# -----------------------------

@app.get("/health")
def health_check():
    """Simple health check."""
    # Optionally ping Neo4j
    try:
        with driver.session() as session:
            session.run("RETURN 1").single()
        return {"status": "ok", "neo4j": "connected"}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}


@app.get("/api/cve/{cve_id}")
def get_cve(cve_id: str):
    """
    Return one CVE with its related CWEs, CPEs, Exploits, KEV info.
    """
    with driver.session() as session:
        result = session.run(
            """
            MATCH (c:CVE {cve_id: $cve_id})
            OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(w:CWE)
            OPTIONAL MATCH (c)-[:AFFECTS]->(cpe:CPE)
            RETURN c,
                   collect(DISTINCT w)   AS cwes,
                   collect(DISTINCT cpe) AS cpes
            """,
            {"cve_id": cve_id},
        ).single()

    if not result:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    cve_node = result["c"]
    cwes = result["cwes"]
    cpes = result["cpes"]
    # exploits = result["exploits"]
    # kev_list = result["kev_list"]
    
    cleaned_cpes = []
    for cpe in cpes:
        if cpe is None:
            continue
        cleaned = clean_cpe_node(cpe)
        if cleaned is not None:
            cleaned_cpes.append(cleaned)

    return {
        "cve": node_to_dict(cve_node),
        "cwes": [node_to_dict(w) for w in cwes if w is not None],
        "cpes": cleaned_cpes,
        # "exploits": [node_to_dict(e) for e in exploits if e is not None],
        # "kev": node_to_dict(kev_list[0]) if kev_list else None,
    }


@app.get("/api/cves")
def list_cves(page: int = 1, page_size: int = 20):
    """
    Basic CVE list for the Explorer table.
    (You can add filters later: severity, cvss_version, vendor, product, etc.)
    """
    skip = (page - 1) * page_size

    with driver.session() as session:
        # Get total count
        total_res = session.run("MATCH (c:CVE) RETURN count(c) AS total").single()
        total = total_res["total"]

        # Get page of CVEs
        records = session.run(
            """
            MATCH (c:CVE)
            RETURN c
            ORDER BY c.published
            SKIP $skip
            LIMIT $limit
            """,
            {"skip": skip, "limit": page_size},
        )

        items = []
        for rec in records:
            c = rec["c"]
            data = dict(c)
            items.append(
                {
                    "cve_id": data.get("cve_id"),
                    "published": data.get("published"),
                    "last_modified": data.get("last_modified"),
                    "status": data.get("status"),
                    "source": data.get("source"),
                    # "cvss_score": data.get("cvss_score"),
                    # "cvss_severity": data.get("cvss_severity"),
                    # "cvss_version": data.get("cvss_version"),
                }
            )

    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "results": items,
    }


@app.get("/api/stats/overview")
def stats_overview():
    """
    Simple stats for homepage cards.
    """
    with driver.session() as session:
        cve_total = session.run("MATCH (c:CVE) RETURN count(c) AS n").single()["n"]
        exploit_total = session.run(
            """
            MATCH (c:CVE)-[:HAS_EXPLOIT]->(:Exploit)
            RETURN count(DISTINCT c) AS n
            """
        ).single()["n"]
        product_total = session.run(
            "MATCH (cpe:CPE) RETURN count(DISTINCT cpe.product) AS n"
        ).single()["n"]
        vendor_total = session.run(
            "MATCH (cpe:CPE) RETURN count(DISTINCT cpe.vendor) AS n"
        ).single()["n"]

    return {
        "total_cves": cve_total,
        "cves_with_exploits": exploit_total,
        "products": product_total,
        "vendors": vendor_total,
    }
