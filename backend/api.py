from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase
from typing import List, Dict, Any
import math

from backend.llm_api import router as llm_router
from backend.config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

# -----------------------------
# Neo4j driver (shared)
# -----------------------------
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI(title="CVE Knowledge Graph API")

# Include LLM router under /api
app.include_router(llm_router, prefix="/api")

# CORS so React (localhost:5173) can call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Helpers
# -----------------------------


def node_to_dict(node):
    """Convert a Neo4j Node to a plain dict, sanitizing NaN/inf."""
    if node is None:
        return None

    d = dict(node)  # properties
    d["labels"] = list(node.labels)

    # sanitize any float NaN / inf values so JSON doesn't explode
    for key, value in list(d.items()):
        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                d[key] = None
        elif isinstance(value, list):
            cleaned_list = []
            for item in value:
                if isinstance(item, float) and (math.isnan(item) or math.isinf(item)):
                    cleaned_list.append(None)
                else:
                    cleaned_list.append(item)
            d[key] = cleaned_list

    return d


def clean_cpe_node(cpe_node):
    """
    Convert a CPE Neo4j node to a dict and drop any fields that are
    'not specified', '*', '-', empty, or None. Keeps labels.
    """
    if cpe_node is None:
        return None

    raw = node_to_dict(cpe_node)  # includes properties + labels
    if raw is None:
        return None

    labels = raw.pop("labels", [])  # keep labels separate

    cleaned_props = {}

    INVALID_STRINGS_LOWER = {
        "not specified",
        "n/a",
        "none",
        "",  # empty after strip
    }
    INVALID_EXACT = {"*", "-"}

    for key, value in raw.items():
        if value is None:
            continue

        if isinstance(value, str):
            v = value.strip()
            # Skip clearly non-real values
            if v.lower() in INVALID_STRINGS_LOWER:
                continue
            if v in INVALID_EXACT:
                continue
            cleaned_props[key] = v
        else:
            cleaned_props[key] = value

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
            OPTIONAL MATCH (c)-[:HAS_EXPLOIT]->(e:Exploit)
            OPTIONAL MATCH (c)-[:LISTED_IN_KEV]->(k:KEV)
            RETURN c,
                   collect(DISTINCT w)   AS cwes,
                   collect(DISTINCT cpe) AS cpes,
                   collect(DISTINCT e)   AS exploits,
                   collect(DISTINCT k)   AS kev_list
            """,
            {"cve_id": cve_id},
        ).single()

    if not result:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    cve_node = result["c"]
    cwes = result["cwes"] or []
    cpes = result["cpes"] or []
    exploits = result["exploits"] or []
    kev_list = result["kev_list"] or []

    cleaned_cpes = []
    for cpe in cpes:
        if cpe is None:
            continue
        cleaned = clean_cpe_node(cpe)
        if cleaned is not None:
            cleaned_cpes.append(cleaned)

    kev = node_to_dict(kev_list[0]) if kev_list else None

    return {
        "cve": node_to_dict(cve_node),
        "cwes": [node_to_dict(w) for w in cwes if w is not None],
        "cpes": cleaned_cpes,
        "exploits": [node_to_dict(e) for e in exploits if e is not None],
        "kev": kev,
    }


@app.get("/api/cves")
def list_cves(page: int = 1, page_size: int = 20):
    """
    Basic CVE list for the Explorer table.
    """
    skip = (page - 1) * page_size

    with driver.session() as session:
        total_res = session.run("MATCH (c:CVE) RETURN count(c) AS total").single()
        total = total_res["total"]

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
                    "cvss_score": data.get("cvss_score"),
                    "cvss_severity": data.get("cvss_severity"),
                    "cvss_version": data.get("cvss_version"),
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
        cve_total = session.run(
            "MATCH (c:CVE) RETURN count(c) AS n"
        ).single()["n"]

        product_total = session.run(
            "MATCH (cpe:CPE) RETURN count(DISTINCT cpe.product) AS n"
        ).single()["n"]

        vendor_total = session.run(
            "MATCH (cpe:CPE) RETURN count(DISTINCT cpe.vendor) AS n"
        ).single()["n"]

        refs_total = session.run(
            "MATCH (c:CVE)-[:HAS_REFERENCE]->() RETURN count(DISTINCT c) AS n"
        ).single()["n"]

        exploit_total = session.run(
            """
            MATCH (c:CVE)-[:HAS_EXPLOIT]->(:Exploit)
            RETURN count(DISTINCT c) AS n
            """
        ).single()["n"]

    return {
        "total_cves": cve_total,
        "cves_with_exploits": exploit_total,
        "products": product_total,
        "vendors": vendor_total,
        "cves_with_references": refs_total,
    }


@app.get("/api/cves/with-references")
def get_cves_with_references(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """
    CVEs that have a non-empty references array.
    """
    skip = (page - 1) * page_size

    with driver.session() as session:
        total_res = session.run(
            """
            MATCH (c:CVE)
            WHERE exists(c.references) AND size(c.references) > 0
            RETURN count(c) AS total
            """
        ).single()
        total = total_res["total"] if total_res else 0

        result = session.run(
            """
            MATCH (c:CVE)
            WHERE exists(c.references) AND size(c.references) > 0
            RETURN
              c.cve_id     AS cve_id,
              c.status     AS status,
              c.source     AS source,
              c.references AS references,
              c.published  AS published
            ORDER BY c.published DESC
            SKIP $skip
            LIMIT $limit
            """,
            skip=skip,
            limit=page_size,
        )

        rows = [r.data() for r in result]

    return {"results": rows, "total": total, "page": page, "page_size": page_size}


@app.get("/api/vendors")
def get_unique_vendors():
    with driver.session() as session:
        result = session.run(
            """
            MATCH (c:CVE)-[:AFFECTS]->(cpe:CPE)
            WHERE cpe.vendor IS NOT NULL AND cpe.vendor <> ""
            RETURN DISTINCT cpe.vendor AS vendor
            ORDER BY vendor
            """
        )
        vendors = [r["vendor"] for r in result]

    return {"vendors": vendors, "total": len(vendors)}


@app.get("/api/products")
def get_unique_products():
    with driver.session() as session:
        result = session.run(
            """
            MATCH (c:CVE)-[:AFFECTS]->(cpe:CPE)
            WHERE cpe.product IS NOT NULL AND cpe.product <> ""
            RETURN DISTINCT cpe.product AS product
            ORDER BY product
            """
        )
        products = [r["product"] for r in result]

    return {"products": products, "total": len(products)}


@app.get("/api/cves/with-exploits")
def get_cves_with_exploits(page: int = 1, page_size: int = 50):
    skip = (page - 1) * page_size

    with driver.session() as session:
        total_res = session.run(
            """
            MATCH (c:CVE)-[:HAS_EXPLOIT]->(:Exploit)
            RETURN count(DISTINCT c) AS total
            """
        ).single()
        total = total_res["total"] if total_res else 0

        result = session.run(
            """
            MATCH (c:CVE)-[:HAS_EXPLOIT]->(e:Exploit)
            WITH c, collect(DISTINCT e.exploit_id) AS exploit_ids
            RETURN
              c.cve_id        AS cve_id,
              c.status        AS status,
              c.source        AS source,
              c.published     AS published,
              c.cvss_score    AS cvss_score,
              c.cvss_severity AS cvss_severity,
              exploit_ids     AS exploits
            ORDER BY c.published DESC
            SKIP $skip
            LIMIT $limit
            """,
            skip=skip,
            limit=page_size,
        )

        rows = [r.data() for r in result]

    return {
        "results": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@app.get("/api/graph/overview")
def graph_overview(limit: int = 200):
    """
    Return a small subgraph for visualization on the homepage.
    Each node in the JSON includes *all* properties from Neo4j,
    with NaN/inf sanitized via node_to_dict.
    """
    with driver.session() as session:
        result = session.run(
            """
            MATCH (c:CVE)-[r:HAS_WEAKNESS|AFFECTS|HAS_EXPLOIT|LISTED_IN_KEV]->(n)
            WITH c, r, n
            LIMIT $limit
            RETURN
              id(c)      AS sourceId,
              labels(c)  AS sourceLabels,
              c          AS sourceNode,
              id(n)      AS targetId,
              labels(n)  AS targetLabels,
              n          AS targetNode,
              type(r)    AS relType
            """,
            {"limit": limit},
        )

        nodes: Dict[int, Dict[str, Any]] = {}
        links: List[Dict[str, Any]] = []

        def build_payload(db_id: int, db_node, labels) -> Dict[str, Any]:
            """
            Build a JSON-safe dict for a node:
              - sanitize NaN/inf using node_to_dict
              - keep all properties
              - add id / labels / group / label for visualization
            """
            props = node_to_dict(db_node) or {}
            raw_labels = props.pop("labels", [])
            labels_list = list(labels or raw_labels or [])
            group = labels_list[0] if labels_list else "Node"

            label = (
                props.get("cve_id")
                or props.get("cwe_id")
                or props.get("exploit_id")
                or props.get("cpe_uri")
                or props.get("product")
                or props.get("vendorProject")
                or props.get("vulnerabilityName")
                or props.get("name")
                or props.get("id")
                or str(db_id)
            )

            payload: Dict[str, Any] = {
                "id": db_id,
                "labels": labels_list,
                "group": group,
                "label": label,
            }
            payload.update(props)
            return payload

        for record in result:
            s_id = record["sourceId"]
            t_id = record["targetId"]

            source_labels = record["sourceLabels"]
            target_labels = record["targetLabels"]
            source_node = record["sourceNode"]
            target_node = record["targetNode"]

            if s_id not in nodes:
                nodes[s_id] = build_payload(s_id, source_node, source_labels)

            if t_id not in nodes:
                nodes[t_id] = build_payload(t_id, target_node, target_labels)

            links.append(
                {
                    "source": s_id,
                    "target": t_id,
                    "label": record["relType"],
                }
            )

    return {
        "nodes": list(nodes.values()),
        "links": links,
    }
