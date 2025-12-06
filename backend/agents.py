import json
from typing import Any, Dict, List
from backend.llm_client import call_llm
from backend.schema_summary import SCHEMA_SUMMARY
from backend.neo4j_client import neo4j_client
import logging
logger = logging.getLogger(__name__)

def extract_json_object(raw: str, context: str = "") -> Dict[str, Any]:
    """
    Try to extract a JSON object from an LLM string response.

    1. First try json.loads directly.
    2. If that fails, try to grab the substring between the first '{' and last '}'.
    3. If that still fails, raise RuntimeError with the raw content for debugging.
    """
    raw = raw.strip()

    # 1) Try direct parse
    try:
        return json.loads(raw)
    except Exception:
        pass

    # 2) Try substring between first '{' and last '}'
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = raw[start : end + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass

    # 3) Give up
    raise RuntimeError(f"Failed to parse JSON in {context}. Raw LLM output:\n{raw}")

# ---------- Cypher read-only guardrail ----------

# Very conservative blacklist for write / DDL keywords.
# We check case-insensitively before executing any query.
WRITE_KEYWORDS = [
    "CREATE ",
    "MERGE ",
    "DELETE ",
    "DETACH ",
    " SET ",
    " REMOVE ",
    " LOAD CSV",
    " FOREACH ",
    "CREATE INDEX",
    "DROP INDEX",
    "CREATE CONSTRAINT",
    "DROP CONSTRAINT",
    "CALL DBMS.",
    "CALL APOC.",
    " START TRANSACTION",
    " COMMIT",
    " ROLLBACK",
]


def is_read_only_cypher(cypher: str) -> bool:
    """
    Return False if the Cypher string appears to contain any write/DDL operation.
    This is a defensive check on top of the LLM prompt.
    """
    upper = cypher.upper()
    for kw in WRITE_KEYWORDS:
        if kw in upper:
            return False
    return True



# Type aliases for readability
SubQuestion = Dict[str, Any]


# ---------- Agent 1: Decomposer / Router ----------

AGENT1_SYSTEM = "You are a query decomposer and router for a security vulnerability assistant."

AGENT1_TEMPLATE = AGENT1_SYSTEM = "You are a query decomposer and router for a security vulnerability assistant."

AGENT1_TEMPLATE = """
Take ONE user question about software vulnerabilities, CVEs, CWEs, or products.
Break it into 1–3 smaller subquestions.

For each subquestion, decide whether it is:
- "explanation"  → conceptual, e.g. "explain log4j", "how does X affect my products"
- "db_query"     → needs listing, counting, or filtering actual CVEs/CWEs/products
                   from a Neo4j database

RULES:
- Subquestions MUST be clear stand-alone questions.
- Use as few subquestions as necessary.
- If the question clearly needs both explanation AND data
  (e.g. "Explain log4j and give list of CVEs in 2021"),
  then create:
  - one "explanation" subquestion, and
  - one "db_query" subquestion.
- Use ids "q1", "q2", "q3", ... in order.

OUTPUT FORMAT:
Return ONLY a single JSON object with this structure:

{{
  "subquestions": [
    {{
      "id": "q1",
      "text": "string",
      "type": "explanation or db_query"
    }}
  ]
}}

Do NOT include any extra keys or text.

USER QUESTION:
{user_question}
"""



def agent1_decompose(user_question: str) -> Dict[str, Any]:
    prompt = AGENT1_TEMPLATE.format(user_question=user_question)
    print("=== AGENT1 PROMPT ===")
    print(prompt)
    raw = call_llm(AGENT1_SYSTEM, prompt)
    print("=== RAW AGENT 1 OUTPUT ===")
    print(raw)

    try:
        data = extract_json_object(raw, context="Agent1 (decompose)")
        sq = data.get("subquestions")
        if isinstance(sq, list) and len(sq) > 0:
            cleaned = []
            for idx, item in enumerate(sq, start=1):
                if not isinstance(item, dict):
                    continue
                sub_id = item.get("id") or f"q{idx}"
                text = item.get("text") or user_question
                typ = item.get("type") or "explanation"
                cleaned.append({"id": sub_id, "text": text, "type": typ})

            if cleaned:
                return {"subquestions": cleaned}

    except Exception as e:
        print("Agent1: failed to parse LLM output:", e)
        print("Raw Agent1 output:\n", raw)

    return {
        "subquestions": [
            {
                "id": "q1",
                "text": user_question,
                "type": "explanation",
            }
        ]
    }

def agent1_debug_raw(user_question: str) -> str:
    """
    Debug helper: call Agent 1's prompt and return the raw LLM output
    WITHOUT trying to parse JSON or touch 'subquestions'.
    """
    prompt = AGENT1_TEMPLATE.format(user_question=user_question)
    raw = call_llm(AGENT1_SYSTEM, prompt)
    return raw


# ---------- Agent 2: Cypher Generator (db_query) ----------

AGENT2_SYSTEM = "You are an expert in Neo4j and Cypher for a security vulnerability knowledge graph."

AGENT2_TEMPLATE = """
SCHEMA:
{schema_summary}

TASK:
Given the user's subquestion, produce ONE OR MORE Cypher queries that answer it.

RULES:
- Queries MUST be read-only.
- NEVER use any of the following in your Cypher:
  CREATE, MERGE, DELETE, DETACH, SET, REMOVE, LOAD CSV, FOREACH,
  CREATE INDEX, DROP INDEX, CREATE CONSTRAINT, DROP CONSTRAINT,
  CALL dbms.*, CALL apoc.*, or any write/DDL operation.
- Use ONLY the node labels, relationship types, and properties from the schema.

- When the subquestion is asking to "list CVEs" (e.g. "list CVEs affecting X",
  "give a list of CVEs for Y", etc.):
  - Focus on returning one row per CVE.
  - Use DISTINCT on the CVE node to avoid duplicates.
  - RETURN only:
      c.cve_id        AS cve_id,
      c.cvss_score    AS cvss_score,
      c.cvss_severity AS cvss_severity
    and nothing else.
  - Example pattern:
      MATCH (c:CVE)-[:AFFECTS]->(p:CPE)
      WHERE toLower(p.vendor) CONTAINS 'servicenow'
      RETURN DISTINCT
        c.cve_id        AS cve_id,
        c.cvss_score    AS cvss_score,
        c.cvss_severity AS cvss_severity
      LIMIT 50;

- For non-list questions that need more detail, you may include description_en etc.,
  but still avoid duplicates using DISTINCT when appropriate.

OUTPUT FORMAT:
Return ONLY a JSON object with this structure:

{{
  "queries": [
    {{
      "label": "short human description of this query",
      "cypher": "Cypher query string"
    }}
  ]
}}

USER SUBQUESTION:
{subquestion}
"""



def agent2_generate_cypher(db_subquestion_text: str) -> Dict[str, Any]:
    prompt = AGENT2_TEMPLATE.format(
        schema_summary=SCHEMA_SUMMARY,
        subquestion=db_subquestion_text,
    )

    print("=== AGENT2 PROMPT ===")
    print(prompt)

    raw = call_llm(AGENT2_SYSTEM, prompt)

    print("=== RAW AGENT 2 OUTPUT ===")
    print(raw)

    try:
        data = extract_json_object(raw, context="Agent2 (generate_cypher)")
        if "queries" not in data or not isinstance(data["queries"], list):
            raise RuntimeError(f"Agent2 JSON missing 'queries': {data}")
        return data
    except Exception as e:
        # Don't kill the whole request – log and return no queries
        print("Agent2: failed to parse LLM output:", e)
        print("Raw Agent2 output (parse failure):\n", raw)
        # Safe fallback: no DB queries
        return {"queries": []}


def execute_cypher_queries(agent2_output: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for q in agent2_output.get("queries", []):
        cypher = q.get("cypher", "")
        label = q.get("label", "query")

        if not cypher:
            continue

        if not is_read_only_cypher(cypher):
            logger.warning("Blocked non read-only Cypher query from LLM: %s", cypher)
            # Skip this query instead of raising
            results.append({
                "label": label,
                "rows": [],
                "error": "Blocked non read-only Cypher query",
            })
            continue

        try:
            rows = neo4j_client.run_query(cypher)
            results.append({"label": label, "rows": rows})
        except Exception as e:
            logger.exception("Error running Cypher: %s", cypher)
            # Record error for this query instead of crashing
            results.append({
                "label": label,
                "rows": [],
                "error": str(e),
            })

    return results

# ---------- Agent 3: Explanation (for explanation subquestions) ----------

AGENT3_SYSTEM = "You are a senior security analyst explaining vulnerabilities to another analyst."

AGENT3_TEMPLATE = """
You are a senior security analyst explaining vulnerabilities to another analyst.

Write your answer in clean Markdown with good spacing.

Requirements:
- Do NOT restate or echo the question text.
- Start with one short sentence that directly answers the question.
- Then, if useful, add sections with Markdown headings, for example:
  - "### What it means"
  - "### Impact"
  - "### Mitigation"
- Use bullet lists for details where appropriate.
- Keep sentences short and avoid fluff.
- the answer should not include typical words like "answer", "response", "subquestion", etc.
- keep a professional tone suitable for a security analyst.

Question:
{subquestion}
"""


def agent3_explain(explanation_subquestion_text: str) -> str:
    prompt = AGENT3_TEMPLATE.format(subquestion=explanation_subquestion_text)
    return call_llm(AGENT3_SYSTEM, prompt)


# ---------- Agent 4: Answer Composer ----------

AGENT4_SYSTEM = "You are a security analyst assistant. Combine multiple partial answers into one coherent response."

AGENT4_TEMPLATE = """
You are given the user's original question and several subquestions with their answers or database results.

ORIGINAL QUESTION:
{original_question}

SUBQUESTIONS AND ANSWERS:
{formatted_subq_blocks}

GUIDELINES:
- Write a single, coherent answer directly for the user.
- Do NOT mention 'subquestions' or 'agents'.
- If there is at least one explanation-type subquestion:
  - Start with a short explanation section (you can use a heading like '### Explanation').
- If there are db_query results:
  - Present key CVEs in a concise Markdown table when possible,
    with columns such as: CVE ID, CVSS, Short Description.
  - Mention important observations (e.g., 'Most CVEs in 2021 are high severity').
- If a db_query part has no rows, say clearly that no matching records were found
  for that part, but still answer other parts.
- Use a professional tone suitable for a security analyst.
- Output MUST be valid Markdown.
- Do not include JSON or debugging information.

Return ONLY the final answer in Markdown.
"""


# def agent4_compose(
#     original_question: str,
#     subquestions: List[SubQuestion],
#     explanations: List[Dict[str, Any]],
#     db_answers: List[Dict[str, Any]],
# ) -> str:
#     exp_map = {e["subquestion_id"]: e["answer"] for e in explanations}
#     db_map = {d["subquestion_id"]: d["db_results"] for d in db_answers}

#     blocks: List[str] = []
#     for sq in subquestions:
#         sq_id = sq.get("id")
#         sq_type = sq.get("type")
#         sq_text = sq.get("text", "")

#         block_lines = [f"Subquestion {sq_id} (type = {sq_type}):", f"Text: {sq_text}"]

#         if sq_type == "explanation":
#             answer = exp_map.get(sq_id, "(no answer)")
#             block_lines.append("Explanation answer:")
#             block_lines.append(answer)

#         elif sq_type == "db_query":
#             results = db_map.get(sq_id, [])
#             block_lines.append("Database results JSON:")
#             block_lines.append(json.dumps(results, indent=2))

#         blocks.append("\n".join(block_lines))

#     formatted_subq_blocks = "\n\n---\n\n".join(blocks)

#     prompt = AGENT4_TEMPLATE.format(
#         original_question=original_question,
#         formatted_subq_blocks=formatted_subq_blocks,
#     )

#     return call_llm(AGENT4_SYSTEM, prompt)


# ---------- High-level pipeline used by API ----------

# ---------- High-level pipeline used by API ----------

def answer_question_pipeline(user_question: str) -> Dict[str, Any]:
    """
    Main pipeline (without Agent4):
    - Agent1: decompose into subquestions
    - Agent3: answer 'explanation' subquestions (LLM)
    - Agent2 + Cypher: answer 'db_query' subquestions (Neo4j)
    - Return explanations and DB results separately so the frontend can:
      - render LLM markdown for explanations
      - render Cypher/Neo4j rows directly in tables
    """
    # 1) Agent 1 — decompose the user question
    a1 = agent1_decompose(user_question)
    subquestions: List[SubQuestion] = a1.get("subquestions", [])

    explanations: List[Dict[str, Any]] = []
    db_sections: List[Dict[str, Any]] = []

    # 2) Route each subquestion
    for sq in subquestions:
        sq_id = sq.get("id", "")
        sq_type = sq.get("type", "explanation")
        sq_text = sq.get("text", user_question)

        # 2a) Explanation subquestions → Agent 3 (LLM only)
        if sq_type == "explanation":
            ans = agent3_explain(sq_text)  # returns markdown/plain text
            explanations.append(
                {
                    "subquestion_id": sq_id,
                    "text": sq_text,
                    "answer_markdown": ans,
                }
            )

        # 2b) db_query subquestions → Agent 2 (Cypher) + Neo4j
        elif sq_type == "db_query":
            cypher_obj = agent2_generate_cypher(sq_text)
            db_results = execute_cypher_queries(cypher_obj)
            # db_results: [{"label": "...", "rows": [...]}, ...]

            for entry in db_results:
                db_sections.append(
                    {
                        "subquestion_id": sq_id,
                        "text": sq_text,
                        "label": entry.get("label", "Results"),
                        "rows": entry.get("rows", []),
                    }
                )

    # 3) Final payload (NO Agent4 composition)
    return {
        "question": user_question,
        "subquestions": subquestions,   # optional; useful for debugging / UI tags
        "explanations": explanations,   # each has answer_markdown
        "db_sections": db_sections,     # each has label + rows for tables
    }

