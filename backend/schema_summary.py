SCHEMA_SUMMARY = """
Nodes:

(CVE):
  - cve_id (string)                  // CVE identifier, e.g. "CVE-2020-5515"
  - description_en (string)          // English description
  - description_es (string, optional)
  - cvss_score (float, optional)     // overall CVSS v3.x score
  - cvss_severity (string, optional) // e.g. "LOW", "MEDIUM", "HIGH", "CRITICAL"
  - cvss_vector (string, optional)   // e.g. "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/..."
  - cvss_version (string, optional)  // e.g. "v3_1"
  - cvss_attackComplexity (string, optional)
  - cvss_attackVector (string, optional)
  - cvss_availabilityImpact (string, optional)
  - cvss_confidentialityImpact (string, optional)
  - cvss_integrityImpact (string, optional)
  - cvss_privilegesRequired (string, optional)
  - cvss_scope (string, optional) 
  - cvss_userInteraction (string, optional)
  - last_modified (string, not null) // ISO-like: "2020-01-15T18:15:00"
  - published (string, not null)     // ISO-like: "2020-01-10T14:29:00"
  - source (string, optional)        // e.g. "cve@mitre.org"
  - status (string, optional)        // e.g. "Modified"

(CPE):
  - cpe_uri (string)                 // e.g. "cpe:2.3:o:microsoft:windows_10_1903:..."
  - vendor (string, optional)        // e.g. "microsoft"
  - product (string, optional)       // e.g. "windows_10_1903"
  - version (string, optional)       // e.g. "Not Specified"
  - part (string, optional)          // e.g. "o", "a", "h"
  - edition (string, optional)
  - sw_edition (string, optional)
  - target_sw (string, optional)
  - target_hw (string, optional)
  - language (string, optional)
  - other (string, optional)
  - update (string, optional)

(CWE):
  - id (string)                      // e.g. "CWE-79"
  - name (string)
  - description (string)

(Reference):
  - url (string)                     // e.g. "http://packetstormsecurity.com/files/..."
  - tags (list of string, optional)  // e.g. ["Exploit", "Third Party Advisory", "VDB Entry"]

Relationships:
  (c:CVE)-[:AFFECTS]->(p:CPE)
  (c:CVE)-[:HAS_CWE]->(w:CWE)
  (c:CVE)-[:HAS_REFERENCE]->(r:Reference)

Field types and Cypher usage notes:

- cvss_score is a FLOAT:
  - Use numeric comparisons: >, >=, <, <=.
  - Example:
      WHERE c.cvss_score >= 9.0

- cvss_severity and most other non-list properties are STRINGS:
  - Use exact match or IN:
      WHERE c.cvss_severity = 'CRITICAL'
      WHERE c.cvss_severity IN ['HIGH', 'CRITICAL']
  - For fuzzy vendor/product search, use toLower(...) + CONTAINS:
      WHERE toLower(p.vendor) CONTAINS 'microsoft'

- published and last_modified are STRINGS containing ISO-like date-times
  (e.g. "2020-01-10T14:29:00", "2020-01-06T01:15:10.840").

  When filtering by date or year in Cypher:
    *ALWAYS* convert BOTH sides to datetime(...) before comparing.

  Example: all CVEs published in 2025:
      WHERE c.published IS NOT NULL
        AND datetime(c.published) >= datetime('2025-01-01T00:00:00')
        AND datetime(c.published) <  datetime('2026-01-01T00:00:00')

- When using RETURN DISTINCT:

- You may only ORDER BY expressions that are either:
  - in the RETURN clause as aliases, or
  - introduced earlier via WITH.

- If you need to order by datetime(c.published), do:

  MATCH (c:CVE) ...
  WITH DISTINCT c, datetime(c.published) AS published_dt
  RETURN
    c.cve_id AS cve_id,
    c.cvss_score AS cvss_score,
    c.cvss_severity AS cvss_severity
  ORDER BY published_dt

  Do NOT write:
  RETURN DISTINCT c.cve_id AS cve_id, ... ORDER BY datetime(c.published)

  Do NOT use:
    - YEAR(), MONTH(), DAY(), DATE(), TO_CHAR()
    - c.published.year or c.last_modified.year
    - substring(c.published, 0, 4) for filtering
    - plain string comparison like:
        c.published >= '2025-01-01'

All Cypher generated against this schema should be READ-ONLY:
  - Do NOT use: CREATE, MERGE, DELETE, DETACH, SET, REMOVE,
                LOAD CSV, FOREACH, CREATE INDEX, DROP INDEX,
                CREATE CONSTRAINT, DROP CONSTRAINT, CALL dbms.*, CALL apoc.*.
"""
