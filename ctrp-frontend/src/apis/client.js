const API_BASE = "http://127.0.0.1:8000";

export async function fetchCVEList(page = 1, pageSize = 20) {
    const res = await fetch(`${API_BASE}/api/cves?page=${page}&page_size=${pageSize}`);
    if (!res.ok) throw new Error(`Failed to fetch CVEs: ${res.status}`);
    return await res.json();
}

export async function fetchCVE(cveId) {
    const res = await fetch(`${API_BASE}/api/cve/${cveId}`);
    if (!res.ok) throw new Error(`Failed to fetch CVE: ${res.status}`);
    return await res.json();
}
