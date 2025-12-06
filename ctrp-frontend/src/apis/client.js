const API_BASE = "http://127.0.0.1:8000";

export async function fetchCVEList(page = 1, pageSize = 5000) {
    const res = await fetch(`${API_BASE}/api/cves?page=${page}&page_size=${pageSize}`);
    if (!res.ok) throw new Error(`Failed to fetch CVEs: ${res.status}`);
    return await res.json();
}

export async function fetchCVE(cveId) {
    const res = await fetch(`${API_BASE}/api/cve/${cveId}`);
    if (!res.ok) throw new Error(`Failed to fetch CVE: ${res.status}`);
    return await res.json();
}


export async function fetchStatsOverview() {
    const res = await fetch(`${API_BASE}/api/stats/overview`);
    if (!res.ok) throw new Error(`Failed to fetch stats overview: ${res.status}`);
    return await res.json();
  }

export async function askLLM(question) {
    const res = await fetch(`${API_BASE}/api/ask`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ question })
    });

    if (!res.ok) {
        throw new Error(`LLM request failed: ${res.status}`);
    }

    return await res.json();
}

export async function fetchCvesWithExploits(page = 1, pageSize = 1000) {
    const res = await fetch(`${API_BASE}/api/cves/with-exploits?page=${page}&page_size=${pageSize}`);
    if (!res.ok) throw new Error(`Failed to load CVEs with exploits: ${res.status}`);
    return await res.json();
  }

  
export async function fetchUniqueVendors() {
  const res = await fetch(`${API_BASE}/api/vendors`);
  if (!res.ok) {
    throw new Error(`Failed to fetch vendors: ${res.status}`);
  }
  return await res.json(); // { vendors: [...], total: n }
}

export async function fetchUniqueProducts() {
  const res = await fetch(`${API_BASE}/api/products`);
  if (!res.ok) {
    throw new Error(`Failed to fetch products: ${res.status}`);
  }
  return await res.json(); // { products: [...], total: n }
}
