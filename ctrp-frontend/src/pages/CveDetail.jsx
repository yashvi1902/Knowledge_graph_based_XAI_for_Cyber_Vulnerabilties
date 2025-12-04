import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { fetchCVE } from "../apis/client";

function formatKey(key) {
    return key
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

export default function CveDetail() {
  const { id } = useParams();    // cve_id from URL
  console.log("CVE detail param:", id);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchCVE(id)
      .then((res) => {
        console.log("CVE detail response:", res);
        setData(res);
      })
      .catch((err) => {
        console.error("Error fetching CVE:", err);
        setError("Failed to load CVE details");
      })
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <p>Loading CVE details…</p>;
  if (error) return <p style={{ color: "red" }}>{error}</p>;
  if (!data || !data.cve) return <p>Not found.</p>;

  const cve = data.cve;
  const cwes = data.cwes || [];
  const cpes = data.cpes || [];
  const exploits = data.exploits || [];
  const kev = data.kev;

  return (
    <div>
      <p>
        <Link to="/">← Back to list</Link>
      </p>

      <h1>{cve.cve_id}</h1>

      <p>{cve.description_en}</p>

      <div style={{ marginTop: 10 }}>
        <div>Published: {cve.published}</div>
        <div>Last Modified: {cve.last_modified}</div>
        <div>Status: {cve.status}</div>
        <div>Source: {cve.source}</div>
      </div>

      <h2>Weaknesses (CWEs)</h2>
      {cwes.length === 0 ? (
        <p>No CWE linked.</p>
      ) : (
        <ul>
          {cwes.map((w) => (
            <li key={w.cwe_id || JSON.stringify(w)}>
              {w.cwe_id} {w.name ? `– ${w.name}` : ""}
            </li>
          ))}
        </ul>
      )}

<h2>Affected Products (CPEs)</h2>
      {cpes.length === 0 ? (
        <p>No CPEs linked.</p>
      ) : (
        <ul style={{ listStyle: "none", paddingLeft: 0 }}>
          {cpes.map((c, idx) => (
            <li
              key={c.cpe_uri || idx}
              style={{
                marginBottom: "12px",
                padding: "8px",
                border: "1px solid #ddd",
                borderRadius: "6px",
              }}
            >
              {Object.entries(c)
                .filter(([key]) => key !== "labels" && key !== "cpe_uri") // don't show labels
                .map(([key, value]) => (
                  <div key={key}>
                    <strong>{formatKey(key)}:</strong> {String(value)}
                  </div>
                ))}

              {/* Optional: still show raw URI if present */}
              {c.cpe_uri && (
                <div>
                  <small style={{ color: "#666" }}>{c.cpe_uri}</small>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}


      <h2>Exploits</h2>
      {exploits.length === 0 ? (
        <p>No exploits linked.</p>
      ) : (
        <ul>
          {exploits.map((e) => (
            <li key={e.exploitdb_id}>
              {e.exploitdb_id} – {e.description}
            </li>
          ))}
        </ul>
      )}

      <h2>CISA KEV</h2>
      {!kev ? (
        <p>Not listed in KEV.</p>
      ) : (
        <div>
          <div>Vendor: {kev.vendor}</div>
          <div>Product: {kev.product}</div>
          <div>Name: {kev.name}</div>
          <div>Date Added: {kev.date_added}</div>
          <div>Due Date: {kev.due_date}</div>
        </div>
      )}
    </div>
  );
}
