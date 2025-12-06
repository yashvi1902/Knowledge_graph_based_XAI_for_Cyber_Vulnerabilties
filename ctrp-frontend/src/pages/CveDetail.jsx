import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { fetchCVE } from "../apis/client";

function formatKey(key) {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function CveDetail() {
  const { id } = useParams(); // cve_id from URL
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

  if (loading) {
    return (
      <div className="max-w-5xl mx-auto px-6 py-10">
        <p className="text-sm text-gray-600">Loading CVE details…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-5xl mx-auto px-6 py-10">
        <div className="rounded-xl border border-red-300 bg-red-50 px-6 py-4 text-red-700 shadow">
          {error}
        </div>
        <Link
          to="/"
          className="mt-4 inline-block text-sm text-blue-600 hover:underline"
        >
          ← Back to list
        </Link>
      </div>
    );
  }

  if (!data || !data.cve) {
    return (
      <div className="max-w-5xl mx-auto px-6 py-10">
        <p className="text-sm text-gray-600">CVE not found.</p>
        <Link
          to="/"
          className="mt-4 inline-block text-sm text-blue-600 hover:underline"
        >
          ← Back to list
        </Link>
      </div>
    );
  }

  const cve = data.cve;
  const cwes = data.cwes || [];
  const cpes = data.cpes || [];
  const exploits = data.exploits || [];
  const kev = data.kev;

  return (
    <div className="max-w-5xl mx-auto px-6 py-10">
      {/* Back link */}
      <div className="mb-4">
        <Link
          to="/"
          className="inline-flex items-center text-sm text-gray-600 hover:text-blue-600"
        >
          ← Back to list
        </Link>
      </div>

      {/* Header */}
      <header className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-gray-500">
            CVE Detail
          </p>
          <h1 className="mt-1 text-3xl font-bold tracking-tight text-gray-900">
            {cve.cve_id}
          </h1>
        </div>

        <div className="flex flex-wrap gap-2 text-xs">
          {cve.status && (
            <span className="rounded-full border border-gray-300 bg-gray-100 px-3 py-1 font-semibold uppercase tracking-wide text-gray-700">
              {cve.status}
            </span>
          )}
          {cve.source && (
            <span className="rounded-full border border-blue-200 bg-blue-50 px-3 py-1 font-semibold text-blue-700">
              {cve.source}
            </span>
          )}
        </div>
      </header>

      {/* Meta info */}
      <section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <MetaCard label="Published" value={cve.published || "—"} />
        <MetaCard label="Last Modified" value={cve.last_modified || "—"} />
        <MetaCard label="CVE Status" value={cve.status || "—"} />
      </section>

      {/* Description */}
      <section className="mb-8">
        <div className="rounded-xl border border-gray-200 bg-white px-5 py-4 shadow-sm">
          <h2 className="mb-2 text-lg font-semibold text-gray-900">
            Description
          </h2>
          <p className="text-sm leading-relaxed text-gray-700">
            {cve.description_en || "No description available."}
          </p>
        </div>
      </section>

      {/* CWEs + KEV */}
      <section className="mb-8 grid grid-cols-1 gap-6 md:grid-cols-2">
        {/* CWEs */}
        <div className="rounded-xl border border-gray-200 bg-white px-5 py-4 shadow-sm">
          <h2 className="mb-2 text-lg font-semibold text-gray-900">
            Weaknesses (CWEs)
          </h2>
          {cwes.length === 0 ? (
            <p className="text-sm text-gray-500">No CWE linked.</p>
          ) : (
            <ul className="space-y-1 text-sm text-gray-800">
              {cwes.map((w) => (
                <li key={w.cwe_id || JSON.stringify(w)}>
                  <span className="font-semibold">{w.cwe_id}</span>
                  {w.name && <span className="text-gray-600"> – {w.name}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* CISA KEV */}
        <div className="rounded-xl border border-gray-200 bg-white px-5 py-4 shadow-sm">
          <h2 className="mb-2 text-lg font-semibold text-gray-900">CISA KEV</h2>
          {!kev ? (
            <p className="text-sm text-gray-500">Not listed in KEV.</p>
          ) : (
            <dl className="text-sm text-gray-800 space-y-1">
              <KeyValue label="Vendor" value={kev.vendor} />
              <KeyValue label="Product" value={kev.product} />
              <KeyValue label="Name" value={kev.name} />
              <KeyValue label="Date Added" value={kev.date_added} />
              <KeyValue label="Due Date" value={kev.due_date} />
            </dl>
          )}
        </div>
      </section>

      {/* CPEs */}
      <section className="mb-8">
        <div className="rounded-xl border border-gray-200 bg-white px-5 py-4 shadow-sm">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">
              Affected Products (CPEs)
            </h2>
            {cpes.length > 0 && (
              <span className="text-xs text-gray-500">
                {cpes.length} entr{cpes.length === 1 ? "y" : "ies"}
              </span>
            )}
          </div>

          {cpes.length === 0 ? (
            <p className="text-sm text-gray-500">No CPEs linked.</p>
          ) : (
            <div className="space-y-3 text-sm">
              {cpes.map((c, idx) => (
                <div
                  key={c.cpe_uri || idx}
                  className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2"
                >
                  <div className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
                    {Object.entries(c)
                      .filter(([key]) => key !== "labels" && key !== "cpe_uri")
                      .map(([key, value]) => (
                        <div key={key}>
                          <span className="text-xs uppercase tracking-wide text-gray-500">
                            {formatKey(key)}
                          </span>
                          <div className="text-gray-800">
                            {String(value) || "—"}
                          </div>
                        </div>
                      ))}
                  </div>
                  {c.cpe_uri && (
                    <div className="mt-1 text-xs text-gray-500 break-all">
                      {c.cpe_uri}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Exploits */}
      <section className="mb-4">
        <div className="rounded-xl border border-gray-200 bg-white px-5 py-4 shadow-sm">
          <h2 className="mb-2 text-lg font-semibold text-gray-900">Exploits</h2>
          {exploits.length === 0 ? (
            <p className="text-sm text-gray-500">No exploits linked.</p>
          ) : (
            <ul className="space-y-2 text-sm text-gray-800">
              {exploits.map((e) => (
                <li key={e.exploitdb_id}>
                  <span className="font-semibold">{e.exploitdb_id}</span>
                  {e.description && (
                    <span className="text-gray-600"> – {e.description}</span>
                    
                  )}
                  {e.author && (
                    <span className="text-gray-600"> – {e.author}</span>
                    
                  )}
                  {e.date_published && (
                    <span className="text-gray-600"> – {e.date_published}</span>
                    
                  )}
                  {e.platform && (
                    <span className="text-gray-600"> – {e.platform}</span>
                    
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>
    </div>
  );
}

/* Small helper components */

function MetaCard({ label, value }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white px-4 py-3 shadow-sm">
      <p className="text-xs text-gray-500">{label}</p>
      <p className="mt-1 text-sm font-semibold text-gray-900 break-all">
        {value || "—"}
      </p>
    </div>
  );
}

function KeyValue({ label, value }) {
  return (
    <div className="flex gap-2">
      <dt className="w-24 text-xs font-medium text-gray-500">{label}</dt>
      <dd className="flex-1 text-gray-800">{value || "—"}</dd>
    </div>
  );
}
