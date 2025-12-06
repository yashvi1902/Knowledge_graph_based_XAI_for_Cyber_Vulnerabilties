import CveDataTable from "./CveDataTable";

export default function TotalCVEs({ data, total, query, setQuery }) {
  const q = query.toLowerCase();

  const filtered = q
    ? data.filter(
        (row) =>
          row.cve_id.toLowerCase().includes(q) ||
          (row.source || "").toLowerCase().includes(q)
      )
    : data;

  return (
    <section>
      {/* Search */}
      <div className="mb-6 max-w-md">
        <div className="relative">
          <span className="absolute inset-y-0 left-3 flex items-center text-gray-500">🔍</span>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search CVEs…"
            className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300"
          />
        </div>

        <p className="mt-2 text-sm text-gray-500">
          Showing <b>{filtered.length}</b> of <b>{total}</b> CVEs
        </p>
      </div>

      {/* Data Table */}
      <div className="bg-white rounded-xl shadow border">
        <CveDataTable data={filtered} loading={false} />
      </div>
    </section>
  );
}
