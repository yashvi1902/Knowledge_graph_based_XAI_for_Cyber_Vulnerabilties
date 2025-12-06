// src/components/UniqueVendors.jsx
import { useEffect, useState } from "react";
import { fetchUniqueVendors } from "../apis/client";

export default function UniqueVendors() {
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const res = await fetchUniqueVendors();
      const vendors = res.vendors || [];
      setRows(vendors.map((v, idx) => ({ id: idx, vendor: v })));
      setTotal(vendors.length);
      setLoading(false);
    }
    load();
  }, []);

  const filterLower = filter.trim().toLowerCase();
  const filteredRows =
    filterLower === ""
      ? rows
      : rows.filter((r) => r.vendor.toLowerCase().includes(filterLower));

  return (
    <section>
      <h2 className="text-2xl font-semibold mb-2">Unique Vendors</h2>
      <p className="text-gray-600 mb-4">
        Total unique vendors: <span className="font-semibold">{total}</span>
      </p>

      {/* Search */}
      <div className="mb-4 max-w-md">
        <input
          type="text"
          placeholder="Search vendors…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-full px-4 py-2 rounded-lg border border-gray-300 bg-white shadow-sm"
        />
      </div>

      {loading ? (
        <p>Loading…</p>
      ) : (
        <div className="bg-white shadow-lg rounded-xl border border-gray-200 p-4">
          <div className="
            grid 
            grid-cols-1 
            sm:grid-cols-2 
            lg:grid-cols-3 
            gap-4
          ">
            {filteredRows.map((item) => (
              <div
                key={item.id}
                className="
                  px-3 py-2 
                  bg-gray-50 
                  rounded-lg 
                  border 
                  hover:bg-gray-100 
                  text-gray-800 
                  break-words 
                  whitespace-normal
                "
              >
                {item.vendor}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
