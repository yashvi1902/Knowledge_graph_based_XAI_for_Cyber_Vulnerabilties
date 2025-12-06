import { useEffect, useState } from "react";
import { fetchUniqueProducts } from "../apis/client";

export default function UniqueProducts() {
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const res = await fetchUniqueProducts();
      const products = res.products || [];
      setRows(products.map((p, idx) => ({ id: idx, product: p })));
      setTotal(products.length);
      setLoading(false);
    }
    load();
  }, []);

  const filterLower = filter.trim().toLowerCase();
  const filteredRows =
    filterLower === ""
      ? rows
      : rows.filter((r) => r.product.toLowerCase().includes(filterLower));

  return (
    <section>
      <h2 className="text-2xl font-semibold mb-2">Unique Products</h2>
      <p className="text-gray-600 mb-4">
        Total unique products: <span className="font-semibold">{total}</span>
      </p>

      {/* Search */}
      <div className="mb-4 max-w-md">
        <input
          type="text"
          placeholder="Search products…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-full px-4 py-2 rounded-lg border border-gray-300 bg-white shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-sm"
        />
      </div>

      {loading ? (
        <p className="text-sm text-gray-600">Loading products…</p>
      ) : (
        <div className="bg-white shadow-lg rounded-xl border border-gray-200 p-4">
          <div
            className="
              grid 
              grid-cols-1 
              sm:grid-cols-2 
              lg:grid-cols-3 
              gap-4
            "
          >
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
                {item.product}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
