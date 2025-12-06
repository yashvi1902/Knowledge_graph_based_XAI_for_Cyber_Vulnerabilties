import { useEffect, useState, } from "react";
import { fetchCVEList, fetchStatsOverview } from "../apis/client";

// Components
import StatCard from "../components/StatCard";
import TotalCVEs from "../components/TotalCVEs";
import CVEsWithExploits from "../components/CVEsWithExploits";
import UniqueVendors from "../components/UniqueVendors";
import UniqueProducts from "../components/UniqueProducts";
import GraphOverview from "../components/GraphOverview";


export default function CVEList() {
  const [data, setData] = useState([]);
  const [total, setTotal] = useState(0);

  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statsError, setStatsError] = useState(null);

  const [activeView, setActiveView] = useState("");
  const [query, setQuery] = useState("");

  

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);

        const listRes = await fetchCVEList();
        setData(listRes.results || []);
        setTotal(listRes.total ?? 0);

        try {
          const statsRes = await fetchStatsOverview();
          setStats(statsRes);
        } catch {
          setStatsError("Failed to load stats");
        }
      } catch {
        setError("Failed to load CVEs");
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  if (loading) return <p>Loading CVEs…</p>;
  if (error) return <p>Error: {error}</p>;
  return (<div>

  
    <div className="max-w-6xl mx-auto px-6 py-10">
      {/* Header */}
      <h1 className="text-4xl font-bold mb-2">CVE Explorer</h1>
      <p className="text-gray-600 mb-8">
        Search, browse, and analyze vulnerabilities.
      </p>

      {/* Stats */}
      
      {stats && (
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
          <StatCard
            label="Total CVEs"
            value={stats.total_cves}
            onClick={() => setActiveView("total")}
            active={activeView === "total"}
          />
          {/* <StatCard
            label="CVEs with Exploits"
            value={stats.cves_with_exploits}
            onClick={() => setActiveView("cvesWithExploits")}
            active={activeView === "cvesWithExploits"}
          /> */}
          <StatCard
            label="Unique Vendors"
            value={stats.vendors}
            onClick={() => setActiveView("vendors")}
            active={activeView === "vendors"}
          />
          <StatCard
            label="Unique Products"
            value={stats.products}
            onClick={() => setActiveView("products")}
            active={activeView === "products"}
          />
        </section>
      )}

      {/* Component Switching */}
      {activeView === "total" && (
        <TotalCVEs data={data} total={total} query={query} setQuery={setQuery} />
      )}

      {activeView === "cvesWithExploits" && <CVEsWithExploits data={data} />}

      {activeView === "vendors" && <UniqueVendors data={data} />}

      {activeView === "products" && <UniqueProducts data={data} />}
    </div>



<div className="max-w-6xl mx-auto px-6 py-10">
  {/* Neo4j-like graph panel */}
  <GraphOverview />

  {/* your stats, cards, tables, etc… */}
</div>
</div>

  );
}
