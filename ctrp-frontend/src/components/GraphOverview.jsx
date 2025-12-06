// src/components/GraphOverview.jsx
import { useEffect, useState, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { useNavigate } from "react-router-dom";

const API_BASE = "http://127.0.0.1:8000";

// Colors inspired by Neo4j Browser label colors
const GROUP_COLORS = {
  CVE: "#2563eb",
  CWE: "#16a34a",
  CPE: "#ea580c",
  Exploit: "#dc2626",
  KEV: "#7c3aed",
  default: "#6b7280",
};

// keys we DON'T want to show in "All Properties"
const INTERNAL_KEYS = new Set([
  "x",
  "y",
  "vx",
  "vy",
  "fx",
  "fy",
  "index",
  "__indexColor",
  "__proto__",
]);

export default function GraphOverview() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  const fgRef = useRef();
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ width: 400, height: 300 });

  const navigate = useNavigate();

  // -----------------------------
  // Safe Type Detection
  // -----------------------------
  const normalizedGroup = (selectedNode?.group || "").toUpperCase();

  const isCVE = normalizedGroup.includes("CVE") || !!selectedNode?.cve_id;

  const isKEV =
    normalizedGroup.includes("KEV") ||
    !!selectedNode?.vendorProject ||
    !!selectedNode?.shortDescription;

  const isCWE =
    normalizedGroup.includes("CWE") ||
    !!selectedNode?.cwe_id ||
    !!selectedNode?.name;

  const isCPE =
    normalizedGroup.includes("CPE") ||
    !!selectedNode?.cpe_uri ||
    !!selectedNode?.product;

  const isExploit =
    normalizedGroup.includes("EXPLOIT") ||
    !!selectedNode?.exploit_id ||
    !!selectedNode?.url;

  // -----------------------------
  // Helpers
  // -----------------------------
  const nodeColor = (node) =>
    (node?.group && GROUP_COLORS[node.group]) || GROUP_COLORS.default;

  const nodeCanvasObject = (node, ctx, globalScale) => {
    const label = node.label || "";
    const radius = 14;
    const maxTextWidth = radius * 2 - 4;

    // circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
    ctx.fillStyle = nodeColor(node);
    ctx.fill();

    // shrink text
    let fontSize = 12 / globalScale;
    fontSize = Math.min(fontSize, 14);
    fontSize = Math.max(fontSize, 3);

    ctx.font = `${fontSize}px Sans-Serif`;
    let width = ctx.measureText(label).width;

    if (width > maxTextWidth) {
      const scale = maxTextWidth / width;
      fontSize = Math.max(3, fontSize * scale);
      ctx.font = `${fontSize}px Sans-Serif`;
    }

    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle = "white";
    ctx.fillText(label, node.x, node.y);
  };

  // -----------------------------
  // Load graph
  // -----------------------------
  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const res = await fetch(`${API_BASE}/api/graph/overview?limit=200`);
        if (!res.ok) throw new Error("Failed to load graph");
        const data = await res.json();
        setGraphData(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  // Size / resize graph
  useEffect(() => {
    function handleResize() {
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      setDims({ width: rect.width, height: rect.height });
    }

    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  // -----------------------------
  // Node Click
  // -----------------------------
  const handleNodeClick = (node) => {
    console.log("Clicked node:", node);
    setSelectedNode(node);

    if (fgRef.current && node) {
      fgRef.current.centerAt(node.x || 0, node.y || 0, 400);
      fgRef.current.zoom(3, 400);
    }
  };

  // -----------------------------
  // Render
  // -----------------------------
  return (
    <section className="mb-8 bg-white border border-gray-200 rounded-xl shadow overflow-hidden">
      {/* Header */}
      <div className="px-5 pt-4 pb-3 border-b border-gray-200 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">
            Knowledge Graph Overview
          </h2>
          <p className="text-xs text-gray-500 mt-1">
            Interactive subgraph of CVEs, CWEs, CPEs, exploits, and KEV
            entries.
          </p>
        </div>

        {/* Legend */}
        <div className="hidden sm:flex gap-3 text-xs">
          {["CVE", "CWE", "CPE", "Exploit", "KEV"].map((g) => (
            <div key={g} className="flex items-center gap-1">
              <span
                className="inline-block w-3 h-3 rounded-full"
                style={{ backgroundColor: GROUP_COLORS[g] }}
              />
              <span className="text-gray-600">{g}</span>
            </div>
          ))}
        </div>
      </div>

      {error && (
        <div className="px-5 py-2 text-sm text-red-700 bg-red-50 border-b border-red-200">
          {error}
        </div>
      )}

      {/* Graph + Side panel */}
      <div className="flex flex-col md:flex-row h-[26rem]">
        {/* Graph */}
        <div
          ref={containerRef}
          className="flex-1 min-w-0 overflow-hidden h-[22rem]"
        >
          {loading ? (
            <div className="h-full flex items-center justify-center text-sm text-gray-500">
              Loading graph…
            </div>
          ) : (
            <ForceGraph2D
              ref={fgRef}
              graphData={graphData}
              width={dims.width}
              height={dims.height}
              backgroundColor="#ffffff"
              nodeLabel={(n) => `${n.group}: ${n.label}`}
              linkLabel={(l) => l.label || ""}
              nodeCanvasObject={nodeCanvasObject}
              linkDirectionalParticles={2}
              linkDirectionalParticleSpeed={0.005}
              linkColor={() => "rgba(148, 163, 184, 0.9)"}
              onNodeClick={handleNodeClick}
            />
          )}
        </div>

        {/* Details Panel */}
        <div className="w-full md:w-72 border-t md:border-l border-gray-200 bg-gray-50 p-4 text-sm">
          {selectedNode ? (
            <>
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-semibold text-gray-900">Node Details</h3>
                <span
                  className="inline-flex items-center justify-center w-6 h-6 rounded-full text-xs font-bold text-white"
                  style={{ backgroundColor: nodeColor(selectedNode) }}
                >
                  {selectedNode.group?.[0] || "N"}
                </span>
              </div>

              {/* --------- Summary by type (CVE / KEV / CWE / CPE / Exploit) --------- */}
              <dl className="space-y-2 text-xs text-gray-700">
                {/* CVE */}
                {isCVE && (
                  <>
                    {console.log("Rendering CVE details:", selectedNode)}
                    <div>
                      <dt className="font-semibold text-gray-500">CVE ID</dt>
                      <dd>{selectedNode.cve_id || selectedNode.label}</dd>
                    </div>

                    <div className="flex items-center gap-4">
                      <div>
                        <dt className="font-semibold text-gray-500">
                          Severity
                        </dt>
                        <dd>
                          {selectedNode.cvss_severity || (
                            <span className="text-gray-400">Unknown</span>
                          )}
                        </dd>
                      </div>

                      <div>
                        <dt className="font-semibold text-gray-500">Score</dt>
                        <dd>{selectedNode.cvss_score ?? "—"}</dd>
                      </div>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">
                        Description
                      </dt>
                      <dd className="break-words max-h-32 overflow-auto">
                        {selectedNode.description || "No description"}
                      </dd>
                    </div>
                  </>
                )}

                {/* KEV */}
                {isKEV && (
                  <>
                    {console.log("Rendering KEV details:", selectedNode)}
                    <div>
                      <dt className="font-semibold text-gray-500">CVE ID</dt>
                      <dd>{selectedNode.kev_cve_id || selectedNode.label}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">
                        Vendor / Project
                      </dt>
                      <dd>{selectedNode.vendorProject || "Unknown"}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">Product</dt>
                      <dd>{selectedNode.product || "Unknown"}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">
                        Vulnerability
                      </dt>
                      <dd>{selectedNode.vulnerabilityName || "N/A"}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">
                        Description
                      </dt>
                      <dd className="break-words max-h-24 overflow-auto">
                        {selectedNode.shortDescription || "No description"}
                      </dd>
                    </div>
                  </>
                )}

                {/* CWE */}
                {isCWE && (
                  <>
                    {console.log("Rendering CWE details:", selectedNode)}
                    <div>
                      <dt className="font-semibold text-gray-500">CWE ID</dt>
                      <dd>{selectedNode.cwe_id || selectedNode.label}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">Name</dt>
                      <dd>{selectedNode.name || "Unknown"}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">
                        Description
                      </dt>
                      <dd className="break-words max-h-32 overflow-auto">
                        {selectedNode.description || "No description"}
                      </dd>
                    </div>
                  </>
                )}

                {/* CPE */}
                {isCPE && (
                  <>
                    {console.log("Rendering CPE details:", selectedNode)}
                    <div>
                      <dt className="font-semibold text-gray-500">Product</dt>
                      <dd>{selectedNode.product || selectedNode.label}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">Vendor</dt>
                      <dd>{selectedNode.vendor || "Unknown"}</dd>
                    </div>

                    <div className="flex items-center gap-4">
                      <div>
                        <dt className="font-semibold text-gray-500">
                          Version
                        </dt>
                        <dd>{selectedNode.version || "Any"}</dd>
                      </div>
                      <div>
                        <dt className="font-semibold text-gray-500">Part</dt>
                        <dd>{selectedNode.part || "—"}</dd>
                      </div>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">CPE URI</dt>
                      <dd className="break-words">
                        {selectedNode.cpe_uri || "N/A"}
                      </dd>
                    </div>
                  </>
                )}

                {/* Exploit */}
                {isExploit && (
                  <>
                    {console.log("Rendering Exploit details:", selectedNode)}
                    <div>
                      <dt className="font-semibold text-gray-500">
                        Exploit ID
                      </dt>
                      <dd>{selectedNode.exploit_id || selectedNode.label}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">Title</dt>
                      <dd>{selectedNode.title || "—"}</dd>
                    </div>

                    <div>
                      <dt className="font-semibold text-gray-500">Source</dt>
                      <dd>{selectedNode.source || "Unknown"}</dd>
                    </div>

                    {selectedNode.url && (
                      <div>
                        <dt className="font-semibold text-gray-500">URL</dt>
                        <dd className="break-all">
                          <a
                            href={selectedNode.url}
                            className="text-blue-500 underline"
                            target="_blank"
                            rel="noreferrer"
                          >
                            {selectedNode.url}
                          </a>
                        </dd>
                      </div>
                    )}
                  </>
                )}
              </dl>

              {/* --------- All Properties (raw) --------- */}
              <h4 className="mt-4 mb-1 text-[11px] font-semibold text-gray-500 uppercase">
                All Properties
              </h4>
              <dl className="space-y-2 text-xs text-gray-700 max-h-64 overflow-auto border-t border-gray-200 pt-2">
                {Object.entries(selectedNode || {})
                  .filter(([key]) => !INTERNAL_KEYS.has(key))
                  .map(([key, value]) => (
                    <div key={key} className="grid grid-cols-3 gap-2">
                      <dt className="font-semibold text-gray-500 break-words">
                        {key}
                      </dt>
                      <dd className="col-span-2 break-words">
                        {value === null || value === undefined ? (
                          <span className="text-gray-400">null</span>
                        ) : Array.isArray(value) ? (
                          JSON.stringify(value)
                        ) : typeof value === "object" ? (
                          JSON.stringify(value)
                        ) : (
                          String(value)
                        )}
                      </dd>
                    </div>
                  ))}
              </dl>

              {/* CVE navigation */}
              {selectedNode.group === "CVE" && (
                <button
                  onClick={() =>
                    navigate(`/cve/${selectedNode.cve_id || selectedNode.label}`)
                  }
                  className="mt-4 inline-flex items-center px-3 py-1.5 rounded-md text-xs font-medium bg-blue-600 text-white hover:bg-blue-700"
                >
                  View CVE details
                </button>
              )}

              <button
                onClick={() => setSelectedNode(null)}
                className="mt-3 text-xs text-gray-500 hover:text-gray-700"
              >
                Clear selection
              </button>
            </>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-gray-500 text-center">
              Click a node to view its details.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
