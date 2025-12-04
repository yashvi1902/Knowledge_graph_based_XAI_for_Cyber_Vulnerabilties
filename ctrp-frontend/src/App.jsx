import { Routes, Route, Link } from "react-router-dom";
import CVEList from "./pages/CVEList";
import CveDetail from "./pages/CveDetail";

export default function App() {
  return (
    <div style={{ padding: 20 }}>
      {/* Simple navbar */}
      <nav style={{ marginBottom: 20 }}>
        <Link to="/" style={{ fontWeight: "bold", marginRight: 16 }}>
          CVE Explorer
        </Link>
      </nav>

      <Routes>
        <Route path="/" element={<CVEList />} />
        <Route path="/cve/:id" element={<CveDetail />} />
      </Routes>
    </div>
  );
}


