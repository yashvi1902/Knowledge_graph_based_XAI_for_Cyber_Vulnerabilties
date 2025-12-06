// src/App.jsx
import { Routes, Route, Link } from "react-router-dom";
import CVEList from "./pages/CVEList";
import CveDetail from "./pages/CveDetail";
import ChatWidget from "./components/chatWidget";

export default function App() {
  return (
    <div className="min-h-screen bg-slate-100 text-slate-950">
      {/* Simple navbar */}
      <nav className="px-6 py-4 border-b mb-4 flex items-center">
        <Link
          to="/"
          className="font-bold text-lg text-slate-950 hover:text-blue-400 transition"
        >
          CVE Explorer
        </Link>
      </nav>

      <div className="pb-8">
        <Routes>
          <Route path="/" element={<CVEList />} />
          <Route path="/cve/:id" element={<CveDetail />} />
        </Routes>
      </div>

      {/* Chat is global: appears on all pages */}
      <ChatWidget />
    </div>
  );
}
