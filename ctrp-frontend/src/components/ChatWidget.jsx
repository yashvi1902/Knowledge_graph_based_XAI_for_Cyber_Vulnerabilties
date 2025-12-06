// src/components/ChatWidget.jsx
import { useState } from "react";
import ReactMarkdown from "react-markdown";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";

export default function ChatWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState([]); // { role, question, explanationMarkdown, dbSections }
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function sendQuestion() {
    const question = input.trim();
    if (!question || loading) return;
  
    setError("");
    setLoading(true);
    setInput("");
  
    // 🔹 Optimistically show the user message immediately
    setMessages((prev) => [
      ...prev,
      { role: "user", question },
    ]);
  
    try {
      const res = await fetch(`${API_BASE}/api/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
  
      let data;
      try {
        data = await res.json();
      } catch {
        data = null;
      }
  
      if (!res.ok) {
        const backendDetail = data?.detail || `API error: ${res.status}`;
        throw new Error(backendDetail);
      }
  
      const explanations = data.explanations ?? [];
      const explanationMarkdown = explanations
        .map((e) => e.answer_markdown || "")
        .join("\n\n---\n\n");
  
      const dbSections = data.db_sections ?? [];
  
      // 🔹 Now append the assistant message when the answer arrives
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          question: data.question,
          explanationMarkdown,
          dbSections,
        },
      ]);
    } catch (err) {
      console.error(err);
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendQuestion();
    }
  }

  function renderExplanation(markdown) {
    if (!markdown) return null;
  
    return (
      <div
        className="prose prose-invert prose-sm max-w-none mb-3 text-slate-300
                   prose-headings:text-slate-100 prose-p:text-slate-100
                   prose-strong:text-slate-100 prose-li:text-slate-100

                   prose-hr:border-gray-600  /* <-- HR color */"  
      >
        <ReactMarkdown>
          {markdown}
        </ReactMarkdown>
      </div>
    );
  }
  

  function renderTable(rows) {
    if (!rows || rows.length === 0) {
      return <div className="text-xs text-slate-300">No results.</div>;
    }

    const columns = Object.keys(rows[0]);

    return (
      <div className="overflow-auto max-h-48 border border-slate-500 rounded-lg">
        <table className="min-w-full text-xs">
          <thead className="bg-slate-500">
            <tr>
              {columns.map((col) => (
                <th
                  key={col}
                  className="px-2 py-1 text-left font-semibold text-slate-200"
                >
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr
                key={i}
                className={i % 2 === 0 ? "bg-slate-500" : "bg-slate-550"}
              >
                {columns.map((col) => (
                  <td key={col} className="px-2 py-1 text-slate-100">
                    {row[col] === null || row[col] === undefined
                      ? "-"
                      : String(row[col])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  function renderAssistantMessage(msg, idx) {
    return (
      <div
        key={idx}
        className="self-start bg-slate-800/80 border border-slate-700 rounded-2xl px-3 py-2 max-w-full"
      >
        {msg.explanationMarkdown && renderExplanation(msg.explanationMarkdown)}

        {msg.dbSections && msg.dbSections.length > 0 && (
          <div className="space-y-3">
            {msg.dbSections.map((sec, i) => (
              <div key={i}>
                <div className="text-xs font-semibold text-slate-300 mb-1">
                  {sec.label || "Results"}
                </div>
                {renderTable(sec.rows)}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <>
      {/* Collapsed floating button */}
      {!isOpen && (
        <button
          type="button"
          onClick={() => setIsOpen(true)}
          className="fixed bottom-4 right-4 z-40 rounded-full bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 shadow-lg shadow-blue-500/30 flex items-center gap-2"
        >
          <span className="text-lg">💬</span>
          <span className="hidden sm:inline text-sm font-medium">
            Ask CVE Assistant
          </span>
        </button>
      )}

      {/* Expanded chat panel */}
      {isOpen && (
        <div className="fixed bottom-4 right-4 z-40 w-full max-w-lg h-[90vh] sm:h-[85vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-xl shadow-black/60 flex flex-col">
          {/* Header */}
          <div className="flex items-center justify-between px-3 py-2 border-b border-slate-900">
            <div>
              <div className="text-sm font-semibold text-slate-100">
                CVE Assistant
              </div>
              <div className="text-xs text-slate-200">
                Ask about CVEs, years, products, severity…
              </div>
            </div>
            <button
              type="button"
              onClick={() => setIsOpen(false)}
              className="text-slate-300 hover:text-slate-100 text-lg px-2"
            >
              ✕
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-3 py-2 space-y-3 text-sm bg-slate-550">
            {messages.length === 0 && (
              <div className="text-xs text-slate-400">
                Try:{" "}
                <span className="font-mono">
                  "Explain log4j and list CVEs affecting ServiceNow"
                </span>
              </div>
            )}

            {messages.map((msg, idx) =>
              msg.role === "user" ? (
                <div
                  key={idx}
                  className="self-end bg-blue-900 text-slate-100 rounded-2xl px-3 py-2 max-w-[80%] ml-auto"
                >
                  {msg.question}
                </div>
              ) : (
                renderAssistantMessage(msg, idx)
              )
            )}

            {loading && (
              <div className="text-xs text-slate-300">
                Assistant is thinking…
              </div>
            )}

            {error && (
              <div className="text-xs text-red-300">Error: {error}</div>
            )}
          </div>

          {/* Input */}
          <div className="border-t border-slate-400 p-2">
            <div className="flex gap-2 items-end">
              <textarea
                className="flex-1 resize-none rounded-xl bg-slate-800 border border-slate-700 text-slate-100 text-sm px-3 py-2 focus:outline-none focus:ring-1 focus:ring-blue-500"
                rows={2}
                placeholder="Ask a question about CVEs, products, years, severity..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
              />
              <button
                type="button"
                onClick={sendQuestion}
                disabled={loading || !input.trim()}
                className="rounded-xl bg-blue-600 hover:bg-blue-500 disabled:bg-blue-700 text-white px-3 py-2 text-sm font-medium"
              >
                {loading ? "Sending..." : "Send"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
