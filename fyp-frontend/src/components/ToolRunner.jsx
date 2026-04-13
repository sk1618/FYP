// components/ToolRunner.jsx
// Executes Nmap or Metasploit against a target IP via the backend API.
// Uses VITE_API_BASE_URL from the .env — no hardcoded localhost.
// Keeps a log of the last 5 scans for visibility.
import React, { useState, useRef } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL;

// Auto-dismissing toast — shown for `duration` ms then faded out.
function useToast() {
  const [toast, setToast] = useState(null);
  const timerRef = useRef(null);

  const show = (message, type = "success") => {
    clearTimeout(timerRef.current);
    setToast({ message, type });
    timerRef.current = setTimeout(() => setToast(null), 3500);
  };

  return { toast, show };
}

function formatTime(date) {
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function ToolRunner({ onToolRun }) {
  const [tool,    setTool]    = useState("");
  const [target,  setTarget]  = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const { toast, show }       = useToast();

  const isLynis = tool === "lynis";

  const handleRun = async () => {
    const trimTool   = tool.trim();
    const trimTarget = isLynis ? "localhost" : target.trim();

    if (!trimTool || (!isLynis && !trimTarget)) {
      show("Select a tool and enter a target IP.", "error");
      return;
    }

    setLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/api/tools/run`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ tool: trimTool, target: trimTarget }),
      });
      const data = await res.json();

      if (data.success) {
        const count = data.data?.length ?? 0;
        show(`Scan completed — ${count} alert(s) generated.`, "success");

        // Prepend to scan history, keep last 5
        setHistory((prev) => [
          { tool: trimTool, target: trimTarget, count, ts: new Date() },
          ...prev,
        ].slice(0, 5));

        setTool("");
        setTarget("");
        onToolRun?.();
      } else {
        show(data.message || "Scan failed.", "error");
      }
    } catch (err) {
      show(`Request failed: ${err.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <div className="panel-title">⚙ Tool Execution</div>

      <div className="form-row">
        {/* Tool selector */}
        <div className="form-group">
          <label className="form-label">Tool</label>
          <select
            className="form-select"
            value={tool}
            onChange={(e) => setTool(e.target.value)}
            disabled={loading}
          >
            <option value="">Select…</option>
            <option value="nmap">Nmap</option>
            <option value="metasploit">Metasploit</option>
            <option value="nikto">Nikto</option>
            <option value="lynis">Lynis</option>
            <option value="hydra">Hydra</option>
            <option value="sqlmap">SQLMap</option>
          </select>
        </div>

        {/* Target IP */}
        <div className="form-group">
          <label className="form-label">
            {tool === "sqlmap" ? "Target IP / URL" : "Target IP"}
          </label>
          <input
            className="form-input"
            type="text"
            placeholder={isLynis ? "Not required for Lynis" : tool === "sqlmap" ? "e.g. 192.168.1.1 or http://site.com" : "e.g. 192.168.1.1"}
            value={isLynis ? "" : target}
            onChange={(e) => !isLynis && setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleRun()}
            disabled={loading || isLynis}
            style={isLynis ? { opacity: 0.35, cursor: "not-allowed" } : undefined}
          />
          {isLynis && (
            <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "0.3rem", display: "block" }}>
              Lynis audits this machine only — no remote target
            </span>
          )}
        </div>

        {/* Run button — aligned to bottom of the flex row */}
        <div style={{ paddingTop: "1.45rem" }}>
          <button className="btn btn--primary" onClick={handleRun} disabled={loading}>
            {loading ? <><span className="spinner" /> Running…</> : "▶ Run"}
          </button>
        </div>
      </div>

      {/* Toast */}
      {toast && (
        <div className={`toast toast--${toast.type}`}>
          {toast.type === "success" ? "✓" : "✕"} {toast.message}
        </div>
      )}

      {/* Scan history */}
      {history.length > 0 && (
        <div className="scan-history">
          <div className="scan-history-title">Recent Scans</div>
          <div className="scan-history-list">
            {history.map((h, i) => (
              <div key={i} className="scan-history-item">
                <span className="scan-history-tool">{h.tool}</span>
                <span className="scan-history-target">{h.target}</span>
                <span className="scan-history-count">{h.count} alert{h.count !== 1 ? "s" : ""}</span>
                <span className="scan-history-time">{formatTime(h.ts)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
