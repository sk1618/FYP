// components/ToolRunner.jsx
// Executes Nmap or Metasploit against a target IP via the backend API.
// Uses VITE_API_BASE_URL from the .env — no hardcoded localhost.
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

export default function ToolRunner({ onToolRun }) {
  const [tool,    setTool]    = useState("");
  const [target,  setTarget]  = useState("");
  const [loading, setLoading] = useState(false);
  const { toast, show }       = useToast();

  const handleRun = async () => {
    const trimTool   = tool.trim();
    const trimTarget = target.trim();

    if (!trimTool || !trimTarget) {
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
        show(`Scan completed — ${data.data?.length ?? 0} alert(s) generated.`, "success");
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
          </select>
        </div>

        {/* Target IP */}
        <div className="form-group">
          <label className="form-label">Target IP</label>
          <input
            className="form-input"
            type="text"
            placeholder="e.g. 192.168.1.1"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleRun()}
            disabled={loading}
          />
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
    </div>
  );
}
