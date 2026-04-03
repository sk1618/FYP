// src/components/ToolRunner.jsx
import { useState } from "react";

function ToolRunner({ onToolRun }) {
  const [tool, setTool] = useState("");
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);

  // ================= TOAST =================
  const showToast = (message, type = "success") => {
    setToast({ message, type });

    setTimeout(() => {
      setToast(null);
    }, 3000);
  };

  // ================= RUN TOOL =================
  const runTool = async () => {
    const trimmedTool = tool.trim();
    const trimmedTarget = target.trim();

    if (!trimmedTool || !trimmedTarget) {
      showToast("Please select a tool and enter a target", "error");
      return;
    }

    if (loading) return;

    setLoading(true);

    try {
      const res = await fetch(
        `${import.meta.env.VITE_API_BASE_URL}/api/tools/run`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tool: trimmedTool,
            target: trimmedTarget,
          }),
        }
      );

      const data = await res.json();

      if (data.success) {
        showToast("Scan completed successfully ✅", "success");

        // Reset inputs after success
        setTool("");
        setTarget("");

        if (onToolRun) {
          onToolRun();
        }
      } else {
        showToast(data.message || "Something went wrong", "error");
      }
    } catch (err) {
      showToast("Request failed: " + err.message, "error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ margin: "20px 0", position: "relative" }}>
      <h2>Tool Execution</h2>

      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <select
          value={tool}
          onChange={(e) => setTool(e.target.value)}
          disabled={loading}
        >
          <option value="">Select Tool</option>
          <option value="nmap">Nmap</option>
          <option value="metasploit">Metasploit</option>
        </select>

        <input
          type="text"
          placeholder="Enter Target IP"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={loading}
        />

        <button onClick={runTool} disabled={loading}>
          {loading ? "Running..." : "Run"}
        </button>
      </div>

      {/* ================= TOAST ================= */}
      {toast && (
        <div
          style={{
            position: "fixed",
            top: "20px",
            right: "20px",
            padding: "12px 16px",
            borderRadius: "8px",
            color: "#fff",
            backgroundColor:
              toast.type === "success" ? "#28a745" : "#dc3545",
            boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
            zIndex: 9999,
            minWidth: "220px",
            textAlign: "center",
          }}
        >
          {toast.message}
        </div>
      )}
    </div>
  );
}

export default ToolRunner;