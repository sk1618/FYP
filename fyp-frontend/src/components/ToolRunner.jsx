import { useState } from "react";

function ToolRunner({ onToolRun, onSuccess }) {
  const [tool, setTool] = useState("");
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);

  const runTool = async () => {
    if (!tool || !target) {
      alert("Please select a tool and enter a target");
      return;
    }

    setLoading(true);

    try {
      const res = await fetch(
        `${import.meta.env.VITE_API_BASE_URL}/api/tools/run`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ tool, target }),
        }
      );

      const data = await res.json();

      if (data.success) {
        // ✅ Popup
        if (onSuccess) {
          onSuccess();
        }

        // ✅ Refresh dashboard
        if (onToolRun) {
          onToolRun();
        }
      } else {
        alert(data.message || "Something went wrong");
      }
    } catch (err) {
      alert("Request failed: " + err.message);
    }

    setLoading(false);
  };

  return (
    <div style={{ margin: "20px 0" }}>
      <h2>Tool Execution</h2>

      <select
        value={tool}
        onChange={(e) => setTool(e.target.value)}
        disabled={loading}
      >
        <option value="">Select Tool</option>
        <option value="nmap">Nmap</option>
      </select>

      <input
        type="text"
        placeholder="Enter Target IP"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        style={{ marginLeft: "10px" }}
        disabled={loading}
      />

      <button
        onClick={runTool}
        style={{ marginLeft: "10px" }}
        disabled={loading}
      >
        {loading ? "Running..." : "Run"}
      </button>
    </div>
  );
}

export default ToolRunner;