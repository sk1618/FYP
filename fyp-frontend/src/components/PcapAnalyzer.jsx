import React, { useState } from "react";
import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE_URL;

export default function PcapAnalyzer() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [liveLoading, setLiveLoading] = useState(false);
  const [error, setError] = useState(null);
  const [duration, setDuration] = useState(10);

  const handleFileChange = (e) => {
    setFile(e.target.files[0] || null);
    setResult(null);
    setError(null);
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError("Please select a .pcap file first.");
      return;
    }

    const formData = new FormData();
    formData.append("pcap", file);

    setLoading(true);
    setLiveLoading(false);
    setError(null);
    setResult(null);

    try {
      const res = await axios.post(`${API_BASE}/api/ai/analyze-pcap`, formData);
      setResult(res.data);
    } catch (err) {
      console.error("[PcapAnalyzer] Upload analysis error:", err);
      setError(err.response?.data?.error || "Analysis failed. Check console for details.");
    } finally {
      setLoading(false);
    }
  };

  const handleLiveScan = async () => {
    setLiveLoading(true);
    setLoading(false);
    setError(null);
    setResult(null);

    try {
      const res = await axios.post(`${API_BASE}/api/ai/live-scan`, {
        duration,
        iface: "any",
      });
      setResult(res.data);
    } catch (err) {
      console.error("[PcapAnalyzer] Live scan error:", err);
      setError(err.response?.data?.error || "Live scan failed. Check console for details.");
    } finally {
      setLiveLoading(false);
    }
  };

  const featuresUsed = result?.features_used || [];
  const trainingMetrics = result?.training_metrics || {};
  const liveComparison = result?.live_comparison || {};

  return (
    <div className="panel">
      <div className="panel-title">🔬 AI PCAP Analyzer</div>

      <div
        style={{
          display: "flex",
          gap: "0.75rem",
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <label className="file-label">
          📂 {file ? "Change .pcap file" : "Choose .pcap file"}
          <input type="file" accept=".pcap" onChange={handleFileChange} />
        </label>

        {file && (
          <span className="file-name" title={file.name}>
            {file.name}
          </span>
        )}

        <button
          className="btn btn--primary"
          onClick={handleAnalyze}
          disabled={loading || liveLoading || !file}
        >
          {loading ? "Analyzing..." : "Analyze"}
        </button>
      </div>

      <div
        style={{
          display: "flex",
          gap: "0.75rem",
          alignItems: "center",
          marginTop: "0.75rem",
          flexWrap: "wrap",
        }}
      >
        <select
          value={duration}
          onChange={(e) => setDuration(Number(e.target.value))}
          disabled={loading || liveLoading}
          style={{
            padding: "0.55rem 0.8rem",
            borderRadius: "10px",
            border: "1px solid rgba(255,255,255,0.15)",
            background: "#111827",
            color: "white",
          }}
        >
          <option value={5}>5 sec</option>
          <option value={10}>10 sec</option>
          <option value={15}>15 sec</option>
          <option value={20}>20 sec</option>
          <option value={30}>30 sec</option>
          <option value={45}>45 sec</option>
          <option value={60}>60 sec</option>
        </select>

        <button
          className="btn btn--primary"
          onClick={handleLiveScan}
          disabled={loading || liveLoading}
          style={{ background: "linear-gradient(135deg, #7c3aed, #2563eb)" }}
        >
          {liveLoading ? "Live Scanning..." : "LiveScan"}
        </button>

        <span
          style={{
            fontSize: "0.78rem",
            color: "rgba(255,255,255,0.45)",
            fontStyle: "italic",
            letterSpacing: "0.01em",
          }}
        >
          Captures live packets on the backend, then classifies traffic with the AI model.
        </span>
      </div>

      {error && (
        <div className="error-banner" style={{ marginTop: "0.75rem" }}>
          ⚠ {error}
        </div>
      )}

      {result && (
        <div className="pcap-result">
          {result.chart_file && (
            <div className="pcap-result-section">
              <div className="pcap-section-title">Random Forest Attack Distribution</div>
              <img
                src={`${API_BASE}/ai-assets/${result.chart_file}?t=${Date.now()}`}
                alt="Random Forest attack distribution chart"
                className="pcap-chart-img"
                onError={(e) => {
                  e.currentTarget.style.display = "none";
                }}
              />
            </div>
          )}

          {result.lr_chart_file && (
            <div className="pcap-result-section">
              <div className="pcap-section-title">Logistic Regression Attack Distribution</div>
              <img
                src={`${API_BASE}/ai-assets/${result.lr_chart_file}?t=${Date.now()}`}
                alt="Logistic Regression attack distribution chart"
                className="pcap-chart-img"
                onError={(e) => {
                  e.currentTarget.style.display = "none";
                }}
              />
            </div>
          )}

          <div className="pcap-result-section">
            <div className="pcap-section-title">Attack Summary (Current Run - Random Forest)</div>
            <pre className="pcap-pre">{JSON.stringify(result.summary, null, 2)}</pre>
          </div>

          {result.lr_summary && (
            <div className="pcap-result-section">
              <div className="pcap-section-title">Attack Summary (Current Run - Logistic Regression)</div>
              <pre className="pcap-pre">{JSON.stringify(result.lr_summary, null, 2)}</pre>
            </div>
          )}

          {Array.isArray(result.report) && result.report.length > 0 && (
            <div className="pcap-result-section">
              <div className="pcap-section-title">
                Detected Groups (Random Forest) ({result.report.length})
              </div>
              <ul className="pcap-list">
                {result.report.map((item, idx) => (
                  <li key={idx} className="pcap-item">
                    <span className="pcap-ip">{item.src_ip}</span>
                    <span className="pcap-arrow">→</span>
                    <span className="pcap-type">{item.attack_type}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {featuresUsed.length > 0 && (
            <div className="pcap-result-section">
              <div className="pcap-section-title">Features Used by the Models</div>
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: "0.5rem",
                  marginTop: "0.5rem",
                }}
              >
                {featuresUsed.map((feature, idx) => (
                  <span
                    key={idx}
                    style={{
                      padding: "0.35rem 0.65rem",
                      borderRadius: "999px",
                      background: "rgba(59,130,246,0.15)",
                      border: "1px solid rgba(59,130,246,0.25)",
                      color: "#93c5fd",
                      fontSize: "0.82rem",
                    }}
                  >
                    {feature}
                  </span>
                ))}
              </div>
            </div>
          )}

          {Object.keys(trainingMetrics).length > 0 && (
            <div className="pcap-result-section">
              <div className="pcap-section-title">Model Evaluation Metrics (Training / Validation)</div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                  gap: "1rem",
                  marginTop: "0.75rem",
                }}
              >
                {Object.entries(trainingMetrics).map(([modelName, values]) => (
                  <div
                    key={modelName}
                    style={{
                      background: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(255,255,255,0.08)",
                      borderRadius: "14px",
                      padding: "1rem",
                    }}
                  >
                    <div
                      style={{
                        fontWeight: "700",
                        marginBottom: "0.75rem",
                        color: "#e2e8f0",
                        fontSize: "0.95rem",
                      }}
                    >
                      {modelName}
                    </div>

                    <div style={{ display: "grid", gap: "0.45rem", fontSize: "0.88rem" }}>
                      <div><strong>Accuracy:</strong> {values.accuracy !== undefined ? Number(values.accuracy).toFixed(3) : "N/A"}</div>
                      <div><strong>Precision:</strong> {values.precision !== undefined ? Number(values.precision).toFixed(3) : "N/A"}</div>
                      <div><strong>Recall:</strong> {values.recall !== undefined ? Number(values.recall).toFixed(3) : "N/A"}</div>
                      <div><strong>F1:</strong> {values.f1 !== undefined ? Number(values.f1).toFixed(3) : "N/A"}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {Object.keys(liveComparison).length > 0 && (
            <div className="pcap-result-section">
              <div className="pcap-section-title">Live Scan Detection Comparison (Current Run)</div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
                  gap: "1rem",
                  marginTop: "0.75rem",
                }}
              >
                {Object.entries(liveComparison).map(([modelName, values]) => (
                  <div
                    key={modelName}
                    style={{
                      background: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(255,255,255,0.08)",
                      borderRadius: "14px",
                      padding: "1rem",
                    }}
                  >
                    <div
                      style={{
                        fontWeight: "700",
                        marginBottom: "0.75rem",
                        color: "#e2e8f0",
                        fontSize: "0.95rem",
                      }}
                    >
                      {modelName}
                    </div>

                    <div style={{ display: "grid", gap: "0.45rem", fontSize: "0.88rem" }}>
                      <div><strong>Estimated Malicious Events:</strong> {values.attacks_detected ?? 0}</div>
                      <div><strong>Detected Groups:</strong> {values.groups_detected ?? 0}</div>
                    </div>

                    <div style={{ marginTop: "0.75rem" }}>
                      <strong style={{ fontSize: "0.88rem" }}>Top Detected Types:</strong>
                      <pre className="pcap-pre" style={{ marginTop: "0.5rem" }}>
                        {JSON.stringify(values.summary || {}, null, 2)}
                      </pre>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}