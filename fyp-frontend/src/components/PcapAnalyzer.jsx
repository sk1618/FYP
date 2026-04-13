// components/PcapAnalyzer.jsx
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

  return (
    <div className="panel">
      <div className="panel-title">🔬 AI PCAP Analyzer</div>

      <div className="file-row">
        <label className="file-label">
          📂 {file ? "Change .pcap file" : "Choose .pcap file"}
          <input type="file" accept=".pcap" onChange={handleFileChange} />
        </label>

        {file && (
          <span className="file-name" title={file.name}>
            {file.name}
          </span>
        )}
      </div>

      <div
        style={{
          display: "flex",
          gap: "0.75rem",
          alignItems: "center",
          flexWrap: "wrap",
          marginTop: "0.9rem",
        }}
      >
        <button
          className="btn btn--primary"
          onClick={handleAnalyze}
          disabled={loading || liveLoading || !file}
        >
          {loading ? "Analyzing..." : "Analyze"}
        </button>

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
          style={{
            background: "linear-gradient(135deg, #7c3aed, #2563eb)",
          }}
        >
          {liveLoading ? "Live Scanning..." : "LiveScan"}
        </button>
      </div>

      <div
        style={{
          marginTop: "0.65rem",
          fontSize: "0.9rem",
          opacity: 0.8,
        }}
      >
        LiveScan captures packets on the backend for a few seconds, then analyzes them with the AI model.
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
              <div className="pcap-section-title">Attack Distribution Chart</div>
              <img
                src={`${API_BASE}/ai-assets/${result.chart_file}?t=${Date.now()}`}
                alt="Attack distribution chart"
                className="pcap-chart-img"
                onError={(e) => {
                  e.currentTarget.style.display = "none";
                }}
              />
            </div>
          )}

          <div className="pcap-result-section">
            <div className="pcap-section-title">Attack Summary</div>
            <pre className="pcap-pre">{JSON.stringify(result.summary, null, 2)}</pre>
          </div>

          {Array.isArray(result.report) && result.report.length > 0 && (
            <div className="pcap-result-section">
              <div className="pcap-section-title">
                Detected Events ({result.report.length})
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
        </div>
      )}
    </div>
  );
}