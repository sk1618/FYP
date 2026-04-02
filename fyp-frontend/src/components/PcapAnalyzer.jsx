import React, { useState } from "react";
import axios from "axios";

function PcapAnalyzer() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!file) {
      alert("Please select a PCAP file first.");
      return;
    }

    const formData = new FormData();
    formData.append("pcap", file);

    try {
      setLoading(true);

      const res = await axios.post(
        "http://localhost:3001/api/ai/analyze-pcap",
        formData
      );

      setResult(res.data);
    } catch (error) {
      console.error("PCAP analysis error:", error);
      alert("Failed to analyze PCAP.");
    } finally {
      setLoading(false);
    }
  };

  return (
  <>
    <h2 style={{ marginBottom: "1rem" }}>AI PCAP Attack Analyzer</h2>

    <div
      style={{
        backgroundColor: "#1a1c2b",
        padding: "1.5rem",
        borderRadius: "10px",
        marginBottom: "2rem",
      }}
    >
      <input
        type="file"
        accept=".pcap"
        onChange={(e) => setFile(e.target.files[0])}
      />

      <button
        onClick={handleAnalyze}
        style={{
          marginLeft: "1rem",
          padding: "0.5rem 1rem",
          backgroundColor: "#007bff",
          color: "white",
          border: "none",
          borderRadius: "6px",
          cursor: "pointer",
        }}
      >
        Analyze
      </button>

      {loading && <p>Analyzing PCAP...</p>}

      {result && (
        <div style={{ marginTop: "1rem" }}>
          <h3>Attack Summary</h3>
          <pre>{JSON.stringify(result.summary, null, 2)}</pre>

          <h3>Detailed Attack Report</h3>
          <ul>
            {result.report.map((attack, index) => (
              <li key={index}>
                {attack.src_ip} → {attack.attack_type}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  </>
);
}

export default PcapAnalyzer;