// src/App.jsx
import React, { useEffect, useState } from "react";
import axios from "axios";
import SummaryCards from "./components/SummaryCards";
import AlertsTable from "./components/AlertsTable";
import VulnerabilitiesTable from "./components/VulnerabilitiesTable";
import ToolRunner from "./components/ToolRunner";
import PcapAnalyzer from "./components/PcapAnalyzer";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [refreshing, setRefreshing] = useState(false);

  // ================= FETCH DATA =================
  const fetchData = async () => {
    try {
      setRefreshing(true);

      const alertsRes = await axios.get(
        `${import.meta.env.VITE_API_BASE_URL}/api/alerts`
      );

      const vulnsRes = await axios.get(
        `${import.meta.env.VITE_API_BASE_URL}/api/vulnerabilities`
      );

      setAlerts(alertsRes.data.data);
      setVulnerabilities(vulnsRes.data.data);
    } catch (err) {
      console.error("Fetch error:", err);
    } finally {
      setRefreshing(false);
    }
  };

  // Fetch once on load
  useEffect(() => {
    fetchData();
  }, []);

  // ================= SEVERITY COUNTS =================
  const alertsHigh = alerts.filter(
    (a) => a.severity?.toLowerCase() === "high"
  ).length;

  const alertsMedium = alerts.filter(
    (a) => a.severity?.toLowerCase() === "medium"
  ).length;

  const alertsLow = alerts.filter(
    (a) => a.severity?.toLowerCase() === "low"
  ).length;

  const vulnsHigh = vulnerabilities.filter(
    (v) => v.severity?.toLowerCase() === "high"
  ).length;

  const vulnsMedium = vulnerabilities.filter(
    (v) => v.severity?.toLowerCase() === "medium"
  ).length;

  const vulnsLow = vulnerabilities.filter(
    (v) => v.severity?.toLowerCase() === "low"
  ).length;

  // ================= GLOBAL STYLING =================
  useEffect(() => {
    document.body.style.margin = "0";
    document.body.style.backgroundColor = "#0f111a";
  }, []);

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "#0f111a",
        color: "#fff",
        display: "flex",
        flexDirection: "column",
        fontFamily: "Arial, sans-serif",
      }}
    >
      {/* ================= HEADER ================= */}
      <header
        style={{
          backgroundColor: "#1a1c2b",
          padding: "1rem 2rem",
          textAlign: "center",
          fontSize: "1.8rem",
          fontWeight: "bold",
          boxShadow: "0 2px 4px rgba(0,0,0,0.5)",
        }}
      >
        Cybersecurity Monitoring Dashboard
      </header>

      {/* ================= MAIN CONTENT ================= */}
      <main
        style={{
          flex: 1,
          padding: "2rem",
          maxWidth: "1200px",
          margin: "0 auto",
          width: "100%",
        }}
      >
        {/* ================= REFRESH STATUS ================= */}
        {refreshing && (
          <div
            style={{
              textAlign: "center",
              marginBottom: "1rem",
              color: "#00ffcc",
              fontWeight: "bold",
            }}
          >
            Refreshing dashboard...
          </div>
        )}

        {/* ================= SUMMARY ================= */}
        <SummaryCards
          alertsLow={alertsLow}
          alertsMedium={alertsMedium}
          alertsHigh={alertsHigh}
          vulnsLow={vulnsLow}
          vulnsMedium={vulnsMedium}
          vulnsHigh={vulnsHigh}
        />

        {/* ================= TOOL RUNNER ================= */}
        <ToolRunner
          onToolRun={fetchData}
          onSuccess={() => alert("Scan completed successfully ✅")}
        />

        {/* ================= PCAP ANALYZER ================= */}
        <PcapAnalyzer />

        {/* ================= TABLES ================= */}
        <AlertsTable alerts={alerts} />
        <VulnerabilitiesTable vulnerabilities={vulnerabilities} />
      </main>
    </div>
  );
}

export default App;