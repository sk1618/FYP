// src/App.jsx
import React, { useEffect, useState, useCallback } from "react";
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
  const [error, setError] = useState(null);

  const API_BASE = import.meta.env.VITE_API_BASE_URL;

  // ================= FETCH DATA =================
  const fetchData = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      if (!API_BASE) {
        throw new Error("VITE_API_BASE_URL is not defined");
      }

      const [alertsRes, vulnsRes] = await Promise.all([
        axios.get(`${API_BASE}/api/alerts`),
        axios.get(`${API_BASE}/api/vulnerabilities`)
      ]);

      const alertsData = alertsRes?.data?.data || [];
      const vulnsData = vulnsRes?.data?.data || [];

      setAlerts(alertsData);
      setVulnerabilities(vulnsData);

    } catch (err) {
      console.error("Fetch error:", err);
      setError("Failed to fetch data from backend.");
    } finally {
      setRefreshing(false);
    }
  }, [API_BASE]);

  // Fetch once on load
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // ================= SEVERITY COUNTS =================
  const countBySeverity = (arr, level) =>
    arr.filter((item) => item.severity?.toLowerCase() === level).length;

  const alertsHigh = countBySeverity(alerts, "high");
  const alertsMedium = countBySeverity(alerts, "medium");
  const alertsLow = countBySeverity(alerts, "low");

  const vulnsHigh = countBySeverity(vulnerabilities, "high");
  const vulnsMedium = countBySeverity(vulnerabilities, "medium");
  const vulnsLow = countBySeverity(vulnerabilities, "low");

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
      {/* HEADER */}
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

      {/* MAIN */}
      <main
        style={{
          flex: 1,
          padding: "2rem",
          maxWidth: "1200px",
          margin: "0 auto",
          width: "100%",
        }}
      >
        {/* REFRESH STATUS */}
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

        {/* ERROR */}
        {error && (
          <div
            style={{
              textAlign: "center",
              marginBottom: "1rem",
              color: "red",
              fontWeight: "bold",
            }}
          >
            {error}
          </div>
        )}

        {/* SUMMARY */}
        <SummaryCards
          alertsLow={alertsLow}
          alertsMedium={alertsMedium}
          alertsHigh={alertsHigh}
          vulnsLow={vulnsLow}
          vulnsMedium={vulnsMedium}
          vulnsHigh={vulnsHigh}
        />

        {/* TOOL RUNNER */}
        <ToolRunner
          onToolRun={fetchData}
          onSuccess={() => alert("Scan completed successfully ✅")}
        />

        {/* PCAP ANALYZER */}
        <PcapAnalyzer />

        {/* TABLES */}
        <AlertsTable alerts={alerts} onRefresh={fetchData} />
        <VulnerabilitiesTable vulnerabilities={vulnerabilities} />
      </main>
    </div>
  );
}

export default App;