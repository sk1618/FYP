// src/App.jsx
import React, { useEffect, useState, useCallback, useRef } from "react";
import axios from "axios";
import SummaryCards         from "./components/SummaryCards";
import SeverityChart        from "./components/SeverityChart";
import AlertsTable          from "./components/AlertsTable";
import VulnerabilitiesTable from "./components/VulnerabilitiesTable";
import ToolRunner           from "./components/ToolRunner";
import PcapAnalyzer         from "./components/PcapAnalyzer";

const API_BASE        = import.meta.env.VITE_API_BASE_URL;
const REFRESH_INTERVAL = 30; // seconds

const countBySeverity = (arr, level) =>
  arr.filter((item) => item.severity?.toLowerCase() === level).length;

function formatTime(date) {
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function App() {
  const [alerts,          setAlerts]          = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [refreshing,      setRefreshing]      = useState(false);
  const [error,           setError]           = useState(null);
  const [lastUpdated,     setLastUpdated]      = useState(null);

  // Auto-refresh state
  const [autoRefresh,  setAutoRefresh]  = useState(false);
  const [countdown,    setCountdown]    = useState(REFRESH_INTERVAL);
  const intervalRef    = useRef(null);
  const countdownRef   = useRef(null);

  const fetchData = useCallback(async () => {
    if (!API_BASE) { setError("VITE_API_BASE_URL is not configured."); return; }
    setRefreshing(true);
    setError(null);
    try {
      const [alertsRes, vulnsRes] = await Promise.all([
        axios.get(`${API_BASE}/api/alerts`),
        axios.get(`${API_BASE}/api/vulnerabilities`),
      ]);
      setAlerts(alertsRes.data?.data ?? []);
      setVulnerabilities(vulnsRes.data?.data ?? []);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("[App] Fetch error:", err);
      setError("Could not reach the backend. Is it running?");
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Auto-refresh: fetch every REFRESH_INTERVAL seconds + show countdown
  useEffect(() => {
    if (autoRefresh) {
      setCountdown(REFRESH_INTERVAL);

      intervalRef.current = setInterval(() => {
        fetchData();
        setCountdown(REFRESH_INTERVAL);
      }, REFRESH_INTERVAL * 1000);

      countdownRef.current = setInterval(() => {
        setCountdown((c) => (c > 0 ? c - 1 : REFRESH_INTERVAL));
      }, 1000);
    } else {
      clearInterval(intervalRef.current);
      clearInterval(countdownRef.current);
    }
    return () => {
      clearInterval(intervalRef.current);
      clearInterval(countdownRef.current);
    };
  }, [autoRefresh, fetchData]);

  const counts = {
    alertsHigh:   countBySeverity(alerts,          "high"),
    alertsMedium: countBySeverity(alerts,          "medium"),
    alertsLow:    countBySeverity(alerts,          "low"),
    vulnsHigh:    countBySeverity(vulnerabilities, "high"),
    vulnsMedium:  countBySeverity(vulnerabilities, "medium"),
    vulnsLow:     countBySeverity(vulnerabilities, "low"),
  };

  return (
    <div className="dashboard">
      <header className="header">
        <div className="header-brand">
          <div className="header-brand-icon">🛡️</div>
          <div>
            <div className="header-title">CyberSec Monitor</div>
            <div className="header-sub">Security Operations Dashboard</div>
          </div>
        </div>

        <div className="header-right">
          {lastUpdated && (
            <span className="last-updated">Updated {formatTime(lastUpdated)}</span>
          )}

          {/* Auto-refresh toggle */}
          <button
            className={`btn-refresh ${autoRefresh ? "btn-refresh--active" : ""}`}
            onClick={() => setAutoRefresh((v) => !v)}
            title={autoRefresh ? "Click to stop auto-refresh" : "Click to enable auto-refresh"}
          >
            {autoRefresh ? `⏱ ${countdown}s` : "⏱ Auto"}
          </button>

          <div className="live-badge">
            <span className="live-dot" />
            Live
          </div>

          <button className="btn-refresh" onClick={fetchData} disabled={refreshing}>
            {refreshing ? <span className="spinner" /> : "↻"}
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
        </div>
      </header>

      <main className="main">
        {error && <div className="error-banner">⚠ {error}</div>}

        <SummaryCards counts={counts} vulnerabilities={vulnerabilities} />

        <SeverityChart alerts={alerts} />

        <div className="panels-row">
          <ToolRunner onToolRun={fetchData} />
          <PcapAnalyzer />
        </div>

        <AlertsTable alerts={alerts} onRefresh={fetchData} loading={refreshing} />
        <VulnerabilitiesTable vulnerabilities={vulnerabilities} onRefresh={fetchData} loading={refreshing} />
      </main>
    </div>
  );
}
