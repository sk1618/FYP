// components/SummaryCards.jsx
import React from "react";

const ALERT_CARDS = [
  { key: "alertsHigh",   label: "High Alerts",   variant: "high" },
  { key: "alertsMedium", label: "Medium Alerts",  variant: "medium" },
  { key: "alertsLow",    label: "Low Alerts",     variant: "low" },
];

function StatCard({ value, label, variant }) {
  return (
    <div className={`stat-card stat-card--${variant}`}>
      <div className="stat-number">{value ?? 0}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function VulnSummary({ counts, vulnerabilities = [] }) {
  const total = vulnerabilities.length;

  // Top 5 unique targets by vuln count
  const targetMap = {};
  for (const v of vulnerabilities) {
    const ip = v.target_ip || "Unknown";
    targetMap[ip] = (targetMap[ip] || 0) + 1;
  }
  const topTargets = Object.entries(targetMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const maxCount = topTargets[0]?.[1] || 1;

  return (
    <div className="vuln-summary-panel">
      {/* Left — total count */}
      <div className="vuln-summary-left">
        <div className="vuln-summary-total">{total}</div>
        <div className="vuln-summary-label">Total Vulnerabilities</div>
        <div className="vuln-summary-sub">
          <span className="badge badge--high" style={{ fontSize: "0.7rem" }}>
            {counts.vulnsHigh ?? 0} High
          </span>
        </div>
      </div>

      {/* Divider */}
      <div className="vuln-summary-divider" />

      {/* Right — top targets */}
      <div className="vuln-summary-right">
        <div className="vuln-summary-targets-title">Top Vulnerable Targets</div>
        {topTargets.length === 0 ? (
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", marginTop: "0.5rem" }}>
            No data yet
          </div>
        ) : (
          <div className="vuln-targets-list">
            {topTargets.map(([ip, count]) => (
              <div key={ip} className="vuln-target-row">
                <span className="vuln-target-ip">{ip}</span>
                <div className="vuln-target-bar-wrap">
                  <div
                    className="vuln-target-bar"
                    style={{ width: `${(count / maxCount) * 100}%` }}
                  />
                </div>
                <span className="vuln-target-count">{count}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function SummaryCards({ counts = {}, vulnerabilities = [] }) {
  return (
    <div className="summary-row">
      {/* Alerts */}
      <div className="summary-col">
        <div className="section-label">Alerts</div>
        <div className="cards-grid">
          {ALERT_CARDS.map(({ key, label, variant }) => (
            <StatCard key={key} value={counts[key]} label={label} variant={variant} />
          ))}
        </div>
      </div>

      {/* Vulnerabilities */}
      <div className="summary-col">
        <div className="section-label">Vulnerabilities</div>
        <VulnSummary counts={counts} vulnerabilities={vulnerabilities} />
      </div>
    </div>
  );
}
