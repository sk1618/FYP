// components/SummaryCards.jsx
// Receives a single `counts` object instead of six individual props —
// cleaner API and easier to extend with new severity levels.
import React from "react";

// Each card definition: which key to read from `counts`, label text, and CSS variant.
const ALERT_CARDS = [
  { key: "alertsHigh",   label: "High Alerts",   variant: "high" },
  { key: "alertsMedium", label: "Medium Alerts",  variant: "medium" },
  { key: "alertsLow",    label: "Low Alerts",     variant: "low" },
];

const VULN_CARDS = [
  { key: "vulnsHigh",   label: "High Vulns",   variant: "high" },
  { key: "vulnsMedium", label: "Medium Vulns",  variant: "medium" },
  { key: "vulnsLow",    label: "Low Vulns",     variant: "low" },
];

function StatCard({ value, label, variant }) {
  return (
    <div className={`stat-card stat-card--${variant}`}>
      <div className="stat-number">{value ?? 0}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export default function SummaryCards({ counts = {} }) {
  return (
    <>
      {/* Alerts */}
      <div className="cards-group">
        <div className="section-label">Alerts</div>
        <div className="cards-grid">
          {ALERT_CARDS.map(({ key, label, variant }) => (
            <StatCard key={key} value={counts[key]} label={label} variant={variant} />
          ))}
        </div>
      </div>

      {/* Vulnerabilities */}
      <div className="cards-group">
        <div className="section-label">Vulnerabilities</div>
        <div className="cards-grid">
          {VULN_CARDS.map(({ key, label, variant }) => (
            <StatCard key={key} value={counts[key]} label={label} variant={variant} />
          ))}
        </div>
      </div>
    </>
  );
}
