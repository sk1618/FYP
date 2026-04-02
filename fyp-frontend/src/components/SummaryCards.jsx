// src/components/SummaryCards.jsx
import React from "react";

export default function SummaryCards({
  alertsLow,
  alertsMedium,
  alertsHigh,
  vulnsLow,
  vulnsMedium,
  vulnsHigh,
}) {
  const cardStyle = (borderColor) => ({
    flex: "1 1 250px",
    padding: "1.5rem",
    borderRadius: "14px",
    backgroundColor: "#1f1f2e",
    textAlign: "center",
    fontWeight: "600",
    boxShadow: "0 4px 12px rgba(0,0,0,0.6)",
    borderLeft: `6px solid ${borderColor}`,
    transition: "transform 0.2s",
  });

  const sectionStyle = {
    marginBottom: "2rem",
  };

  return (
    <div style={{ margin: "2rem 0" }}>
      {/* ================= ALERTS SECTION ================= */}
      <div style={sectionStyle}>
        <h2 style={{ marginBottom: "1rem" }}>Alerts Summary</h2>

        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "1rem",
          }}
        >
          <div style={cardStyle("green")}>
            <h2>{alertsLow}</h2>
            <p>Low Alerts</p>
          </div>

          <div style={cardStyle("orange")}>
            <h2>{alertsMedium}</h2>
            <p>Medium Alerts</p>
          </div>

          <div style={cardStyle("red")}>
            <h2>{alertsHigh}</h2>
            <p>High Alerts</p>
          </div>
        </div>
      </div>

      {/* ================= VULNERABILITIES SECTION ================= */}
      <div>
        <h2 style={{ marginBottom: "1rem" }}>Vulnerabilities Summary</h2>

        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "1rem",
          }}
        >
          <div style={cardStyle("green")}>
            <h2>{vulnsLow}</h2>
            <p>Low Vulnerabilities</p>
          </div>

          <div style={cardStyle("orange")}>
            <h2>{vulnsMedium}</h2>
            <p>Medium Vulnerabilities</p>
          </div>

          <div style={cardStyle("red")}>
            <h2>{vulnsHigh}</h2>
            <p>High Vulnerabilities</p>
          </div>
        </div>
      </div>
    </div>
  );
}