// src/components/AlertsTable.jsx
import React from "react";

const severityColor = (severity) => {
  if (!severity) return "#fff";

  switch (severity.toLowerCase()) {
    case "high":
      return "red";
    case "medium":
      return "orange";
    case "low":
      return "green";
    default:
      return "#fff";
  }
};

const thStyle = {
  padding: "0.5rem",
  border: "1px solid #555",
  textAlign: "left",
};

const tdStyle = {
  padding: "0.5rem",
  border: "1px solid #555",
};

export default function AlertsTable({ alerts }) {
  return (
    <div style={{ padding: "1rem", marginTop: "2rem" }}>
      <h2>Alerts</h2>

      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          marginTop: "1rem",
        }}
      >
        <thead
          style={{
            backgroundColor: "#2a2c3b",
            position: "sticky",
            top: 0,
          }}
        >
          <tr>
            {/* ❌ ID REMOVED */}
            <th style={thStyle}>Source IP</th>
            <th style={thStyle}>Destination IP</th>
            <th style={thStyle}>Activity</th>
            <th style={thStyle}>Severity</th>
            <th style={thStyle}>Description</th>
            <th style={thStyle}>Timestamp</th> {/* ✅ NEW */}
          </tr>
        </thead>

        <tbody>
          {alerts.map((alert, idx) => (
            <tr
              key={alert.id}
              style={{
                backgroundColor:
                  idx % 2 === 0 ? "#1f1f2e" : "#232438",
                transition: "0.2s",
              }}
            >
              {/* ❌ Removed ID Cell */}
              <td style={tdStyle}>{alert.source_ip}</td>
              <td style={tdStyle}>{alert.destination_ip}</td>
              <td style={tdStyle}>{alert.activity_type}</td>

              <td
                style={{
                  ...tdStyle,
                  color: severityColor(alert.severity),
                  fontWeight: "bold",
                }}
              >
                {alert.severity}
              </td>

              <td style={tdStyle}>{alert.description}</td>

              {/* ✅ Format Timestamp */}
              <td style={tdStyle}>
                {alert.timestamp
                  ? new Date(alert.timestamp).toLocaleString()
                  : "N/A"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}