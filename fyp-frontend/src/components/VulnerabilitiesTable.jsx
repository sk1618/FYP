// src/components/VulnerabilitiesTable.jsx
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

// ✅ Capitalize helper
const capitalize = (str) => {
  if (!str) return "";
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
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

export default function VulnerabilitiesTable({ vulnerabilities }) {
  return (
    <div style={{ padding: "1rem", marginTop: "2rem" }}>
      <h2>Vulnerabilities</h2>

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
            <th style={thStyle}>Target IP</th>
            <th style={thStyle}>Vulnerability</th>
            <th style={thStyle}>Severity</th>
            <th style={thStyle}>Description</th>
            <th style={thStyle}>Scan Date</th>
          </tr>
        </thead>

        <tbody>
          {vulnerabilities.map((vuln, idx) => (
            <tr
              key={vuln.id}
              style={{
                backgroundColor:
                  idx % 2 === 0 ? "#1f1f2e" : "#232438",
                transition: "0.2s",
              }}
            >
              <td style={tdStyle}>{vuln.target_ip}</td>
              <td style={tdStyle}>{vuln.vuln_name}</td>

              <td
                style={{
                  ...tdStyle,
                  color: severityColor(vuln.severity),
                  fontWeight: "bold",
                }}
              >
                {capitalize(vuln.severity)}
              </td>

              <td style={tdStyle}>{vuln.description}</td>

              <td style={tdStyle}>
                {vuln.scan_date
                  ? new Date(vuln.scan_date).toLocaleString()
                  : "N/A"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}