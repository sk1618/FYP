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
  const safeVulns = Array.isArray(vulnerabilities) ? vulnerabilities : [];

  if (!vulnerabilities) {
    return <div style={{ padding: "1rem" }}>Loading vulnerabilities...</div>;
  }

  if (safeVulns.length === 0) {
    return <div style={{ padding: "1rem" }}>No vulnerabilities found.</div>;
  }

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
          {safeVulns.map((vuln, idx) => (
            <tr
              key={vuln.id || idx}
              style={{
                backgroundColor:
                  idx % 2 === 0 ? "#1f1f2e" : "#232438",
              }}
            >
              <td style={tdStyle}>{vuln.target_ip || "N/A"}</td>
              <td style={tdStyle}>{vuln.vuln_name || "N/A"}</td>

              <td
                style={{
                  ...tdStyle,
                  color: severityColor(vuln.severity),
                  fontWeight: "bold",
                }}
              >
                {capitalize(vuln.severity) || "N/A"}
              </td>

              <td style={tdStyle}>{vuln.description || "N/A"}</td>

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