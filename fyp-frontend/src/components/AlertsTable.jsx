import React, { useState } from "react";
import axios from "axios";

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

export default function AlertsTable({ alerts, onRefresh }) {
  const [loading, setLoading] = useState(false);

  const safeAlerts = Array.isArray(alerts) ? alerts : [];

  if (!alerts) {
    return <div style={{ padding: "1rem" }}>Loading alerts...</div>;
  }

  const handleDeleteAll = async () => {
    const confirmDelete = window.confirm(
      "Are you sure you want to delete ALL alerts?"
    );

    if (!confirmDelete) return;

    try {
      setLoading(true);

      await axios.delete("http://localhost:3001/api/alerts");

      if (onRefresh) {
        await onRefresh();
      }

      alert("All alerts deleted successfully");
    } catch (err) {
      console.error(err);
      alert("Failed to delete alerts");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "1rem", marginTop: "2rem" }}>
      <h2>Alerts</h2>

      {/* DELETE BUTTON (ONLY SHOW IF DATA EXISTS) */}
      {safeAlerts.length > 0 && (
        <button
          onClick={handleDeleteAll}
          disabled={loading}
          style={{
            marginTop: "1rem",
            marginBottom: "1rem",
            padding: "0.5rem 1rem",
            backgroundColor: "red",
            color: "white",
            border: "none",
            cursor: "pointer",
          }}
        >
          {loading ? "Deleting..." : "Delete All Alerts"}
        </button>
      )}

      {/* EMPTY STATE */}
      {safeAlerts.length === 0 ? (
        <div style={{ marginTop: "1rem" }}>No alerts found.</div>
      ) : (
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
              <th style={thStyle}>Source IP</th>
              <th style={thStyle}>Destination IP</th>
              <th style={thStyle}>Activity</th>
              <th style={thStyle}>Severity</th>
              <th style={thStyle}>Description</th>
              <th style={thStyle}>Timestamp</th>
            </tr>
          </thead>

          <tbody>
            {safeAlerts.map((alert, idx) => (
              <tr
                key={alert.id || idx}
                style={{
                  backgroundColor: idx % 2 === 0 ? "#1f1f2e" : "#232438",
                }}
              >
                <td style={tdStyle}>{alert.source_ip || "N/A"}</td>
                <td style={tdStyle}>{alert.destination_ip || "N/A"}</td>
                <td style={tdStyle}>{alert.activity_type || "N/A"}</td>

                <td
                  style={{
                    ...tdStyle,
                    color: severityColor(alert.severity),
                    fontWeight: "bold",
                  }}
                >
                  {alert.severity || "N/A"}
                </td>

                <td style={tdStyle}>{alert.description || "N/A"}</td>

                <td style={tdStyle}>
                  {alert.timestamp
                    ? new Date(alert.timestamp).toLocaleString()
                    : "N/A"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}