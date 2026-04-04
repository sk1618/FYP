// components/VulnerabilitiesTable.jsx
// Features: per-row delete, filter by severity/IP/keyword, CSV export.
import React, { useState, useMemo } from "react";
import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE_URL;

function severityClass(severity) {
  switch (severity?.toLowerCase()) {
    case "high":   return "badge--high";
    case "medium": return "badge--medium";
    case "low":    return "badge--low";
    default:       return "badge--unknown";
  }
}

function formatDate(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

// ── CSV export ────────────────────────────────────────────────────────────────
function exportCSV(data) {
  const cols = [
    { label: "Target IP",      key: "target_ip" },
    { label: "Vulnerability",  key: "vuln_name" },
    { label: "Severity",       key: "severity" },
    { label: "Description",    key: "description" },
    { label: "Scan Date",      key: "scan_date" },
  ];

  const escape = (v) => {
    const s = String(v ?? "").replace(/"/g, '""');
    return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s}"` : s;
  };

  const header = cols.map((c) => c.label).join(",");
  const rows   = data.map((row) => cols.map((c) => escape(row[c.key])).join(","));
  const csv    = [header, ...rows].join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── VulnerabilitiesTable ──────────────────────────────────────────────────────
export default function VulnerabilitiesTable({ vulnerabilities, onRefresh }) {
  const [deletingId, setDeletingId] = useState(null);

  // Filter state
  const [search,   setSearch]   = useState("");
  const [severity, setSeverity] = useState("");

  const safeVulns = Array.isArray(vulnerabilities) ? vulnerabilities : [];

  const filtered = useMemo(() => {
    return safeVulns.filter((v) => {
      const matchSeverity = !severity || v.severity?.toLowerCase() === severity;
      const keyword       = search.toLowerCase();
      const matchSearch   = !search || [
        v.target_ip, v.vuln_name, v.description,
      ].some((val) => val?.toLowerCase().includes(keyword));
      return matchSeverity && matchSearch;
    });
  }, [safeVulns, search, severity]);

  const handleDeleteOne = async (id) => {
    setDeletingId(id);
    try {
      await axios.delete(`${API_BASE}/api/vulnerabilities/${id}`);
      await onRefresh?.();
    } catch (err) {
      console.error("[VulnerabilitiesTable] Delete error:", err);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="table-container">
      {/* Toolbar */}
      <div className="table-toolbar">
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <span className="table-toolbar-title">Vulnerabilities</span>
          <span className="count-pill">{filtered.length} / {safeVulns.length}</span>
        </div>

        {safeVulns.length > 0 && (
          <div className="toolbar-actions">
            <button className="btn btn--ghost btn--sm" onClick={() => exportCSV(filtered)}>
              ↓ CSV
            </button>
          </div>
        )}
      </div>

      {/* Filter bar */}
      {safeVulns.length > 0 && (
        <div className="filter-bar">
          <input
            className="filter-input"
            type="text"
            placeholder="Search IP, vulnerability, description…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="filter-select"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            <option value="">All severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          {(search || severity) && (
            <button className="btn btn--ghost btn--sm" onClick={() => { setSearch(""); setSeverity(""); }}>
              ✕ Clear
            </button>
          )}
        </div>
      )}

      {/* Empty state */}
      {filtered.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">🛡️</div>
          <div className="empty-state-text">
            {safeVulns.length === 0 ? "No vulnerabilities found." : "No vulnerabilities match your filters."}
          </div>
        </div>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Target IP</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Scan Date</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((vuln, idx) => (
                <tr key={vuln.id ?? idx}>
                  <td className="td-ip">{vuln.target_ip || "—"}</td>
                  <td>{vuln.vuln_name || "—"}</td>
                  <td>
                    <span className={`badge ${severityClass(vuln.severity)}`}>
                      {vuln.severity
                        ? vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1).toLowerCase()
                        : "Unknown"}
                    </span>
                  </td>
                  <td className="td-desc" title={vuln.description}>
                    {vuln.description || "—"}
                  </td>
                  <td className="td-time">{formatDate(vuln.scan_date)}</td>
                  <td>
                    <button
                      className="btn-row-delete"
                      onClick={() => handleDeleteOne(vuln.id)}
                      disabled={deletingId === vuln.id}
                      title="Delete this vulnerability"
                    >
                      {deletingId === vuln.id ? <span className="spinner" /> : "🗑"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
