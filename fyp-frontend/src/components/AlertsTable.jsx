// components/AlertsTable.jsx
// Features: per-row delete, filter by severity/IP/keyword, CSV export, delete-all modal.
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
    { label: "Source IP",      key: "source_ip" },
    { label: "Destination IP", key: "destination_ip" },
    { label: "Activity",       key: "activity_type" },
    { label: "Severity",       key: "severity" },
    { label: "Description",    key: "description" },
    { label: "Timestamp",      key: "timestamp" },
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
  a.download = `alerts-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Confirm modal ─────────────────────────────────────────────────────────────
function ConfirmModal({ onConfirm, onCancel }) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-icon">🗑️</div>
        <div className="modal-title">Delete all alerts?</div>
        <div className="modal-body">
          This will permanently remove every alert from the database.
        </div>
        <div className="modal-actions">
          <button className="btn btn--ghost" onClick={onCancel}>Cancel</button>
          <button className="btn btn--danger" onClick={onConfirm}>Delete all</button>
        </div>
      </div>
    </div>
  );
}

// ── AlertsTable ───────────────────────────────────────────────────────────────
export default function AlertsTable({ alerts, onRefresh }) {
  const [deleting,    setDeleting]    = useState(false);
  const [deletingId,  setDeletingId]  = useState(null);
  const [showConfirm, setShowConfirm] = useState(false);

  // Filter state
  const [search,   setSearch]   = useState("");
  const [severity, setSeverity] = useState("");

  const safeAlerts = Array.isArray(alerts) ? alerts : [];

  // Apply filters client-side
  const filtered = useMemo(() => {
    return safeAlerts.filter((a) => {
      const matchSeverity = !severity || a.severity?.toLowerCase() === severity;
      const keyword       = search.toLowerCase();
      const matchSearch   = !search || [
        a.source_ip, a.destination_ip, a.activity_type, a.description,
      ].some((v) => v?.toLowerCase().includes(keyword));
      return matchSeverity && matchSearch;
    });
  }, [safeAlerts, search, severity]);

  // Delete single row
  const handleDeleteOne = async (id) => {
    setDeletingId(id);
    try {
      await axios.delete(`${API_BASE}/api/alerts/${id}`);
      await onRefresh?.();
    } catch (err) {
      console.error("[AlertsTable] Delete error:", err);
    } finally {
      setDeletingId(null);
    }
  };

  // Delete all
  const handleDeleteAll = async () => {
    setShowConfirm(false);
    setDeleting(true);
    try {
      await axios.delete(`${API_BASE}/api/alerts`);
      await onRefresh?.();
    } catch (err) {
      console.error("[AlertsTable] Delete all error:", err);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <>
      {showConfirm && (
        <ConfirmModal onConfirm={handleDeleteAll} onCancel={() => setShowConfirm(false)} />
      )}

      <div className="table-container">
        {/* Toolbar */}
        <div className="table-toolbar">
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
            <span className="table-toolbar-title">Alerts</span>
            <span className="count-pill">{filtered.length} / {safeAlerts.length}</span>
          </div>

          <div className="toolbar-actions">
            {safeAlerts.length > 0 && (
              <button className="btn btn--ghost btn--sm" onClick={() => exportCSV(filtered)}>
                ↓ CSV
              </button>
            )}
            {safeAlerts.length > 0 && (
              <button
                className="btn btn--danger btn--sm"
                onClick={() => setShowConfirm(true)}
                disabled={deleting}
              >
                {deleting ? <><span className="spinner" /> Deleting…</> : "🗑 Delete all"}
              </button>
            )}
          </div>
        </div>

        {/* Filter bar */}
        {safeAlerts.length > 0 && (
          <div className="filter-bar">
            <input
              className="filter-input"
              type="text"
              placeholder="Search IP, activity, description…"
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
            <div className="empty-state-icon">📭</div>
            <div className="empty-state-text">
              {safeAlerts.length === 0 ? "No alerts recorded yet." : "No alerts match your filters."}
            </div>
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Activity</th>
                  <th>Severity</th>
                  <th>Description</th>
                  <th>Timestamp</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((alert, idx) => (
                  <tr key={alert.id ?? idx}>
                    <td className="td-ip">{alert.source_ip || "—"}</td>
                    <td className="td-ip">{alert.destination_ip || "—"}</td>
                    <td>{alert.activity_type || "—"}</td>
                    <td>
                      <span className={`badge ${severityClass(alert.severity)}`}>
                        {alert.severity || "Unknown"}
                      </span>
                    </td>
                    <td className="td-desc" title={alert.description}>
                      {alert.description || "—"}
                    </td>
                    <td className="td-time">{formatDate(alert.timestamp)}</td>
                    <td>
                      <button
                        className="btn-row-delete"
                        onClick={() => handleDeleteOne(alert.id)}
                        disabled={deletingId === alert.id}
                        title="Delete this alert"
                      >
                        {deletingId === alert.id ? <span className="spinner" /> : "🗑"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
