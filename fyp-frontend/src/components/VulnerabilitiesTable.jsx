// components/VulnerabilitiesTable.jsx
// Features: per-row delete, delete-all modal, filter, CSV export, pagination, loading skeleton.
import React, { useState, useMemo, useEffect } from "react";
import axios from "axios";

const API_BASE  = import.meta.env.VITE_API_BASE_URL;
const PAGE_SIZE = 25;

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
    { label: "Target IP",     key: "target_ip" },
    { label: "Vulnerability", key: "vuln_name" },
    { label: "Severity",      key: "severity" },
    { label: "Description",   key: "description" },
    { label: "Scan Date",     key: "scan_date" },
  ];

  const escape = (v) => {
    const s = String(v ?? "").replace(/"/g, '""');
    return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s}"` : s;
  };

  const csv = [
    cols.map((c) => c.label).join(","),
    ...data.map((row) => cols.map((c) => escape(row[c.key])).join(",")),
  ].join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Confirm modal ─────────────────────────────────────────────────────────────
function ConfirmModal({ onConfirm, onCancel }) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-icon">🗑️</div>
        <div className="modal-title">Delete all vulnerabilities?</div>
        <div className="modal-body">
          This will permanently remove every vulnerability from the database.
        </div>
        <div className="modal-actions">
          <button className="btn btn--ghost" onClick={onCancel}>Cancel</button>
          <button className="btn btn--danger" onClick={onConfirm}>Delete all</button>
        </div>
      </div>
    </div>
  );
}

// ── VulnerabilitiesTable ──────────────────────────────────────────────────────
export default function VulnerabilitiesTable({ vulnerabilities, onRefresh, loading }) {
  const [deletingId,  setDeletingId]  = useState(null);
  const [deleting,    setDeleting]    = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [search,      setSearch]      = useState("");
  const [severity,    setSeverity]    = useState("");
  const [page,        setPage]        = useState(1);

  const safeVulns = Array.isArray(vulnerabilities) ? vulnerabilities : [];

  const filtered = useMemo(() =>
    safeVulns.filter((v) => {
      const matchSev    = !severity || v.severity?.toLowerCase() === severity;
      const kw          = search.toLowerCase();
      const matchSearch = !search || [v.target_ip, v.vuln_name, v.description]
        .some((val) => val?.toLowerCase().includes(kw));
      return matchSev && matchSearch;
    }), [safeVulns, search, severity]
  );

  // Reset to page 1 whenever filters change
  useEffect(() => { setPage(1); }, [search, severity]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated  = useMemo(
    () => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [filtered, page]
  );

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

  const handleDeleteAll = async () => {
    setShowConfirm(false);
    setDeleting(true);
    try {
      await axios.delete(`${API_BASE}/api/vulnerabilities`);
      await onRefresh?.();
    } catch (err) {
      console.error("[VulnerabilitiesTable] Delete all error:", err);
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
            <span className="table-toolbar-title">Vulnerabilities</span>
            <span className="count-pill">{filtered.length} / {safeVulns.length}</span>
          </div>
          <div className="toolbar-actions">
            {safeVulns.length > 0 && (
              <button className="btn btn--ghost btn--sm" onClick={() => exportCSV(filtered)}>
                ↓ CSV
              </button>
            )}
            {safeVulns.length > 0 && (
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
        {safeVulns.length > 0 && (
          <div className="filter-bar">
            <input
              className="filter-input"
              type="text"
              placeholder="Search IP, vulnerability, description…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <select className="filter-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
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

        {/* Loading skeleton */}
        {loading && safeVulns.length === 0 ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Target IP</th><th>Vulnerability</th><th>Severity</th>
                  <th>Description</th><th>Scan Date</th><th></th>
                </tr>
              </thead>
              <tbody>
                {Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 6 }).map((_, j) => (
                      <td key={j}><div className="skeleton-cell" style={{ width: j === 5 ? 24 : "80%" }} /></td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🛡️</div>
            <div className="empty-state-text">
              {safeVulns.length === 0 ? "No vulnerabilities found." : "No vulnerabilities match your filters."}
            </div>
          </div>
        ) : (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Target IP</th><th>Vulnerability</th><th>Severity</th>
                    <th>Description</th><th>Scan Date</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  {paginated.map((vuln, idx) => (
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
                      <td className="td-desc" title={vuln.description}>{vuln.description || "—"}</td>
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

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="pagination">
                <button className="btn btn--ghost btn--sm"
                  onClick={() => setPage((p) => p - 1)} disabled={page === 1}>
                  ← Prev
                </button>
                <span className="pagination-info">Page {page} of {totalPages}</span>
                <button className="btn btn--ghost btn--sm"
                  onClick={() => setPage((p) => p + 1)} disabled={page === totalPages}>
                  Next →
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
