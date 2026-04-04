// utils/vuln.js
// Shared vulnerability auto-creation logic.
// Actual DB columns: target_ip, vuln_name, description, severity, scan_date
const db = require("../db");

const POSITIVE_SIGNALS = [
  "cve", "vulnerable", "exploit completed",
  "session opened", "success", "confirmed",
];
const NEGATIVE_SIGNALS = [
  "no vulnerability", "not vulnerable", "failed",
];

function isVulnerable(description = "") {
  const lower = description.toLowerCase();
  return (
    POSITIVE_SIGNALS.some((s) => lower.includes(s)) &&
    !NEGATIVE_SIGNALS.some((s) => lower.includes(s))
  );
}

async function maybeCreateVulnerability(alertId, alertData) {
  if (!isVulnerable(alertData.description)) return;

  await db.execute(
    `INSERT INTO vulnerabilities (target_ip, vuln_name, description, severity, scan_date)
     VALUES (?, ?, ?, ?, NOW())`,
    [
      alertData.destination_ip,
      "Detected Vulnerability",
      alertData.description,
      "High",
    ]
  );
}

module.exports = { maybeCreateVulnerability, isVulnerable };
