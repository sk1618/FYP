// routes/alerts.js
const express = require("express");
const router = express.Router();
const db = require("../db");
const { success, error } = require("../utils/response");

// ================= HELPER: process alert → vulnerability =================
function processAlertToVulnerability(alertId, alertData) {
  const desc = (alertData.description || "").toLowerCase();
  const activity = (alertData.activity_type || "").toLowerCase();

  // Only create vulnerabilities for actual findings
  if (desc.includes("vulnerable") || desc.includes("cve")) {
    const title = "Potential Vulnerability Detected";
    const severity = "High";

    const insertQuery = `
      INSERT INTO vulnerabilities
      (target_ip, vuln_name, description, severity, source_alert_id)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.query(
      insertQuery,
      [
        alertData.destination_ip,
        title,
        alertData.description,
        severity,
        alertId,
      ],
      (err) => {
        if (err) {
          console.error("Error inserting vulnerability:", err);
        }
      }
    );
  }
}

// ================= GET ALL ALERTS =================
router.get("/", (req, res) => {
  const query = `
    SELECT id, source_ip, destination_ip, activity_type, severity, description, timestamp
    FROM alerts
    ORDER BY timestamp DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching alerts:", err);
      return error(res, "Database error", 500);
    }

    return success(res, results, "Alerts fetched successfully");
  });
});

// ================= GET SINGLE ALERT =================
router.get("/:id", (req, res) => {
  const query = `
    SELECT id, source_ip, destination_ip, activity_type, severity, description, timestamp
    FROM alerts
    WHERE id = ?
  `;

  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      console.error("Error fetching alert:", err);
      return error(res, "Database error", 500);
    }

    if (results.length === 0) {
      return error(res, "Alert not found", 404);
    }

    return success(res, results[0], "Alert fetched successfully");
  });
});

// ================= CREATE NEW ALERT =================
router.post("/", (req, res) => {
  const { source_ip, destination_ip, activity_type, severity, description } =
    req.body;

  const query = `
    INSERT INTO alerts 
    (source_ip, destination_ip, activity_type, severity, description)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [source_ip, destination_ip, activity_type, severity, description],
    (err, result) => {
      if (err) {
        console.error("Error inserting alert:", err);
        return error(res, "Database error", 500);
      }

      const alertId = result.insertId;

      // ✅ Only process actual vulnerabilities
      processAlertToVulnerability(alertId, {
        source_ip,
        destination_ip,
        activity_type,
        severity,
        description,
      });

      return success(res, { alertId }, "Alert created successfully", 201);
    }
  );
});

// ================= DELETE SINGLE ALERT =================
router.delete("/:id", (req, res) => {
  const query = "DELETE FROM alerts WHERE id = ?";

  db.query(query, [req.params.id], (err, result) => {
    if (err) {
      console.error("Error deleting alert:", err);
      return error(res, "Database error", 500);
    }

    return success(res, null, "Alert deleted successfully");
  });
});

// ================= DELETE ALL ALERTS =================
router.delete("/", (req, res) => {
  const query = "DELETE FROM alerts";

  db.query(query, (err, result) => {
    if (err) {
      console.error("Error deleting all alerts:", err);
      return error(res, "Database error", 500);
    }

    return success(res, null, "All alerts deleted successfully");
  });
});

module.exports = router;