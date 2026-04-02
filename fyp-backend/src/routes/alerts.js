const express = require("express");
const router = express.Router();
const db = require("../db");
const { success, error } = require("../utils/response");

// ================= GET all alerts =================
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

// ================= GET single alert =================
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

// ================= Create new alert =================
router.post("/", (req, res) => {
  const {
    source_ip,
    destination_ip,
    activity_type,
    severity,
    description,
  } = req.body;

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

      return success(
        res,
        { alertId: result.insertId },
        "Alert created successfully",
        201
      );
    }
  );
});

module.exports = router;