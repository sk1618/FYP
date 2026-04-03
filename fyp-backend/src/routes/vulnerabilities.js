const express = require("express");
const router = express.Router();
const db = require("../db");
const { success, error } = require("../utils/response");

// ================= GET ALL VULNERABILITIES =================
router.get("/", (req, res) => {
  const query = `
    SELECT 
      id, 
      target_ip, 
      title AS vuln_name, 
      severity, 
      description, 
      timestamp AS scan_date
    FROM vulnerabilities 
    ORDER BY timestamp DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching vulnerabilities:", err);
      return error(res, "Database error", 500);
    }

    return success(res, results, "Vulnerabilities fetched successfully");
  });
});

// ================= GET SINGLE VULNERABILITY =================
router.get("/:id", (req, res) => {
  const query = `
    SELECT 
      id, 
      target_ip, 
      title AS vuln_name, 
      severity, 
      description, 
      timestamp AS scan_date
    FROM vulnerabilities 
    WHERE id = ?
  `;

  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      console.error("Error fetching vulnerability:", err);
      return error(res, "Database error", 500);
    }

    if (results.length === 0) {
      return error(res, "Vulnerability not found", 404);
    }

    return success(res, results[0], "Vulnerability fetched successfully");
  });
});

// ================= CREATE VULNERABILITY =================
router.post("/", (req, res) => {
  const { target_ip, vuln_name, description, severity, scan_date } = req.body;

  const query = `
    INSERT INTO vulnerabilities 
    (target_ip, title, description, severity, timestamp)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [target_ip, vuln_name, description, severity, scan_date || new Date()],
    (err, result) => {
      if (err) {
        console.error("Error inserting vulnerability:", err);
        return error(res, "Database error", 500);
      }

      return success(
        res,
        { vulnId: result.insertId },
        "Vulnerability created successfully",
        201
      );
    }
  );
});

// ================= DELETE SINGLE VULNERABILITY =================
router.delete("/:id", (req, res) => {
  const query = "DELETE FROM vulnerabilities WHERE id = ?";

  db.query(query, [req.params.id], (err, result) => {
    if (err) {
      console.error("Error deleting vulnerability:", err);
      return error(res, "Database error", 500);
    }

    return success(res, null, "Vulnerability deleted successfully");
  });
});

// ================= DELETE ALL VULNERABILITIES =================
router.delete("/", (req, res) => {
  const query = "DELETE FROM vulnerabilities";

  db.query(query, (err, result) => {
    if (err) {
      console.error("Error deleting all vulnerabilities:", err);
      return error(res, "Database error", 500);
    }

    return success(res, null, "All vulnerabilities deleted successfully");
  });
});

module.exports = router;