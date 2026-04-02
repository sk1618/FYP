const express = require("express");
const router = express.Router();
const db = require("../db");
const { success, error } = require("../utils/response");

// ================= GET all vulnerabilities =================
router.get("/", (req, res) => {
  const query = `
    SELECT id, target_ip, vuln_name, severity, description, scan_date 
    FROM vulnerabilities 
    ORDER BY scan_date DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching vulnerabilities:", err);
      return error(res, "Database error", 500);
    }

    return success(res, results, "Vulnerabilities fetched successfully");
  });
});

// ================= GET single vulnerability =================
router.get("/:id", (req, res) => {
  const query = `
    SELECT id, target_ip, vuln_name, severity, description, scan_date 
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

    return success(
      res,
      results[0],
      "Vulnerability fetched successfully"
    );
  });
});

// ================= Create vulnerability =================
router.post("/", (req, res) => {
  const { target_ip, vuln_name, description, severity, scan_date } = req.body;

  const query = `
    INSERT INTO vulnerabilities 
    (target_ip, vuln_name, description, severity, scan_date)
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

module.exports = router;