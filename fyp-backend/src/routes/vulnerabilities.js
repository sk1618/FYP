// routes/vulnerabilities.js
// Column names match the actual DB schema:
//   vuln_name, scan_date (not title/timestamp)
const express = require("express");
const router  = express.Router();
const db      = require("../db");
const { success, error } = require("../utils/response");

// ── GET all vulnerabilities (newest first) ────────────────────────────────────
router.get("/", async (_req, res, next) => {
  try {
    const [rows] = await db.execute(
      `SELECT id, target_ip, vuln_name, severity, description, scan_date
       FROM vulnerabilities ORDER BY scan_date DESC`
    );
    success(res, rows, "Vulnerabilities fetched successfully");
  } catch (err) {
    next(err);
  }
});

// ── GET single vulnerability ──────────────────────────────────────────────────
router.get("/:id", async (req, res, next) => {
  try {
    const [rows] = await db.execute(
      `SELECT id, target_ip, vuln_name, severity, description, scan_date
       FROM vulnerabilities WHERE id = ?`,
      [req.params.id]
    );
    if (!rows.length) return error(res, "Vulnerability not found", 404);
    success(res, rows[0], "Vulnerability fetched successfully");
  } catch (err) {
    next(err);
  }
});

// ── POST create vulnerability ─────────────────────────────────────────────────
router.post("/", async (req, res, next) => {
  const { target_ip, vuln_name, description, severity, scan_date } = req.body;

  try {
    const [result] = await db.execute(
      `INSERT INTO vulnerabilities (target_ip, vuln_name, description, severity, scan_date)
       VALUES (?, ?, ?, ?, ?)`,
      [target_ip, vuln_name, description, severity, scan_date || new Date()]
    );
    success(res, { vulnId: result.insertId }, "Vulnerability created successfully", 201);
  } catch (err) {
    next(err);
  }
});

// ── DELETE single vulnerability ───────────────────────────────────────────────
router.delete("/:id", async (req, res, next) => {
  try {
    await db.execute("DELETE FROM vulnerabilities WHERE id = ?", [req.params.id]);
    success(res, null, "Vulnerability deleted successfully");
  } catch (err) {
    next(err);
  }
});

// ── DELETE all vulnerabilities ────────────────────────────────────────────────
router.delete("/", async (_req, res, next) => {
  try {
    await db.execute("DELETE FROM vulnerabilities");
    success(res, null, "All vulnerabilities deleted successfully");
  } catch (err) {
    next(err);
  }
});

module.exports = router;
