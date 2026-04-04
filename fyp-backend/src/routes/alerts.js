// routes/alerts.js
// Full async/await using the mysql2 promise pool (db.execute).
// Vulnerability auto-creation is delegated to utils/vuln.js so the logic
// isn't duplicated across this file and toolController.js.
const express = require("express");
const router  = express.Router();
const db      = require("../db");
const { success, error }         = require("../utils/response");
const { maybeCreateVulnerability } = require("../utils/vuln");

// ── GET all alerts (newest first) ─────────────────────────────────────────────
router.get("/", async (_req, res, next) => {
  try {
    const [rows] = await db.execute(`
      SELECT id, source_ip, destination_ip, activity_type,
             severity, description, timestamp
      FROM   alerts
      ORDER  BY timestamp DESC
    `);
    success(res, rows, "Alerts fetched successfully");
  } catch (err) {
    next(err);
  }
});

// ── GET single alert ──────────────────────────────────────────────────────────
router.get("/:id", async (req, res, next) => {
  try {
    const [rows] = await db.execute(
      `SELECT id, source_ip, destination_ip, activity_type,
              severity, description, timestamp
       FROM   alerts
       WHERE  id = ?`,
      [req.params.id]
    );
    if (!rows.length) return error(res, "Alert not found", 404);
    success(res, rows[0], "Alert fetched successfully");
  } catch (err) {
    next(err);
  }
});

// ── POST create alert ─────────────────────────────────────────────────────────
router.post("/", async (req, res, next) => {
  const { source_ip, destination_ip, activity_type, severity, description } = req.body;

  try {
    const [result] = await db.execute(
      `INSERT INTO alerts
         (source_ip, destination_ip, activity_type, severity, description)
       VALUES (?, ?, ?, ?, ?)`,
      [source_ip, destination_ip, activity_type, severity, description]
    );

    // Fire-and-forget: don't block the response if vuln creation fails.
    maybeCreateVulnerability(result.insertId, {
      source_ip, destination_ip, activity_type, severity, description,
    }).catch((err) => console.error("[alerts] Auto-vuln creation failed:", err.message));

    success(res, { alertId: result.insertId }, "Alert created successfully", 201);
  } catch (err) {
    next(err);
  }
});

// ── DELETE single alert ───────────────────────────────────────────────────────
router.delete("/:id", async (req, res, next) => {
  try {
    await db.execute("DELETE FROM alerts WHERE id = ?", [req.params.id]);
    success(res, null, "Alert deleted successfully");
  } catch (err) {
    next(err);
  }
});

// ── DELETE all alerts ─────────────────────────────────────────────────────────
router.delete("/", async (_req, res, next) => {
  try {
    await db.execute("DELETE FROM alerts");
    success(res, null, "All alerts deleted successfully");
  } catch (err) {
    next(err);
  }
});

module.exports = router;
