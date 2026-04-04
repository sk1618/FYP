// routes/tools.js
const express = require("express");
const router  = express.Router();
const { runTool, clearAlerts } = require("../controllers/toolController");

// POST /api/tools/run  — execute nmap or metasploit against a target
router.post("/run", runTool);

// DELETE /api/tools/alerts — convenience endpoint to wipe all alerts
router.delete("/alerts", clearAlerts);

module.exports = router;
