const express = require("express");
const router = express.Router();
const { runTool, clearAlerts } = require("../controllers/toolController");

// Run tools (nmap / metasploit)
router.post("/run", runTool);

// Delete all alerts
router.delete("/alerts", clearAlerts);

module.exports = router;