// src/app.js
// dotenv is loaded in server.js before this module is required.
const express = require("express");
const cors    = require("cors");

const alertsRoutes        = require("./routes/alerts");
const vulnerabilitiesRoutes = require("./routes/vulnerabilities");
const toolsRoutes         = require("./routes/tools");
const aiRoutes            = require("./routes/ai");

const app = express();

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Routes ────────────────────────────────────────────────────────────────────
app.use("/api/alerts",          alertsRoutes);
app.use("/api/vulnerabilities", vulnerabilitiesRoutes);
app.use("/api/tools",           toolsRoutes);
app.use("/api/ai",              aiRoutes);

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/", (_req, res) => {
  res.json({ success: true, message: "FYP Security Monitoring API is running." });
});

// ── Global error handler ──────────────────────────────────────────────────────
// Catches anything passed to next(err) in route handlers.
app.use((err, _req, res, _next) => {
  console.error("[Server Error]", err.message);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Internal Server Error",
  });
});

module.exports = app;
