require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express(); // define app first

// ================= Middleware =================
app.use(cors());
app.use(express.json());

// Import routes
const alertsRoutes = require("./routes/alerts");
const vulnerabilitiesRoutes = require("./routes/vulnerabilities");
const toolsRoutes = require("./routes/tools");
const aiRoutes = require("./routes/ai");

// ================= Routes =================
app.use("/api/alerts", alertsRoutes);
app.use("/api/vulnerabilities", vulnerabilitiesRoutes);
app.use("/api/tools", toolsRoutes);
app.use("/api/ai", aiRoutes);

// ================= Root Test Endpoint =================
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "FYP Security Monitoring API is running babyygirl.",
  });
});

// ================= Global Error Handler =================
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err);

  res.status(500).json({
    success: false,
    message: "Internal Server Error",
  });
});

// Export app for server.js
module.exports = app;