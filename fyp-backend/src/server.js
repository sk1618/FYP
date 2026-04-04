// src/server.js
// Entry point. Loads env vars before anything else so db.js and app.js
// receive them at require-time.
require("dotenv").config();

const app  = require("./app");
const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, () => {
  console.log(`[Server] Running on port ${PORT}`);
});

// Graceful shutdown — lets in-flight requests finish before the process exits.
process.on("SIGINT", () => {
  console.log("[Server] Shutting down...");
  server.close(() => {
    console.log("[Server] Closed.");
    process.exit(0);
  });
});
