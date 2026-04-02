require("dotenv").config();

const app = require("./app");

const PORT = process.env.PORT || 3001;

// ================= Start Server =================
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// ================= Graceful Shutdown =================
process.on("SIGINT", () => {
  console.log("Shutting down server...");
  server.close(() => {
    console.log("Server closed.");
    process.exit(0);
  });
});