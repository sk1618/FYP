// src/db.js
// Uses mysql2/promise so every route can use async/await directly.
// dotenv is loaded once in server.js before anything else imports this.
const mysql = require("mysql2/promise");

const db = mysql.createPool({
  host:            process.env.DB_HOST,
  user:            process.env.DB_USER,
  password:        process.env.DB_PASSWORD,
  database:        process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT, 10) || 10,
  queueLimit:      0,
});

module.exports = db;
