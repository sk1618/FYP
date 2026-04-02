const db = require("../db");
const { runCommand } = require("../utils/toolRunner");

// Helper to run DB queries with promises
function queryAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });
}

exports.runTool = async (req, res) => {
  const { tool, target } = req.body;

  // ================= Validation =================
  if (!tool || !target) {
    return res.status(400).json({
      success: false,
      message: "Tool and target are required",
    });
  }

  if (typeof tool !== "string" || typeof target !== "string") {
    return res.status(400).json({
      success: false,
      message: "Invalid input types",
    });
  }

  if (tool.trim() === "" || target.trim() === "") {
    return res.status(400).json({
      success: false,
      message: "Tool and target cannot be empty",
    });
  }

  const allowedTools = ["nmap"];

  if (!allowedTools.includes(tool)) {
    return res.status(400).json({
      success: false,
      message: "Tool not allowed",
    });
  }

  // ================= Execution =================
  try {
    const output = await runCommand(tool.trim(), [target.trim()]);
    const vulnerabilities = parseNmap(output);

    // ================= DB Cleanup =================
    await queryAsync(
      "DELETE FROM vulnerabilities WHERE target_ip = ?",
      [target.trim()]
    );

    // ================= Insert Results =================
    if (vulnerabilities.length > 0) {
      const insertPromises = vulnerabilities.map((vuln) => {
        const query = `
          INSERT INTO vulnerabilities 
          (target_ip, vuln_name, description, severity)
          VALUES (?, ?, ?, ?)
        `;

        return queryAsync(query, [
          target.trim(),
          vuln.vuln_name,
          vuln.description,
          vuln.severity,
        ]);
      });

      await Promise.all(insertPromises);
    }

    return res.json({
      success: true,
      message: "Scan completed successfully",
      data: vulnerabilities,
    });

  } catch (err) {
    console.error("Tool execution error:", err.message);

    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
};

// ================= Helper =================
function parseNmap(output) {
  const lines = output.split("\n");
  const results = [];

  lines.forEach((line) => {
    const match = line.match(/^(\d+)\/tcp\s+open\s+(\S+)/);

    if (match) {
      results.push({
        vuln_name: `Open Port ${match[1]}`,
        description: `Service ${match[2]} running on port ${match[1]}`,
        severity: "Medium",
      });
    }
  });

  return results;
}