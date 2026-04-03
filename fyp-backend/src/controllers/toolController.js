const db = require("../db");
const { runCommand } = require("../utils/toolRunner");

// ================= Helper: query with promises =================
function queryAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });
}

// ================= Helper: process alert → vulnerability =================
async function processAlertToVulnerability(alertId, alertData) {
  const text = (alertData.description || "").toLowerCase();

  const isVulnerable =
    text.includes("cve") ||
    text.includes("vulnerable") ||
    text.includes("exploit completed") ||
    text.includes("session opened") ||
    text.includes("success") ||
    text.includes("confirmed");

  const isNegative =
    text.includes("no vulnerability") ||
    text.includes("not vulnerable") ||
    text.includes("failed");

  if (isVulnerable && !isNegative) {
    const insertQuery = `
      INSERT INTO vulnerabilities
      (scan_id, target_ip, title, description, severity, source_alert_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    try {
      await queryAsync(insertQuery, [
        `scan-${Date.now()}`,
        alertData.destination_ip,
        "Detected Vulnerability",
        alertData.description,
        "High",
        alertId
      ]);

      console.log("✅ Vulnerability inserted");
    } catch (err) {
      console.error("❌ Error inserting vulnerability:", err);
    }
  }
}

// ================= RUN TOOL =================
exports.runTool = async (req, res) => {
  const { tool, target } = req.body;

  console.log("=== TOOL REQUEST RECEIVED ===", tool, target);

  if (!tool || !target || typeof tool !== "string" || typeof target !== "string") {
    return res.status(400).json({ success: false, message: "Tool and target are required" });
  }

  const allowedTools = ["nmap", "metasploit"];
  if (!allowedTools.includes(tool)) {
    return res.status(400).json({ success: false, message: "Tool not allowed" });
  }

  // ================= NMAP =================
  if (tool === "nmap") {
    try {
      console.log("🚀 Running Nmap scan on:", target);

      const output = await runCommand("nmap", [target.trim()]);
      const alerts = parseNmapToAlerts(output, target.trim());

      for (const alert of alerts) {
        const result = await queryAsync(`
          INSERT INTO alerts
          (source_ip, destination_ip, activity_type, severity, description)
          VALUES (?, ?, ?, ?, ?)`,
          [alert.source_ip, alert.destination_ip, alert.activity_type, alert.severity, alert.description]
        );

        await processAlertToVulnerability(result.insertId, alert);
      }

      return res.json({
        success: true,
        message: "Nmap scan completed",
        data: alerts
      });

    } catch (err) {
      console.error("❌ Nmap error:", err);
      return res.status(500).json({ success: false, message: err.message });
    }
  }

  // ================= METASPLOIT =================
  if (tool === "metasploit") {
    try {
      console.log("🚀 Running Metasploit scan on:", target);

      const scanId = `scan-${Date.now()}`;

      // Step 1: Nmap to detect ports
      const nmapOutput = await runCommand("nmap", [target.trim()]);
      const ports = extractOpenPortsFromNmap(nmapOutput);

      if (ports.length === 0) {
        return res.json({
          success: true,
          message: "No open ports detected",
          data: []
        });
      }

      // Step 2: Module mapping
      const moduleMap = {
        "21": ["auxiliary/scanner/ftp/ftp_version"],
        "22": ["auxiliary/scanner/ssh/ssh_version"],
        "80": ["auxiliary/scanner/http/http_version"],
        "443": ["auxiliary/scanner/ssl/ssl_version"],
        "445": ["auxiliary/scanner/smb/smb_ms17_010"],
        "3306": ["auxiliary/scanner/mysql/mysql_version"],
      };

      let allAlerts = [];

      // Step 3: Run modules
      for (const port of ports) {
        const modules = moduleMap[port];
        if (!modules) continue;

        for (const module of modules) {
          const command = `msfconsole -q -x "use ${module}; set RHOSTS ${target}; run; exit"`;

          try {
            const output = await runCommand("bash", ["-c", command]);
            const parsedAlerts = parseMetasploitModuleOutput(output, target, port);
            allAlerts = allAlerts.concat(parsedAlerts);
          } catch (err) {
            console.error(`❌ Module failed on port ${port}:`, err.message);
          }
        }
      }

      // Step 4: Insert alerts + vulnerabilities
      for (const alert of allAlerts) {
        const result = await queryAsync(`
          INSERT INTO alerts
          (source_ip, destination_ip, activity_type, severity, description)
          VALUES (?, ?, ?, ?, ?)`,
          [alert.source_ip, alert.destination_ip, alert.activity_type, alert.severity, alert.description]
        );

        await processAlertToVulnerability(result.insertId, alert);
      }

      return res.json({
        success: true,
        message: "Metasploit scan completed",
        data: allAlerts
      });

    } catch (err) {
      console.error("❌ Metasploit error:", err);
      return res.status(500).json({ success: false, message: err.message });
    }
  }
};

// ================= DELETE ALERTS =================
exports.clearAlerts = async (req, res) => {
  try {
    await queryAsync("DELETE FROM alerts");
    return res.json({ success: true, message: "All alerts deleted" });
  } catch (err) {
    console.error("❌ Delete alerts error:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
};

// ================= NMAP PARSER =================
function parseNmapToAlerts(output, target) {
  const lines = output.split("\n");
  const results = [];

  lines.forEach(line => {
    const match = line.match(/^(\d+)\/tcp\s+open\s+(\S+)/);
    if (match) {
      results.push({
        source_ip: "scanner",
        destination_ip: target,
        activity_type: `Open Port ${match[1]}`,
        severity: "Low",
        description: `Service ${match[2]} running on port ${match[1]} (Nmap)`
      });
    }
  });

  return results;
}

// ================= PORT EXTRACTOR =================
function extractOpenPortsFromNmap(output) {
  const lines = output.split("\n");
  const ports = [];

  lines.forEach(line => {
    const match = line.match(/^(\d+)\/tcp\s+open/);
    if (match) ports.push(match[1]);
  });

  return [...new Set(ports)];
}

// ================= METASPLOIT PARSER =================
function parseMetasploitModuleOutput(output, target, port) {
  const lines = output.split("\n");
  const results = [];

  let service = "Unknown";

  if (port == "80") service = "HTTP";
  else if (port == "443") service = "HTTPS";
  else if (port == "22") service = "SSH";
  else if (port == "21") service = "FTP";
  else if (port == "3306") service = "MySQL";
  else if (port == "445") service = "SMB";

  const outputLower = output.toLowerCase();

  const positiveSignals = [
    "session opened",
    "exploit completed",
    "meterpreter",
    "cve",
    "vulnerable",
    "success"
  ];

  const negativeSignals = [
    "no vulnerability",
    "not vulnerable",
    "failed",
    "error"
  ];

  const isPositive = positiveSignals.some(sig => outputLower.includes(sig));
  const isNegative = negativeSignals.some(sig => outputLower.includes(sig));

  if (isPositive && !isNegative) {
    results.push({
      source_ip: "scanner",
      destination_ip: target,
      activity_type: `Service ${service} on port ${port}`,
      severity: "High",
      description: `Metasploit indicates potential vulnerability on ${service} (${port})`
    });
  }

  // Always create alert
  results.push({
    source_ip: "scanner",
    destination_ip: target,
    activity_type: `Scan ${service} (${port})`,
    severity: isPositive && !isNegative ? "High" : "Low",
    description: `Metasploit module executed for ${service} but analysis result: ${
      isPositive && !isNegative ? "vulnerable" : "no vulnerability detected"
    }`
  });

  return results;
}