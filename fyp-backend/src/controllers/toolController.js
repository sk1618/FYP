// controllers/toolController.js
// Orchestrates Nmap and Metasploit scans, persists results to the DB, and
// auto-creates vulnerability records via the shared vuln utility.
const db      = require("../db");
const { runCommand }             = require("../utils/toolRunner");
const { maybeCreateVulnerability } = require("../utils/vuln");

// ── Constants ─────────────────────────────────────────────────────────────────

const ALLOWED_TOOLS = new Set(["nmap", "metasploit"]);

// Maps open TCP port numbers to human-readable service names.
const PORT_SERVICE = {
  21:   "FTP",
  22:   "SSH",
  80:   "HTTP",
  443:  "HTTPS",
  445:  "SMB",
  3306: "MySQL",
};

// Maps port numbers to the Metasploit auxiliary modules to run against them.
const MSF_MODULES = {
  21:   ["auxiliary/scanner/ftp/ftp_version"],
  22:   ["auxiliary/scanner/ssh/ssh_version"],
  80:   ["auxiliary/scanner/http/http_version"],
  443:  ["auxiliary/scanner/ssl/ssl_version"],
  445:  ["auxiliary/scanner/smb/smb_ms17_010"],
  3306: ["auxiliary/scanner/mysql/mysql_version"],
};

// ── DB helpers ────────────────────────────────────────────────────────────────

/**
 * Inserts an alert row and conditionally creates a linked vulnerability.
 * Returns the new alert's insertId.
 */
async function insertAlert(alertData) {
  const [result] = await db.execute(
    `INSERT INTO alerts
       (source_ip, destination_ip, activity_type, severity, description)
     VALUES (?, ?, ?, ?, ?)`,
    [
      alertData.source_ip,
      alertData.destination_ip,
      alertData.activity_type,
      alertData.severity,
      alertData.description,
    ]
  );
  // Fire-and-forget — don't let a vuln-insert error abort the alert loop.
  maybeCreateVulnerability(result.insertId, alertData).catch((err) =>
    console.error("[toolController] Vuln creation failed:", err.message)
  );
  return result.insertId;
}

// ── Parsers ───────────────────────────────────────────────────────────────────

/**
 * Converts raw nmap stdout into an array of alert objects.
 * Matches lines like: "22/tcp   open  ssh"
 */
function parseNmapOutput(output, target) {
  return output
    .split("\n")
    .map((line) => line.match(/^(\d+)\/tcp\s+open\s+(\S+)/))
    .filter(Boolean)
    .map(([, port, service]) => ({
      source_ip:     "scanner",
      destination_ip: target,
      activity_type: `Open Port ${port}`,
      severity:      "Low",
      description:   `Service "${service}" detected on TCP port ${port} (Nmap)`,
    }));
}

/**
 * Extracts the set of open TCP port numbers from nmap stdout.
 */
function extractOpenPorts(output) {
  return [
    ...new Set(
      output
        .split("\n")
        .map((line) => line.match(/^(\d+)\/tcp\s+open/))
        .filter(Boolean)
        .map(([, port]) => parseInt(port, 10))
    ),
  ];
}

/**
 * Converts Metasploit module stdout into alert objects.
 * Creates one "scan result" alert and, if positive signals are found,
 * an additional "vulnerability" alert.
 */
function parseMetasploitOutput(output, target, port) {
  const lower   = output.toLowerCase();
  const service = PORT_SERVICE[port] || "Unknown";

  const POSITIVE = ["session opened", "exploit completed", "meterpreter", "cve", "vulnerable", "success"];
  const NEGATIVE = ["no vulnerability", "not vulnerable", "failed", "error"];

  const isVuln =
    POSITIVE.some((s) => lower.includes(s)) &&
    !NEGATIVE.some((s) => lower.includes(s));

  const alerts = [
    {
      source_ip:     "scanner",
      destination_ip: target,
      activity_type: `Scan ${service} (port ${port})`,
      severity:      isVuln ? "High" : "Low",
      description:   isVuln
        ? `Metasploit detected a potential vulnerability on ${service} port ${port}`
        : `Metasploit found no vulnerabilities on ${service} port ${port}`,
    },
  ];

  // Second, higher-signal alert when the module confirms exploitation potential.
  if (isVuln) {
    alerts.push({
      source_ip:     "scanner",
      destination_ip: target,
      activity_type: `Confirmed: ${service} port ${port}`,
      severity:      "High",
      description:   `Metasploit confirmed exploit potential on ${service} (port ${port})`,
    });
  }

  return alerts;
}

// ── Exported handlers ─────────────────────────────────────────────────────────

exports.runTool = async (req, res) => {
  const { tool, target } = req.body;

  if (!tool || !target || typeof tool !== "string" || typeof target !== "string") {
    return res.status(400).json({ success: false, message: "tool and target are required strings" });
  }

  const normalizedTool   = tool.trim().toLowerCase();
  const normalizedTarget = target.trim();

  if (!ALLOWED_TOOLS.has(normalizedTool)) {
    return res.status(400).json({ success: false, message: `Tool "${tool}" is not allowed` });
  }

  try {
    // ── Nmap ────────────────────────────────────────────────────────────────
    if (normalizedTool === "nmap") {
      const output = await runCommand("nmap", [normalizedTarget]);
      const alerts = parseNmapOutput(output, normalizedTarget);
      await Promise.all(alerts.map(insertAlert));
      return res.json({ success: true, message: "Nmap scan completed", data: alerts });
    }

    // ── Metasploit ──────────────────────────────────────────────────────────
    if (normalizedTool === "metasploit") {
      // Step 1: discover open ports.
      const nmapOutput = await runCommand("nmap", [normalizedTarget]);
      const ports      = extractOpenPorts(nmapOutput);

      if (!ports.length) {
        return res.json({ success: true, message: "No open ports detected", data: [] });
      }

      // Step 2: run the appropriate MSF module for each known port.
      const allAlerts = [];
      for (const port of ports) {
        const modules = MSF_MODULES[port];
        if (!modules) continue;

        for (const mod of modules) {
          const cmd = `msfconsole -q -x "use ${mod}; set RHOSTS ${normalizedTarget}; run; exit"`;
          try {
            const output = await runCommand("bash", ["-c", cmd]);
            allAlerts.push(...parseMetasploitOutput(output, normalizedTarget, port));
          } catch (err) {
            console.error(`[metasploit] Module ${mod} on port ${port} failed:`, err.message);
          }
        }
      }

      await Promise.all(allAlerts.map(insertAlert));
      return res.json({ success: true, message: "Metasploit scan completed", data: allAlerts });
    }
  } catch (err) {
    console.error(`[${normalizedTool}] Error:`, err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
};

exports.clearAlerts = async (_req, res) => {
  try {
    await db.execute("DELETE FROM alerts");
    res.json({ success: true, message: "All alerts deleted" });
  } catch (err) {
    console.error("[clearAlerts] Error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
};
