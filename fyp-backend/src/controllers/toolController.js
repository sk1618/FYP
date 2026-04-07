// controllers/toolController.js
// Orchestrates Nmap and Metasploit scans, persists results to the DB, and
// auto-creates vulnerability records via the shared vuln utility.
const db      = require("../db");
const { runCommand }             = require("../utils/toolRunner");
const { maybeCreateVulnerability } = require("../utils/vuln");
// ── Constants ─────────────────────────────────────────────────────────────────

const ALLOWED_TOOLS = new Set(["nmap", "metasploit", "nikto"]);

// Accepts IPv4 addresses and simple hostnames only — no shell metacharacters.
const SAFE_TARGET = /^[a-zA-Z0-9.\-]+$/;

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

/**
 * Infers a human-readable category from a Nikto finding.
 */
function categorizeNiktoFinding(text) {
  const l = text.toLowerCase();
  if (l.includes("phpmyadmin"))                                          return "phpMyAdmin Exposed";
  if (l.includes("phpinfo") || l.includes("php reveals"))               return "PHP Info Disclosure";
  if (l.includes("xss") || l.includes("cross site tracing") || l.includes("xst")) return "XSS / Tracing Risk";
  if (l.includes("sql"))                                                 return "SQL Injection Risk";
  if (l.includes("outdated") || l.includes("end-of-life") || l.includes("eol"))   return "Outdated Software";
  if (l.includes("x-frame") || l.includes("x-content") || l.includes("header is not") || l.includes("anti-clickjacking")) return "Missing Security Header";
  if (l.includes("directory indexing") || l.includes("browsable"))      return "Exposed Directory";
  if (l.includes("default file") || l.includes("apache default"))       return "Default File Found";
  if (l.includes("mod_negotiation") || l.includes("multiviews"))        return "Apache Misconfiguration";
  if (l.includes("http trace") || l.includes("trace method"))           return "Dangerous HTTP Method";
  if (l.includes("inode") || l.includes("etag") || l.includes("x-powered-by") || l.includes("powered by")) return "Information Disclosure";
  if (l.includes("wp-config") || l.includes("credentials"))             return "Credential File Exposed";
  if (l.includes("brute force"))                                         return "Brute Force Risk";
  if (l.includes("cve-") || l.includes("osvdb-"))                       return "Known Vulnerability";
  return "Web Vulnerability";
}

/**
 * Converts raw Nikto stdout into alert objects.
 * Findings start with "+ " — header/footer lines are skipped.
 * Severity is inferred from keywords, CVE/OSVDB refs appended to description.
 */
function parseNiktoOutput(output, target) {
  const HIGH_KEYWORDS   = ["vulnerable", "inject", "xss", "sql", "rce", "exploit", "cve-", "trace", "phpmyadmin", "credentials", "wp-config"];
  const MEDIUM_KEYWORDS = ["osvdb", "outdated", "misconfigur", "exposed", "default", "brute force", "mod_negotiation", "phpinfo", "php reveals", "inode", "etag"];

  return output
    .split("\n")
    .filter((line) => {
      if (!line.startsWith("+ ")) return false;
      const l = line.toLowerCase();
      return !l.startsWith("+ target") &&
             !l.startsWith("+ start") &&
             !l.startsWith("+ end") &&
             !l.startsWith("+ server:") &&
             !l.includes("requests:") &&
             !l.includes("host(s) tested");
    })
    .map((line) => {
      // Strip path prefix (e.g. "/phpMyAdmin/ChangeLog: ") and "See: http..." references
      const raw     = line.replace(/^\+\s*/, "").trim();
      const noPath  = raw.replace(/^\/[^:]*:\s*/, "").trim();
      const noSee   = noPath.replace(/\s*See:\s*https?:\/\/\S+/gi, "").trim();

      // Extract CVE and OSVDB references to append as clean tags
      const cveRefs  = [...new Set((raw.match(/CVE-\d{4}-\d+/gi)  || []).map((r) => r.toUpperCase()))];
      const osvdbRefs= [...new Set((raw.match(/OSVDB-\d+/gi)       || []).map((r) => r.toUpperCase()))];
      const allRefs  = [...cveRefs, ...osvdbRefs];

      const description = allRefs.length
        ? `${noSee} [${allRefs.join(", ")}]`.slice(0, 500)
        : noSee.slice(0, 500);

      const lower    = raw.toLowerCase();
      const severity = HIGH_KEYWORDS.some((k)   => lower.includes(k)) ? "High"
                     : MEDIUM_KEYWORDS.some((k) => lower.includes(k)) ? "Medium"
                     : "Low";

      return {
        source_ip:      "nikto",
        destination_ip: target,
        activity_type:  `Nikto: ${categorizeNiktoFinding(raw)}`,
        severity,
        description,
      };
    });
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

  if (!SAFE_TARGET.test(normalizedTarget)) {
    return res.status(400).json({ success: false, message: "Invalid target — only IP addresses and hostnames are accepted" });
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

    // ── Nikto ───────────────────────────────────────────────────────────────
    if (normalizedTool === "nikto") {
      // Nikto exits with code 1 even on success — capture output regardless
      const output = await runCommand("nikto", ["-h", normalizedTarget, "-nointeractive"], 300_000, true);
      const alerts = parseNiktoOutput(output, normalizedTarget);

      if (!alerts.length) {
        return res.json({ success: true, message: "Nikto scan completed — no findings", data: [] });
      }

      await Promise.all(alerts.map(insertAlert));
      return res.json({ success: true, message: `Nikto scan completed — ${alerts.length} finding(s)`, data: alerts });
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
