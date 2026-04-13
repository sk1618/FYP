// controllers/toolController.js
// Orchestrates Nmap and Metasploit scans, persists results to the DB, and
// auto-creates vulnerability records via the shared vuln utility.
const db      = require("../db");
const { runCommand }             = require("../utils/toolRunner");
const { maybeCreateVulnerability } = require("../utils/vuln");
// ── Constants ─────────────────────────────────────────────────────────────────

const ALLOWED_TOOLS = new Set(["nmap", "metasploit", "nikto", "lynis", "hydra", "sqlmap"]);

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

// Maps open TCP port numbers to Hydra service names.
const HYDRA_SERVICES = {
  21:   "ftp",
  22:   "ssh",
  23:   "telnet",
  3306: "mysql",
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
async function insertAlert(alertData, skipVuln = false) {
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
  if (!skipVuln) {
    await maybeCreateVulnerability(result.insertId, alertData).catch((err) =>
      console.error("[toolController] Vuln creation failed:", err.message)
    );
  }
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
      source_ip:     "nmap",
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
      source_ip:     "metasploit",
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
      source_ip:     "metasploit",
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

/**
 * Converts raw Lynis stdout into alert objects.
 * Lynis Results section format:
 *   Warnings section  → lines starting with "!"
 *   Suggestions section → lines starting with "*"
 *   Hardening index : 67
 */
function parseLynisOutput(output, target) {
  const alerts = [];
  let inResults     = false;
  let inWarnings    = false;
  let inSuggestions = false;

  for (const line of output.split("\n")) {
    const clean = line.replace(/\x1b\[[0-9;]*m/g, "").trim();
    if (!clean) continue;

    // Enter Results section
    if (clean.includes("Results") && clean.includes("Lynis")) { inResults = true; continue; }
    if (!inResults) continue;

    // Detect subsections
    if (/^Warnings\s*\(/i.test(clean))    { inWarnings = true;  inSuggestions = false; continue; }
    if (/^Suggestions\s*\(/i.test(clean)) { inSuggestions = true; inWarnings = false;  continue; }
    if (/^Follow-up:/i.test(clean) || /^Lynis security scan details/i.test(clean)) {
      inWarnings = false; inSuggestions = false;
    }

    // Hardening index
    const hiMatch = clean.match(/Hardening index\s*:\s*(\d+)/i);
    if (hiMatch) {
      alerts.push({
        source_ip:      "lynis",
        destination_ip: target,
        activity_type:  "Lynis: Hardening Score",
        severity:       "Low",
        description:    `System hardening index: ${hiMatch[1]} / 100`,
      });
      continue;
    }

    // Warnings: lines starting with "!" — skip reference lines
    if (inWarnings && clean.startsWith("!")) {
      const text = clean.replace(/^!\s*/, "").trim();
      if (/^(Website|Article|See also):/i.test(text)) continue;
      alerts.push({
        source_ip:      "lynis",
        destination_ip: target,
        activity_type:  "Lynis: Warning",
        severity:       "High",
        description:    text.slice(0, 500),
      });
      continue;
    }

    // Suggestions: lines starting with "*" — skip reference lines
    if (inSuggestions && clean.startsWith("*")) {
      const text  = clean.replace(/^\*\s*/, "").trim();
      if (/^(Website|Article|See also):/i.test(text)) continue;

      const lower = text.toLowerCase();
      const severity =
        /ssh|firewall|kernel|password|root|exploit|cve|authenticat|sudo|privilege|suid|permission/.test(lower)
          ? "High"
          : /outdated|expired|disable|restrict|encrypt|audit|log|fail2ban|pam/.test(lower)
            ? "Medium"
            : "Low";

      alerts.push({
        source_ip:      "lynis",
        destination_ip: target,
        activity_type:  "Lynis: Suggestion",
        severity,
        description:    text.slice(0, 500),
      });
    }
  }

  return alerts;
}

/**
 * Converts Hydra stdout into alert objects.
 * Success lines look like:
 *   [22][ssh] host: 192.168.1.1   login: root   password: 123456
 * Always emits at least one "attempt" alert per service so the scan is visible.
 */
function parseHydraOutput(output, target, port, service) {
  const alerts = [];
  const upper  = service.toUpperCase();

  for (const line of output.split("\n")) {
    const m = line.match(/\[\d+\]\[[\w-]+\]\s+host:\s+\S+.*?login:\s+(\S+)\s+password:\s+(\S+)/);
    if (m) {
      alerts.push({
        source_ip:      "hydra",
        destination_ip: target,
        activity_type:  `Hydra: Credential Found on ${upper} (port ${port})`,
        severity:       "High",
        description:    `Weak credential confirmed — login: ${m[1]}, password: ${m[2]}`,
      });
    }
  }

  // Always record the brute-force attempt itself
  alerts.push({
    source_ip:      "hydra",
    destination_ip: target,
    activity_type:  `Hydra: Brute-Force ${upper} (port ${port})`,
    severity:       alerts.length > 0 ? "High" : "Low",
    description:    alerts.length > 0
      ? `Hydra found ${alerts.length} valid credential(s) on ${upper} port ${port}`
      : `Hydra brute-force completed — no weak credentials found on ${upper} port ${port}`,
  });

  return alerts;
}

/**
 * Converts SQLMap stdout into alert objects.
 * Looks for lines confirming injectable parameters and database type.
 */
function parseSqlmapOutput(output, target) {
  const alerts  = [];
  const lines   = output.split("\n");
  const seen    = new Set();

  for (const line of lines) {
    const lower = line.toLowerCase();

    // Confirmed injectable parameter
    const paramMatch = line.match(/parameter\s+'([^']+)'\s+is\s+vulnerable/i)
                    || line.match(/\[CRITICAL\].*parameter\s+'([^']+)'/i)
                    || line.match(/GET parameter\s+'([^']+)'\s+is\s+(vulnerable|injectable)/i)
                    || line.match(/POST parameter\s+'([^']+)'\s+is\s+(vulnerable|injectable)/i)
                    || line.match(/sqlmap identified the following injection point/i) && line.match(/'([^']+)'/);
    if (paramMatch && !seen.has(paramMatch[1])) {
      seen.add(paramMatch[1]);
      alerts.push({
        source_ip:      "sqlmap",
        destination_ip: target,
        activity_type:  "SQLMap: SQL Injection Found",
        severity:       "High",
        description:    `Parameter '${paramMatch[1]}' is vulnerable to SQL injection on ${target}`,
      });
    }

    // Database banner / backend identified
    const dbMatch = line.match(/back-end DBMS[:\s]+(.+)/i);
    if (dbMatch && !seen.has("dbms")) {
      seen.add("dbms");
      alerts.push({
        source_ip:      "sqlmap",
        destination_ip: target,
        activity_type:  "SQLMap: Database Identified",
        severity:       "Medium",
        description:    `Database identified: ${dbMatch[1].trim()}`,
      });
    }

    // Forms or endpoints discovered
    if (lower.includes("found a total of") && lower.includes("form") && !seen.has("forms")) {
      seen.add("forms");
      const countMatch = line.match(/found a total of (\d+)/i);
      alerts.push({
        source_ip:      "sqlmap",
        destination_ip: target,
        activity_type:  "SQLMap: Forms Discovered",
        severity:       "Low",
        description:    `SQLMap discovered ${countMatch ? countMatch[1] : "multiple"} form(s) on ${target} — tested for injection`,
      });
    }
  }

  // If nothing actionable was found, record that the scan ran
  if (!alerts.length) {
    alerts.push({
      source_ip:      "sqlmap",
      destination_ip: target,
      activity_type:  "SQLMap: Scan Completed",
      severity:       "Low",
      description:    `SQLMap found no SQL injection vulnerabilities on ${target}`,
    });
  }

  return alerts;
}

// ── Hydra credential file ─────────────────────────────────────────────────────
// Written once at startup — common default credentials used for demo scanning.
const fs   = require("fs");
const HYDRA_CREDS_FILE = "/tmp/fyp-hydra-creds.txt";
const HYDRA_CREDS = [
  "root:root", "root:toor", "root:", "admin:admin", "admin:password",
  "admin:admin123", "msfadmin:msfadmin", "user:user", "test:test",
  "guest:guest", "postgres:postgres", "service:service", "tomcat:tomcat",
  "ftp:ftp", "anonymous:anonymous", "anonymous:",
].join("\n");
fs.writeFileSync(HYDRA_CREDS_FILE, HYDRA_CREDS);

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

  // SQLMap accepts full URLs; all other tools accept IPs/hostnames only.
  const SAFE_URL = /^https?:\/\/[a-zA-Z0-9.\-]+(:\d+)?(\/[^\s]*)?$/;
  const targetOk = normalizedTool === "sqlmap"
    ? (SAFE_TARGET.test(normalizedTarget) || SAFE_URL.test(normalizedTarget))
    : SAFE_TARGET.test(normalizedTarget);

  if (!targetOk) {
    return res.status(400).json({ success: false, message: "Invalid target — only IP addresses and hostnames are accepted (SQLMap also accepts http:// URLs)" });
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

    // ── Lynis ───────────────────────────────────────────────────────────────
    if (normalizedTool === "lynis") {
      const output = await runCommand(
        "sudo", ["lynis", "audit", "system", "--no-colors", "--quick"],
        300_000, true
      );

      // Deduplicate by description before inserting
      const raw    = parseLynisOutput(output, normalizedTarget);
      const seen   = new Set();
      const alerts = raw.filter((a) => {
        if (seen.has(a.description)) return false;
        seen.add(a.description);
        return true;
      });

      if (!alerts.length) {
        return res.json({ success: true, message: "Lynis audit completed — no findings", data: [] });
      }

      // Insert sequentially to avoid flooding the DB pool (skipVuln — Lynis handles it directly)
      for (const a of alerts) await insertAlert(a, true);

      // Directly create vulnerability records for High severity findings
      // (maybeCreateVulnerability won't trigger on Lynis output as it lacks CVE keywords)
      const highFindings = alerts.filter((a) => a.severity === "High");
      for (const a of highFindings) {
        await db.execute(
          `INSERT INTO vulnerabilities (target_ip, vuln_name, severity, description, scan_date)
           VALUES (?, ?, ?, ?, NOW())`,
          [a.destination_ip, a.activity_type, a.severity, a.description]
        );
      }

      return res.json({ success: true, message: `Lynis audit completed — ${alerts.length} finding(s)`, data: alerts });
    }
    // ── Hydra ───────────────────────────────────────────────────────────────
    if (normalizedTool === "hydra") {
      // Step 1: find open ports.
      const nmapOutput = await runCommand("nmap", [normalizedTarget]);
      const ports      = extractOpenPorts(nmapOutput);

      const supportedPorts = ports.filter((p) => HYDRA_SERVICES[p]);
      if (!supportedPorts.length) {
        return res.json({ success: true, message: "Hydra: no supported services found (SSH/FTP/Telnet/MySQL)", data: [] });
      }

      const allAlerts = [];
      for (const port of supportedPorts) {
        const service = HYDRA_SERVICES[port];
        try {
          const output = await runCommand(
            "hydra",
            ["-C", HYDRA_CREDS_FILE, "-t", "4", "-f",
             "-s", String(port), normalizedTarget, service],
            60_000, true
          );
          allAlerts.push(...parseHydraOutput(output, normalizedTarget, port, service));
        } catch (err) {
          console.error(`[hydra] ${service} port ${port} failed:`, err.message);
        }
      }

      for (const a of allAlerts) await insertAlert(a, true);

      // Create vulnerability records for confirmed credentials
      const credFindings = allAlerts.filter((a) => a.severity === "High" && a.activity_type.includes("Credential Found"));
      for (const a of credFindings) {
        await db.execute(
          `INSERT INTO vulnerabilities (target_ip, vuln_name, severity, description, scan_date)
           VALUES (?, ?, ?, ?, NOW())`,
          [a.destination_ip, a.activity_type, a.severity, a.description]
        );
      }

      return res.json({ success: true, message: `Hydra scan completed — ${allAlerts.length} result(s)`, data: allAlerts });
    }

    // ── SQLMap ──────────────────────────────────────────────────────────────
    if (normalizedTool === "sqlmap") {
      // Auto-build URL — prepend http:// if not already a URL
      const url = /^https?:\/\//i.test(normalizedTarget)
        ? normalizedTarget
        : `http://${normalizedTarget}`;

      // Store only the hostname in destination_ip (column is sized for IPs/hostnames)
      const sqlmapHost = (() => {
        try { return new URL(url).hostname; } catch { return normalizedTarget; }
      })();

      const output = await runCommand(
        "sqlmap",
        ["-u", url, "--batch", "--crawl=2",
         "--level=1", "--risk=1",
         "--technique=BEU", "--flush-session",
         "--timeout=10", "--retries=0"],
        240_000, true
      );

      const alerts = parseSqlmapOutput(output, sqlmapHost);
      for (const a of alerts) await insertAlert(a);

      // Create vulnerability records for confirmed injections
      const injections = alerts.filter((a) => a.activity_type.includes("SQL Injection Found"));
      for (const a of injections) {
        await db.execute(
          `INSERT INTO vulnerabilities (target_ip, vuln_name, severity, description, scan_date)
           VALUES (?, ?, ?, ?, NOW())`,
          [a.destination_ip, a.activity_type, a.severity, a.description]
        );
      }

      return res.json({ success: true, message: `SQLMap scan completed — ${alerts.length} finding(s)`, data: alerts });
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
