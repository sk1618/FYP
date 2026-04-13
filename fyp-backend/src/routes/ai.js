// Supports both:
// 1) Uploading an existing PCAP file and analyzing it
// 2) Capturing live packets with tcpdump for a few seconds, then analyzing them
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { execFile } = require("child_process");

const router = express.Router();
const UPLOADS_DIR = path.join(__dirname, "../../uploads");
const upload = multer({ dest: UPLOADS_DIR });

const AI_SCRIPT = path.join(__dirname, "../../ai/analyze_ai.py");

// Deletes temp files silently
function cleanupFile(filePath) {
  if (!filePath) return;
  fs.unlink(filePath, (err) => {
    if (err) {
      console.warn("[AI] Could not remove temp file:", filePath);
    }
  });
}

function parsePythonJson(stdout) {
  const lastLine = stdout.trim().split("\n").pop();
  return JSON.parse(lastLine);
}

function runAnalysis(pcapPath, res, cleanupAfter = true) {
  execFile("python3", [AI_SCRIPT, pcapPath], (err, stdout, stderr) => {
    if (cleanupAfter) {
      cleanupFile(pcapPath);
    }

    if (err) {
      console.error("[AI] Execution error:", err.message);
      return res.status(500).json({
        success: false,
        error: "AI analysis failed.",
        details: stderr || err.message,
      });
    }

    try {
      const parsed = parsePythonJson(stdout);
      return res.json(parsed);
    } catch (parseErr) {
      console.error("[AI] JSON parse error:", parseErr.message);
      return res.status(500).json({
        success: false,
        error: "Failed to parse AI output.",
        rawOutput: stdout,
      });
    }
  });
}

// GET /api/ai
router.get("/", (_req, res) => {
  res.json({ success: true, message: "AI analysis endpoint is ready." });
});

// POST /api/ai/analyze-pcap
router.post("/analyze-pcap", upload.single("pcap"), (req, res) => {
  const pcapPath = req.file?.path;

  if (!pcapPath) {
    return res.status(400).json({
      success: false,
      error: "No PCAP file uploaded.",
    });
  }

  runAnalysis(pcapPath, res, true);
});

// POST /api/ai/live-scan
router.post("/live-scan", (req, res) => {
  const rawDuration = Number(req.body?.duration);
  const duration = Number.isFinite(rawDuration)
    ? Math.min(Math.max(rawDuration, 3), 120)
    : 10;

  const iface = String(req.body?.iface || "any").trim();

  if (!/^[a-zA-Z0-9._:-]+$/.test(iface)) {
    return res.status(400).json({
      success: false,
      error: "Invalid network interface.",
    });
  }

  const livePcapPath = path.join(UPLOADS_DIR, `live_${Date.now()}.pcap`);

  // timeout stops tcpdump automatically after N seconds
  execFile(
    "timeout",
    [String(duration), "tcpdump", "-i", iface, "-w", livePcapPath, "-nn"],
    (captureErr, _stdout, captureStderr) => {
      const allowedExitCodes = [0, 124, 137, 143];

      if (captureErr && !allowedExitCodes.includes(captureErr.code)) {
        console.error("[AI] Live capture error:", captureErr.message);
        cleanupFile(livePcapPath);

        return res.status(500).json({
          success: false,
          error: "Live capture failed.",
          details:
            captureStderr ||
            captureErr.message ||
            "tcpdump could not capture packets.",
        });
      }

      if (!fs.existsSync(livePcapPath)) {
        return res.status(500).json({
          success: false,
          error: "Live capture failed.",
          details: "No capture file was created.",
        });
      }

      const stats = fs.statSync(livePcapPath);

      // A pcap with only a header and no packets is typically very small
      if (stats.size <= 24) {
        cleanupFile(livePcapPath);
        return res.status(400).json({
          success: false,
          error: "No packets captured during the live scan.",
        });
      }

      runAnalysis(livePcapPath, res, true);
    }
  );
});

module.exports = router;