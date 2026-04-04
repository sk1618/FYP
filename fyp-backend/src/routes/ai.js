// routes/ai.js
// Accepts a PCAP file upload, runs it through the Python ML model, and returns
// the parsed JSON result.  The temp file created by multer is always deleted
// after the analysis (success or failure) to avoid disk accumulation.
const express    = require("express");
const multer     = require("multer");
const path       = require("path");
const fs         = require("fs");
const { execFile } = require("child_process");

const router = express.Router();
const upload = multer({ dest: path.join(__dirname, "../../uploads") });

const AI_SCRIPT = path.join(__dirname, "../../ai/analyze_ai.py");

// Deletes the multer temp file silently — errors here are non-fatal.
function cleanupFile(filePath) {
  if (!filePath) return;
  fs.unlink(filePath, (err) => {
    if (err) console.warn("[AI] Could not remove temp file:", filePath);
  });
}

// ── GET /api/ai — health check ────────────────────────────────────────────────
router.get("/", (_req, res) => {
  res.json({ success: true, message: "AI analysis endpoint is ready." });
});

// ── POST /api/ai/analyze-pcap ─────────────────────────────────────────────────
router.post("/analyze-pcap", upload.single("pcap"), (req, res) => {
  const pcapPath = req.file?.path;
  const args     = pcapPath ? [AI_SCRIPT, pcapPath] : [AI_SCRIPT];

  // Try python3 first; many systems alias only python3.
  execFile("python3", args, (err, stdout, stderr) => {
    cleanupFile(pcapPath);

    if (err) {
      console.error("[AI] Execution error:", err.message);
      return res.status(500).json({
        success: false,
        error:   "AI analysis failed.",
        details: stderr || err.message,
      });
    }

    try {
      // The Python script may print debug lines; only the last line is JSON.
      const lastLine = stdout.trim().split("\n").pop();
      const parsed   = JSON.parse(lastLine);
      return res.json(parsed);
    } catch (parseErr) {
      console.error("[AI] JSON parse error:", parseErr.message);
      return res.status(500).json({
        success: false,
        error:     "Failed to parse AI output.",
        rawOutput: stdout,
      });
    }
  });
});

module.exports = router;
