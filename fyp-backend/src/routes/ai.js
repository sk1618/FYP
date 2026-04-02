const express = require("express");
const multer = require("multer");
const path = require("path");
const { execFile } = require("child_process");

const router = express.Router();

const upload = multer({
  dest: path.join(__dirname, "../../uploads"),
});

router.get("/", (req, res) => {
  res.json({ message: "AI route is working." });
});

router.post("/analyze-pcap", upload.single("pcap"), (req, res) => {
  const pythonScript = path.join(__dirname, "../../ai/analyze_ai.py");
  const pcapPath = req.file ? req.file.path : undefined;

  execFile("python", pcapPath ? [pythonScript, pcapPath] : [pythonScript], (error, stdout, stderr) => {
    if (error) {
      console.error("Python execution error:", error);
      console.error("stderr:", stderr);
      return res.status(500).json({
        error: "AI analysis failed.",
        details: stderr || error.message,
      });
    }

    try {
      const lines = stdout.trim().split("\n");
      const lastLine = lines[lines.length - 1];
      const parsed = JSON.parse(lastLine);
      return res.json(parsed);
    } catch (parseError) {
      console.error("JSON parse error:", parseError);
      console.error("stdout:", stdout);
      console.error("stderr:", stderr);
      return res.status(500).json({
        error: "Failed to parse AI output.",
        rawOutput: stdout,
      });
    }
  });
});

module.exports = router;