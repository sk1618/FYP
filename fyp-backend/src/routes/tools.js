const express = require("express");
const router = express.Router();
const { runTool } = require("../controllers/toolController");

router.post("/run", runTool);

module.exports = router;