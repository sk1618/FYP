const { spawn } = require("child_process");

exports.runCommand = (tool, args = [], timeout = 60000) => {
  return new Promise((resolve, reject) => {
    const process = spawn(tool, args);

    let output = "";
    let errorOutput = "";
    let timedOut = false;

    // ✅ Timeout handling
    const timer = setTimeout(() => {
      timedOut = true;
      process.kill("SIGKILL");
      reject(new Error("Tool execution timed out"));
    }, timeout);

    process.stdout.on("data", (data) => {
      output += data.toString();
    });

    process.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    process.on("close", (code) => {
      clearTimeout(timer);

      if (timedOut) return;

      if (code !== 0) {
        return reject(new Error(errorOutput || "Tool failed"));
      }

      resolve(output);
    });
  });
};