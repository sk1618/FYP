// utils/toolRunner.js
// Wraps child_process.spawn in a promise with a configurable timeout.
// NOTE: The spawned process is stored as `proc`, not `process`, to avoid
//       shadowing Node's global `process` object.
const { spawn } = require("child_process");

/**
 * Runs an external command and resolves with its stdout.
 * Rejects on non-zero exit code, spawn error, or timeout.
 *
 * @param {string}   cmd     - Executable name (e.g. "nmap", "bash")
 * @param {string[]} args    - Argument list
 * @param {number}   timeout - Milliseconds before SIGKILL (default 2 min)
 */
exports.runCommand = (cmd, args = [], timeout = 120_000) => {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args);

    let stdout    = "";
    let stderr    = "";
    let timedOut  = false;

    const timer = setTimeout(() => {
      timedOut = true;
      proc.kill("SIGKILL");
      reject(new Error(`Command "${cmd}" timed out after ${timeout / 1000}s`));
    }, timeout);

    proc.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    proc.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    // Fired when the process cannot be spawned at all (e.g. command not found).
    proc.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (timedOut) return;
      if (code !== 0) return reject(new Error(stderr || `"${cmd}" exited with code ${code}`));
      resolve(stdout);
    });
  });
};
