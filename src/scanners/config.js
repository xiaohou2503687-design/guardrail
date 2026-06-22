const fs = require("fs");
const path = require("path");

function scanConfig(filePath) {
  const findings = [];
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();

  if (base === ".gitignore") {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const hasEnv = content.split("\n").some(l => l.trim() === ".env");
      const hasNodeModules = content.split("\n").some(l => l.trim() === "node_modules/");
      if (!hasEnv) {
        findings.push({
          type: "missing_gitignore", severity: "medium", line: 1,
          message: ".gitignore does not contain `.env` — environment files may be committed",
          snippet: "Add `.env` to .gitignore",
          rule: "GR-CFG-001"
        });
      }
      if (!hasNodeModules) {
        findings.push({
          type: "missing_gitignore", severity: "low", line: 1,
          message: ".gitignore may not have `node_modules/` — dependencies may be tracked",
          snippet: "Add `node_modules/` to .gitignore",
          rule: "GR-CFG-002"
        });
      }
    } catch {}
  }

  if (base === ".npmrc") {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      if (content.includes("//registry.npmjs.org/:_authToken=")) {
        findings.push({
          type: "npmrc_token", severity: "high", line: 1,
          message: "npm auth token found in .npmrc — use `npm login` instead",
          rule: "GR-CFG-003"
        });
      }
    } catch {}
  }

  if (ext === ".yaml" || ext === ".yml") {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/\b(?:password|secret|token|api_key):\s*[^\s\$]{8,}/.test(line) && !line.includes("${") && !line.includes("${{")) {
          findings.push({
            type: "yaml_secret", severity: "high", line: i + 1,
            message: "Secret value hardcoded in YAML config",
            snippet: line.trim().substring(0, 100),
            rule: "GR-CFG-004"
          });
        }
      }
    } catch {}
  }

  if (base === "dockerfile" || base.endsWith(".dockerfile")) {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim().toUpperCase();
        if (line.startsWith("ENV ") && /\b(?:PASSWORD|SECRET|TOKEN|KEY)\b/.test(line) && !line.includes("${")) {
          findings.push({
            type: "docker_env", severity: "high", line: i + 1,
            message: "Sensitive value in Dockerfile ENV — use build args or secrets",
            snippet: lines[i].trim().substring(0, 120),
            rule: "GR-CFG-005"
          });
        }
        if (line.startsWith("FROM ") && (line.includes(":latest") || !line.includes(":"))) {
          findings.push({
            type: "docker_latest", severity: "low", line: i + 1,
            message: "Docker image uses `:latest` tag — pin to specific version for reproducibility",
            snippet: lines[i].trim(),
            rule: "GR-CFG-006"
          });
        }
      }
    } catch {}
  }

  return findings;
}

module.exports = { scanConfig };
