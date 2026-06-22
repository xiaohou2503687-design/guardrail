const fs = require("fs");
const { SECRET_PATTERNS } = require("../rules/secrets-patterns");

function scanSecrets(filePath) {
  const findings = [];
  let content;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return findings;
  }

  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith("#") || trimmed.startsWith("//") || trimmed.startsWith("/*")) continue;
    if (trimmed.startsWith("REM ") || trimmed.startsWith("--")) continue;

    for (const pattern of SECRET_PATTERNS) {
      const match = trimmed.match(pattern.regex);
      if (match) {
        const value = match[1] || match[0];
        if (isFalsePositive(value, pattern)) continue;

        findings.push({
          type: pattern.type,
          severity: pattern.severity,
          line: i + 1,
          message: pattern.message,
          snippet: redactSnippet(trimmed, pattern),
          rule: pattern.id
        });
        break;
      }
    }

    if (isEnvFileWithValue(line, filePath)) {
      const eq = line.indexOf("=");
      if (eq > 0 && line.substring(eq + 1).trim().length > 4 && !line.substring(0, eq).includes(" ")) {
        const exists = findings.find(f => f.line === i + 1);
        if (!exists) {
          findings.push({
            type: "exposed_secret",
            severity: "high",
            line: i + 1,
            message: "Environment variable with value found in tracked file",
            snippet: `${line.substring(0, eq)}=***REDACTED***`,
            rule: "GR-ENV-001"
          });
        }
      }
    }
  }

  return findings;
}

function isEnvFileWithValue(line, filePath) {
  const name = filePath.toLowerCase();
  if (name.endsWith(".env.example") || name.endsWith(".env.sample") || name.endsWith(".env.template")) return false;
  if (!name.includes(".env") || name.endsWith(".env")) return true;
  return false;
}

function isFalsePositive(value, pattern) {
  const fp = pattern.falsePositives || [];
  return fp.some(check => {
    if (typeof check === "string") return value.includes(check);
    if (check instanceof RegExp) return check.test(value);
    return false;
  });
}

function redactSnippet(line, pattern) {
  if (pattern.redactKey) {
    const re = new RegExp(`(${pattern.redactKey}\\s*[=:]\\s*)(.+)`, "i");
    return line.replace(re, "$1***REDACTED***");
  }
  if (line.length > 100) return line.substring(0, 97) + "...";
  return line;
}

module.exports = { scanSecrets };
