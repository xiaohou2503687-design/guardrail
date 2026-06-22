const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

async function scanDependencies(targetPath) {
  const findings = [];

  const hasNodeModules = fs.existsSync(path.join(targetPath, "node_modules"));
  const hasPackageJson = fs.existsSync(path.join(targetPath, "package.json"));

  if (hasPackageJson) {
    try {
      const result = JSON.parse(fs.readFileSync(path.join(targetPath, "package.json"), "utf-8"));
      const deps = { ...result.dependencies, ...result.devDependencies };

      const knownVulns = getKnownVulnerableVersions();
      for (const [name, version] of Object.entries(deps)) {
        const cleanVersion = version.replace(/^[\^~]/, "");
        const vuln = knownVulns[name];
        if (vuln && isVulnerableVersion(cleanVersion, vuln.range)) {
          findings.push({
            type: "vulnerable_dependency",
            severity: vuln.severity,
            package: name,
            version: version,
            message: `${name}@${version}: ${vuln.description}`,
            fix: vuln.fix,
            rule: "GR-DEP-001"
          });
        }
      }

      if (hasNodeModules) {
        try {
          const auditOutput = execSync("npm audit --json --silent 2>&1", {
            cwd: targetPath, maxBuffer: 10 * 1024 * 1024, timeout: 30000
          }).toString().trim();
          if (auditOutput && auditOutput !== "{}") {
            const audit = JSON.parse(auditOutput);
            if (audit.vulnerabilities) {
              for (const [name, vuln] of Object.entries(audit.vulnerabilities)) {
                const sev = vuln.severity === "critical" ? "critical" : vuln.severity === "high" ? "high" : vuln.severity === "moderate" ? "medium" : "low";
                findings.push({
                  type: "npm_audit",
                  severity: sev,
                  package: name,
                  version: vuln.range || "unknown",
                  message: vuln.title || `${name}: ${vuln.severity} severity vulnerability`,
                  fix: vuln.fixAvailable ? "Run npm audit fix" : "Manual fix required",
                  rule: "GR-DEP-002"
                });
              }
            }
          }
        } catch {
          findings.push({
            type: "npm_audit_failed",
            severity: "low",
            message: "npm audit failed — run `npm install` first or check manually",
            rule: "GR-DEP-003"
          });
        }
      } else {
        findings.push({
          type: "no_node_modules",
          severity: "low",
          message: "node_modules not found — run `npm install` to enable dependency scanning",
          rule: "GR-DEP-004"
        });
      }
    } catch {
      findings.push({
        type: "package_json_error",
        severity: "low",
        message: "Could not parse package.json",
        rule: "GR-DEP-005"
      });
    }
  }

  const requirementsPath = path.join(targetPath, "requirements.txt");
  if (fs.existsSync(requirementsPath)) {
    try {
      const content = fs.readFileSync(requirementsPath, "utf-8");
      const lines = content.split("\n").filter(l => l.trim() && !l.startsWith("#"));
      const pythonVulns = getKnownPythonVulns();
      for (const line of lines) {
        const match = line.match(/^([a-zA-Z0-9_-]+)\s*([><=!~]+)\s*([\d.]+)/);
        if (match) {
          const [, name, , version] = match;
          const vuln = pythonVulns[name];
          if (vuln && isVulnerableVersion(version, vuln.range)) {
            findings.push({
              type: "vulnerable_dependency",
              severity: vuln.severity,
              package: name,
              version: version,
              message: `${name}==${version}: ${vuln.description}`,
              fix: vuln.fix,
              rule: "GR-DEP-006"
            });
          }
        }
      }
    } catch {}
  }

  return findings;
}

function isVulnerableVersion(current, range) {
  if (!range || range === "*") return true;
  const parts = current.split(".").map(Number);
  if (range.startsWith("<=")) {
    const v = range.slice(2).split(".").map(Number);
    return compareVersions(parts, v) <= 0;
  }
  if (range.startsWith("<")) {
    const v = range.slice(1).split(".").map(Number);
    return compareVersions(parts, v) < 0;
  }
  return false;
}

function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) > (b[i] || 0)) return 1;
    if ((a[i] || 0) < (b[i] || 0)) return -1;
  }
  return 0;
}

function getKnownVulnerableVersions() {
  return {
    "lodash": { range: "<4.17.21", severity: "high", description: "Prototype pollution vulnerability (CVE-2021-23337)", fix: "Update to lodash@^4.17.21" },
    "axios": { range: "<1.7.4", severity: "high", description: "SSRF vulnerability (CVE-2024-39338)", fix: "Update to axios@^1.7.4" },
    "next": { range: "<14.2.15", severity: "critical", description: "Server-Side Request Forgery (CVE-2024-46995)", fix: "Update to next@^14.2.15" },
    "webpack": { range: "<5.94.0", severity: "high", description: "DOM clobbering gadget in AutoPublicPathRuntimeModule", fix: "Update to webpack@^5.94.0" },
    "vite": { range: "<5.4.6", severity: "high", description: "Server.fs.deny bypass (CVE-2024-45811)", fix: "Update to vite@^5.4.6" },
    "express": { range: "<4.21.0", severity: "high", description: "Open redirect in express.static (CVE-2024-43796)", fix: "Update to express@^4.21.0" },
    "follow-redirects": { range: "<1.15.6", severity: "high", description: "SSRF vulnerability", fix: "Update to follow-redirects@^1.15.6" },
    "braces": { range: "<3.0.3", severity: "high", description: "Uncontrolled resource consumption (CVE-2024-4068)", fix: "Update to braces@^3.0.3" },
    "ws": { range: "<8.17.1", severity: "high", description: "DoS via excessively large Sec-WebSocket-Extensions header", fix: "Update to ws@^8.17.1" },
    "cross-spawn": { range: "<7.0.5", severity: "high", description: "Regular Expression Denial of Service", fix: "Update to cross-spawn@^7.0.5" },
    "micromatch": { range: "<4.0.8", severity: "high", description: "Regular Expression Denial of Service (CVE-2024-4067)", fix: "Update to micromatch@^4.0.8" },
    "path-to-regexp": { range: "<0.1.12", severity: "high", description: "Backtracking ReDoS", fix: "Update to path-to-regexp@^0.1.12" },
    "semver": { range: "<7.5.2", severity: "medium", description: "Regular Expression Denial of Service", fix: "Update to semver@^7.5.2" },
    "word-wrap": { range: "<1.2.4", severity: "medium", description: "Regular Expression Denial of Service", fix: "Update to word-wrap@^1.2.4" },
    "tough-cookie": { range: "<4.1.3", severity: "medium", description: "Prototype pollution", fix: "Update to tough-cookie@^4.1.3" },
    "postcss": { range: "<8.4.31", severity: "medium", description: "Line return parsing error leading to CSS injection", fix: "Update to postcss@^8.4.31" }
  };
}

function getKnownPythonVulns() {
  return {
    "django": { range: "<4.2.15", severity: "high", description: "Multiple CVEs in older Django versions", fix: "Update to django>=4.2.15" },
    "flask": { range: "<2.3.3", severity: "medium", description: "Open redirect vulnerability", fix: "Update to flask>=2.3.3" },
    "requests": { range: "<2.32.0", severity: "medium", description: "Header injection vulnerability", fix: "Update to requests>=2.32.0" },
    "pillow": { range: "<10.3.0", severity: "critical", description: "Buffer overflow in WEBP parsing", fix: "Update to pillow>=10.3.0" },
    "cryptography": { range: "<42.0.0", severity: "high", description: "Multiple vulnerabilities in older versions", fix: "Update to cryptography>=42.0.0" },
    "urllib3": { range: "<2.2.2", severity: "high", description: "Proxy-Authorization header leak (CVE-2024-37891)", fix: "Update to urllib3>=2.2.2" },
    "jinja2": { range: "<3.1.4", severity: "high", description: "Sandbox breakout via XML attribute injection", fix: "Update to jinja2>=3.1.4" }
  };
}

module.exports = { scanDependencies };
