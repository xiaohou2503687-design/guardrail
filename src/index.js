const { walkFiles, isTextFile, shouldIgnore } = require("./utils/file-walker");
const { scanSecrets } = require("./scanners/secrets");
const { scanDependencies } = require("./scanners/dependencies");
const { scanOwasp } = require("./scanners/owasp");
const { scanConfig } = require("./scanners/config");
const { terminalReport } = require("./reporters/terminal");
const fs = require("fs");
const path = require("path");

async function scan(options) {
  const targetPath = options.path || process.cwd();
  const issues = { secrets: [], dependencies: [], owasp: [], config: [] };

  if (!options.depsOnly) {
    console.log("🔍 Scanning for secrets and vulnerabilities...\n");

    const files = await walkFiles(targetPath);
    const textFiles = files.filter(f => isTextFile(f) && !shouldIgnore(f));

    for (const file of textFiles) {
      const relPath = path.relative(targetPath, file);
      const secrets = scanSecrets(file);
      if (secrets.length) {
        issues.secrets.push(...secrets.map(s => ({ ...s, file: relPath })));
      }
      const owaspIssues = scanOwasp(file);
      if (owaspIssues.length) {
        issues.owasp.push(...owaspIssues.map(o => ({ ...o, file: relPath })));
      }
      const configIssues = scanConfig(file);
      if (configIssues.length) {
        issues.config.push(...configIssues.map(c => ({ ...c, file: relPath })));
      }
    }
  }

  if (!options.secretsOnly) {
    const depIssues = await scanDependencies(targetPath);
    issues.dependencies = depIssues;
  }

  const summary = calculateSummary(issues);
  terminalReport(issues, summary, targetPath);

  // Save report for "guardrail report" command
  const reportPath = path.join(targetPath, ".guardrail-report.json");
  fs.writeFileSync(reportPath, JSON.stringify({ issues, summary, scannedAt: new Date().toISOString(), targetPath }, null, 2));

  return { issues, summary, scannedAt: new Date().toISOString(), targetPath };
}

function calculateSummary(issues) {
  const total = Object.values(issues).flat().length;
  const critical = Object.values(issues).flat().filter(i => i.severity === "critical").length;
  const high = Object.values(issues).flat().filter(i => i.severity === "high").length;
  const medium = Object.values(issues).flat().filter(i => i.severity === "medium").length;
  const low = Object.values(issues).flat().filter(i => i.severity === "low").length;

  const score = Math.max(0, 100 - (critical * 25) - (high * 10) - (medium * 3) - low);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  return { total, critical, high, medium, low, score, grade };
}

module.exports = { scan };
