const chalk = require("chalk");

function terminalReport(issues, summary, targetPath) {
  console.log("");
  console.log(chalk.bold.cyan("╔══════════════════════════════════════════╗"));
  console.log(chalk.bold.cyan("║  🛡️  GuardRail Security Scan Report      ║"));
  console.log(chalk.bold.cyan("╚══════════════════════════════════════════╝"));
  console.log("");
  console.log(chalk.gray(`  Target: ${targetPath}`));
  console.log(chalk.gray(`  Scanned: ${new Date().toISOString()}`));
  console.log("");

  const { score, grade, total, critical, high, medium, low } = summary;

  const gradeColor = grade === "A" ? chalk.green : grade === "B" ? chalk.blue : grade === "C" ? chalk.yellow : grade === "D" ? chalk.red : chalk.bgRed.white;
  console.log(`  Security Score: ${gradeColor.bold(` ${score}/100 `)}  Grade: ${gradeColor.bold(` ${grade} `)}`);
  console.log("");
  console.log(`  ${chalk.bgRed.white(` ${critical} CRITICAL `)}  ${chalk.red(`${high} HIGH`)}  ${chalk.yellow(`${medium} MEDIUM`)}  ${chalk.blue(`${low} LOW`)}  —  ${total} total`);
  console.log("");

  if (total === 0) {
    console.log(chalk.green.bold("  🎉 No security issues found! Your project looks clean."));
    console.log("");
    return;
  }

  printSection("🔑 Secrets & Credentials", issues.secrets, "secrets");
  printSection("📦 Dependencies", issues.dependencies, "dependencies");
  printSection("🐛 Code Vulnerabilities (OWASP)", issues.owasp, "owasp");
  printSection("⚙️  Configuration", issues.config, "config");

  console.log("");
  console.log(chalk.gray("──────────────────────────────────────────"));
  console.log(chalk.white.bold("  💡 Quick Fixes:"));
  if (issues.secrets.length > 0) {
    console.log(chalk.yellow(`    • ${issues.secrets.length} secrets found → rotate exposed keys immediately`));
    console.log(chalk.yellow("    • Add .env files to .gitignore and use environment variables"));
  }
  if (issues.dependencies.length > 0) {
    console.log(chalk.yellow(`    • ${issues.dependencies.length} dependency issues → run update commands`));
  }
  if (issues.owasp.length > 0) {
    console.log(chalk.yellow(`    • ${issues.owasp.length} code issues → review and refactor vulnerable patterns`));
  }
  console.log("");
  console.log(chalk.gray("  Run `guardrail report` for a Markdown export."));
  console.log("");
}

function printSection(title, items, type) {
  if (items.length === 0) return;

  const icon = type === "secrets" ? "🔑" : type === "dependencies" ? "📦" : type === "owasp" ? "🐛" : "⚙️";
  console.log(chalk.bold(`\n${icon} ${title} (${items.length})`));
  console.log(chalk.gray("─".repeat(60)));

  const sorted = [...items].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] || 4) - (order[b.severity] || 4);
  });

  const shown = sorted.slice(0, 15);
  for (const item of shown) {
    const sevIcon = item.severity === "critical" ? "🔴" : item.severity === "high" ? "🟠" : item.severity === "medium" ? "🟡" : "🔵";
    console.log(`  ${sevIcon} ${chalk.bold(item.severity.toUpperCase().padEnd(8))} ${chalk.cyan(item.file || item.package || "")}`);
    console.log(`     ${chalk.white(item.message)}`);
    if (item.line) console.log(`     ${chalk.gray(`Line ${item.line}`)}`);
    if (item.fix) console.log(`     ${chalk.green(`Fix: ${item.fix}`)}`);
    if (item.snippet && type !== "dependencies") console.log(`     ${chalk.gray(item.snippet.substring(0, 80))}`);
  }

  if (items.length > 15) {
    console.log(chalk.gray(`  ... and ${items.length - 15} more issues`));
  }
}

module.exports = { terminalReport };
