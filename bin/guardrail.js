#!/usr/bin/env node
const { program } = require("commander");
const { scan } = require("../src/index");

program
  .name("guardrail")
  .description("🛡️  Security scanner for indie projects")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan current directory for security issues")
  .option("-p, --path <path>", "Target path", process.cwd())
  .option("-j, --json", "Output as JSON")
  .option("-s, --secrets-only", "Only scan for secrets")
  .option("-d, --deps-only", "Only scan dependencies")
  .option("--no-color", "Disable colors")
  .action(async (options) => {
    const result = await scan(options);
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    }
    process.exit(result.summary.critical > 0 ? 1 : 0);
  });

program
  .command("report")
  .description("Generate a security report from last scan")
  .option("-f, --format <format>", "Output format: json|html|md", "md")
  .action(async (options) => {
    const { generateReport } = require("../src/reporters/markdown");
    console.log(await generateReport(options.format));
  });

program.parse();
