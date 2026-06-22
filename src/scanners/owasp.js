const fs = require("fs");
const path = require("path");

const OWASP_PATTERNS = [
  {
    id: "GR-OWASP-001", type: "xss_innerHTML", severity: "high",
    regex: /\.innerHTML\s*=\s*(?!['"`]\s*['"`])/,
    message: "Potential XSS via innerHTML assignment with dynamic content",
    languages: [".js", ".jsx", ".ts", ".tsx", ".html", ".vue", ".svelte"]
  },
  {
    id: "GR-OWASP-002", type: "dangerous_eval", severity: "critical",
    regex: /\beval\s*\(/,
    message: "eval() usage detected — arbitrary code execution risk",
    languages: [".js", ".jsx", ".ts", ".tsx", ".mjs"]
  },
  {
    id: "GR-OWASP-003", type: "dangerous_function_constructor", severity: "high",
    regex: /\bnew\s+Function\s*\(/,
    message: "new Function() usage — similar risk to eval()",
    languages: [".js", ".jsx", ".ts", ".tsx"]
  },
  {
    id: "GR-OWASP-004", type: "sql_injection_concat", severity: "critical",
    regex: /["'`]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.+\s*\+\s*|["'`]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.+\$\{/i,
    message: "Potential SQL injection via string concatenation in query",
    languages: [".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".rb", ".java"]
  },
  {
    id: "GR-OWASP-005", type: "python_exec", severity: "critical",
    regex: /\bexec\s*\(|\bos\.system\s*\(|\bsubprocess\.call\s*\(.*shell\s*=\s*True/,
    message: "Dangerous code execution in Python",
    languages: [".py"]
  },
  {
    id: "GR-OWASP-006", type: "unsafe_deserialization", severity: "high",
    regex: /\bpickle\.loads?\s*\(|\byaml\.load\s*\(|JSON\.parse\s*\(\s*(?!JSON\.stringify)/,
    message: "Potentially unsafe deserialization",
    languages: [".py", ".js", ".jsx", ".ts", ".tsx"]
  },
  {
    id: "GR-OWASP-007", type: "hardcoded_credential", severity: "high",
    regex: /(?:password|passwd|secret|token|api_key|apikey)\s*[=:]\s*["'][a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,}["']/i,
    message: "Potential hardcoded credential in code (short string)",
    languages: [".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".go", ".rs", ".java"]
  },
  {
    id: "GR-OWASP-008", type: "insecure_cors", severity: "medium",
    regex: /Access-Control-Allow-Origin\s*:\s*\*/,
    message: "CORS configured with wildcard origin — may allow unauthorized cross-origin access",
    languages: [".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".go"]
  },
  {
    id: "GR-OWASP-009", type: "insecure_random", severity: "medium",
    regex: /\bMath\.random\s*\(\s*\)/,
    message: "Math.random() used for security-sensitive operation — use crypto.randomUUID()",
    languages: [".js", ".jsx", ".ts", ".tsx"]
  },
  {
    id: "GR-OWASP-010", type: "nosql_injection", severity: "high",
    regex: /\{\s*["']\$where["']\s*:|\.find\(\s*\{[^}]*\$(?:where|regex|ne|gt|lt)\b/,
    message: "Potential NoSQL injection with raw operator usage",
    languages: [".js", ".jsx", ".ts", ".tsx"]
  },
  {
    id: "GR-OWASP-011", type: "insecure_redirect", severity: "medium",
    regex: /(?:res\.redirect|location\.href|window\.location)\s*[=\(]\s*(?:req\.(?:query|params|body)|request\.(?:GET|POST))/,
    message: "Open redirect vulnerability — user input used in redirect",
    languages: [".js", ".jsx", ".ts", ".tsx", ".py", ".php"]
  },
  {
    id: "GR-OWASP-012", type: "debug_enabled", severity: "medium",
    regex: /DEBUG\s*=\s*True|NODE_ENV\s*=\s*["']development["']|django\.settings\.DEBUG\s*=\s*True/,
    message: "Debug mode enabled — may leak sensitive info in production",
    languages: [".py", ".js", ".jsx", ".ts", ".tsx", ".env"]
  },
  {
    id: "GR-OWASP-013", type: "insecure_cookie", severity: "medium",
    regex: /secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*["']none["']/,
    message: "Insecure cookie configuration",
    languages: [".js", ".jsx", ".ts", ".tsx"]
  },
  {
    id: "GR-OWASP-014", type: "command_injection", severity: "critical",
    regex: /child_process\.(?:exec|spawn|execSync)\s*\(.*\+|child_process\.(?:exec|spawn)\s*\(\s*["'][^"']*\$/,
    message: "Potential command injection via string concatenation",
    languages: [".js", ".jsx", ".ts", ".tsx"]
  },
  {
    id: "GR-OWASP-015", type: "exposed_port_comment", severity: "low",
    regex: /#\s*(?:TODO|FIXME|HACK|XXX|TEMP|WORKAROUND|INSECURE)/i,
    message: "Security-related TODO/FIXME comment found",
    languages: [".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".go", ".rs", ".java", ".php"]
  }
];

function scanOwasp(filePath) {
  const findings = [];
  const ext = path.extname(filePath).toLowerCase();
  let content;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return findings;
  }

  const lines = content.split("\n");
  const applicablePatterns = OWASP_PATTERNS.filter(p => p.languages.includes(ext));

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith("//") || line.trim().startsWith("#")) continue;

    for (const pattern of applicablePatterns) {
      if (pattern.regex.test(line)) {
        findings.push({
          type: pattern.type,
          severity: pattern.severity,
          line: i + 1,
          message: pattern.message,
          snippet: line.trim().substring(0, 120),
          rule: pattern.id
        });
      }
    }
  }

  return findings;
}

module.exports = { scanOwasp };
