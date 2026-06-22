const SECRET_PATTERNS = [
  {
    id: "GR-SEC-001", type: "aws_access_key", severity: "critical",
    regex: /(?:AWS|aws)_?(?:ACCESS|access)_?(?:KEY|key)[=:]\s*['"]?(AKIA[0-9A-Z]{16})['"]?/,
    message: "AWS Access Key ID exposed",
    redactKey: "(?:AWS|aws)_?(?:ACCESS|access)_?(?:KEY|key)",
    falsePositives: ["AKIAIOSFODNN7EXAMPLE"]
  },
  {
    id: "GR-SEC-002", type: "aws_secret_key", severity: "critical",
    regex: /(?:AWS|aws)_?(?:SECRET|secret)_?(?:KEY|key)[=:]\s*['"]?([0-9a-zA-Z/+]{40})['"]?/,
    message: "AWS Secret Access Key exposed",
    redactKey: "(?:AWS|aws)_?(?:SECRET|secret)_?(?:KEY|key)"
  },
  {
    id: "GR-SEC-003", type: "github_token", severity: "critical",
    regex: /(?:ghp_|github_pat_)([a-zA-Z0-9]{36,255})/,
    message: "GitHub Personal Access Token exposed",
    falsePositives: ["github_pat_XXXXXXXXXXXXXXXXXXXX"]
  },
  {
    id: "GR-SEC-004", type: "openai_key", severity: "critical",
    regex: /(?:OPENAI|openai)_?(?:API|api)_?(?:KEY|key)[=:]\s*['"]?(sk-[a-zA-Z0-9]{32,})['"]?/,
    message: "OpenAI API Key exposed",
    redactKey: "(?:OPENAI|openai)_?(?:API|api)_?(?:KEY|key)"
  },
  {
    id: "GR-SEC-005", type: "stripe_key", severity: "critical",
    regex: /(?:STRIPE|stripe)_?(?:SECRET|secret|API|api)_?(?:KEY|key)[=:]\s*['"]?(sk_live_[a-zA-Z0-9]{24,})['"]?/,
    message: "Stripe Live Secret Key exposed",
    redactKey: "(?:STRIPE|stripe).*(?:KEY|key)"
  },
  {
    id: "GR-SEC-006", type: "stripe_test_key", severity: "medium",
    regex: /(?:STRIPE|stripe)_?(?:SECRET|secret|API|api)_?(?:KEY|key)[=:]\s*['"]?(sk_test_[a-zA-Z0-9]{24,})['"]?/,
    message: "Stripe Test Key exposed (low risk but shouldn't be in source)",
    redactKey: "(?:STRIPE|stripe).*(?:KEY|key)"
  },
  {
    id: "GR-SEC-007", type: "google_api_key", severity: "high",
    regex: /AIza[0-9A-Za-z\-_]{35}/,
    message: "Google API Key exposed"
  },
  {
    id: "GR-SEC-008", type: "jwt_token", severity: "high",
    regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
    message: "JWT Token found in source code",
    falsePositives: ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN"]
  },
  {
    id: "GR-SEC-009", type: "private_key", severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    message: "Private key found in source code"
  },
  {
    id: "GR-SEC-010", type: "slack_webhook", severity: "high",
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+/,
    message: "Slack Webhook URL exposed"
  },
  {
    id: "GR-SEC-011", type: "discord_webhook", severity: "medium",
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/,
    message: "Discord Webhook URL exposed"
  },
  {
    id: "GR-SEC-012", type: "database_url", severity: "high",
    regex: /(?:DATABASE_URL|MONGO_URI|REDIS_URL|POSTGRES_URL)[=:]\s*['"]?(?:mongodb|postgres|mysql|redis):\/\/[^'"]*:[^'"\s@]+@/,
    message: "Database connection string with credentials exposed",
    redactKey: "(?:DATABASE_URL|MONGO_URI|REDIS_URL|POSTGRES_URL)"
  },
  {
    id: "GR-SEC-013", type: "anthropic_key", severity: "critical",
    regex: /(?:ANTHROPIC|anthropic|CLAUDE|claude)_?(?:API|api)_?(?:KEY|key)[=:]\s*['"]?(sk-ant-[a-zA-Z0-9\-_]{50,})['"]?/,
    message: "Anthropic/Claude API Key exposed",
    redactKey: "(?:ANTHROPIC|anthropic|CLAUDE|claude).*(?:KEY|key)"
  },
  {
    id: "GR-SEC-014", type: "deepseek_key", severity: "critical",
    regex: /(?:DEEPSEEK|deepseek)_?(?:API|api)_?(?:KEY|key)[=:]\s*['"]?(sk-[a-zA-Z0-9]{32,})['"]?/,
    message: "DeepSeek API Key exposed",
    redactKey: "(?:DEEPSEEK|deepseek).*(?:KEY|key)"
  },
  {
    id: "GR-SEC-015", type: "generic_password", severity: "medium",
    regex: /(?:PASSWORD|password|PASSWD|passwd|PWD|pwd)[=:]\s*['"](?!(?:${|your|xxx|test|example|changeme|null|empty|none|<))[^'"]{4,}['"]/,
    message: "Hardcoded password found",
    redactKey: "(?:PASSWORD|password|PASSWD|passwd|PWD|pwd)",
    falsePositives: ["password=${DB_PASSWORD}", "password=your-password", "password=xxx"]
  }
];

module.exports = { SECRET_PATTERNS };
