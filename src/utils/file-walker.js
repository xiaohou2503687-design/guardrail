const fs = require("fs");
const path = require("path");
const { glob } = require("glob");

const IGNORE_PATTERNS = [
  "node_modules/**", ".git/**", ".next/**", "dist/**", "build/**",
  "*.min.js", "*.min.css", "*.map", "*.lock", "*.pb.go",
  "__pycache__/**", ".venv/**", "vendor/**", "target/**",
  "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
  "*.woff", "*.woff2", "*.ttf", "*.eot",
  "*.mp3", "*.mp4", "*.webm", "*.ogg",
  "*.zip", "*.tar", "*.gz", "*.rar", "*.7z",
  "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx",
  ".DS_Store", "Thumbs.db"
];

const TEXT_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".pyi", ".pyx",
  ".go", ".rs", ".java", ".kt", ".swift",
  ".rb", ".php", ".c", ".cpp", ".h", ".hpp",
  ".html", ".htm", ".css", ".scss", ".less",
  ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg",
  ".md", ".mdx", ".txt", ".csv", ".rst",
  ".sh", ".bash", ".zsh", ".fish", ".ps1",
  ".env", ".gitignore", ".dockerignore",
  ".sql", ".graphql", ".gql",
  ".vue", ".svelte", ".astro",
  "Dockerfile", "Makefile", "Gemfile", "Rakefile"
]);

async function walkFiles(rootDir) {
  const pattern = path.join(rootDir, "**/*").replace(/\\/g, "/");
  const files = await glob(pattern, {
    ignore: IGNORE_PATTERNS.map(p => path.join(rootDir, p).replace(/\\/g, "/")),
    nodir: true,
    dot: true
  });
  return files;
}

function isTextFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath);
  if (TEXT_EXTENSIONS.has(ext)) return true;
  if (TEXT_EXTENSIONS.has(base)) return true;
  if (ext === "" && !base.startsWith(".")) {
    try {
      const buf = fs.readFileSync(filePath, { length: 512 });
      return !buf.includes(0);
    } catch { return false; }
  }
  return false;
}

function shouldIgnore(filePath) {
  const relative = filePath.toLowerCase();
  return IGNORE_PATTERNS.some(p => {
    const pattern = p.replace(/\*\*/g, ".*").replace(/\*/g, "[^/]*");
    return new RegExp(pattern, "i").test(relative);
  });
}

module.exports = { walkFiles, isTextFile, shouldIgnore };
