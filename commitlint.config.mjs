const allowedTypes = [
  "build",
  "chore",
  "ci",
  "docs",
  "feat",
  "fix",
  "perf",
  "refactor",
  "revert",
  "style",
  "test",
];

export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [2, "always", allowedTypes],
    // Allow longer headers (120 instead of 100)
    "header-max-length": [2, "always", 120],
    // Disable body line length check (too restrictive for co-authored trailers)
    "body-max-line-length": [0, "always", 100],
  },
  ignores: [
    // Ignore merge commits (e.g., "Merge branch 'develop' into ...")
    (message) => message.startsWith("Merge "),
  ],
};
