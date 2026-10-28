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
    "header-max-length": [2, "always", 120],
    // Off: co-author trailers run long.
    "body-max-line-length": [0, "always", 100],
  },
  ignores: [
    (message) => message.startsWith("Merge ") || message.startsWith("merge: "),
  ],
};
