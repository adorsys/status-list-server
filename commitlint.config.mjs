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
  },
  ignores: [
    // Ignore merge commits (e.g., "Merge branch 'develop' into ...")
    (message) => message.startsWith("Merge "),
  ],
};
