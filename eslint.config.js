import js from "@eslint/js";
import security from "eslint-plugin-security";
import globals from "globals";

export default [
  { ignores: ["bin/", "dist/", "node_modules/", "tests/out/"] },
  js.configs.recommended,
  security.configs.recommended,
  {
    files: ["extension/**/*.js"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.browser, ...globals.webextensions },
    },
  },
  {
    files: ["tests/**/*.js", "*.js"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.node },
    },
  },
  {
    rules: {
      eqeqeq: "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
];
