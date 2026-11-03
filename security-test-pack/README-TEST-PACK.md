# ArixShield v1.4.4 — consolidated security test index

The former standalone test pack contained byte-identical copies of tests, runners,
and evidence files that are already part of this complete repository. Those copies
have been removed to avoid duplicate files. The canonical files are preserved at
the repository root:

- `test/` — the complete merged regression and adversarial suite.
- `scripts/run-100k-lab.mjs` and `scripts/run-endurance.mjs` — deterministic local
  lab and in-process endurance runners.
- `scripts/run-browser-farm.mjs` — optional restricted browser runner.
- `scripts/asvs-l3-verifier.mjs`, `docs/asvs-evidence-map.json`, and
  `docs/ASVS-5.0.0-L3-VERIFICATION-MATRIX.md` — partial evidence tooling and matrix.
- `results/` — current test transcript plus explicitly historical lab artifacts.

Run commands from the repository root with Node.js 22.x:

```bash
npm test
npm run check
```

The current local suite result is recorded in `results/TEST-RESULTS-SUMMARY.md`.
Historical 100k corpus and endurance reports are not measurements of this merged
release unless explicitly stated in their report. No test report is an ASVS
certification or substitute for independent penetration testing.
