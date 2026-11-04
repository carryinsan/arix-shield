# Dependency lockfile release gate

The runtime helper `@vercel/functions` is pinned in `package.json`, but a pinned direct dependency is not a lock of its transitive dependency graph. A production release must include a reviewed npm `package-lock.json` generated from the official registry with integrity metadata.

Generate it from a network-connected trusted environment using the Node.js 22/npm 10 toolchain:

```sh
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
npm ci
npm audit --omit=dev --audit-level=low
npm test
npm run check
```

Commit the resulting `package-lock.json`. Build/deployment automation should use `npm ci`, not dependency-resolving `npm install`. Do not hand-author package versions or integrity hashes. The current archive intentionally does not contain a fabricated lockfile; dependency audit is an open release gate until the above process succeeds.
