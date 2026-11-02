/** Central security parameters. Changing these requires a reviewed migration and docs update. */
export const PASSWORD_KDF = Object.freeze({ algorithm: 'scrypt', N: 32768, r: 8, p: 3, keyLength: 32, maxmem: 64 * 1024 * 1024 });
export const LEGACY_PBKDF2_ITERATIONS = 600000;
export const CLEARANCE_RSA_MIN_BITS = 3072;
export const HIBP_LOOKUP_TIMEOUT_MS = 400;
