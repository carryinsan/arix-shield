import { generateKeyPairSync, randomUUID } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
const kid = `arix-${randomUUID()}`;
const publicJwk = { ...publicKey.export({ format: 'jwk' }), alg: 'RSA-OAEP-256', use: 'enc', kid, ext: true };
const privateJwk = { ...privateKey.export({ format: 'jwk' }), alg: 'RSA-OAEP-256', use: 'enc', kid, ext: true };
console.log('Add these values to the ArixShield Vercel project environment (private value is sensitive):\n');
console.log(`ARIX_CLEARANCE_KID=${kid}`);
console.log(`ARIX_CLEARANCE_PUBLIC_JWK=${JSON.stringify(publicJwk)}`);
console.log(`ARIX_CLEARANCE_PRIVATE_JWK=${JSON.stringify(privateJwk)}`);
