import { log, trace, debug, info, warn, error } from '@/shared/log.js';

// Helpers
function normalizeBytes(data) {
    if (data instanceof Uint8Array) {
        return data;
    }

    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }

    if (typeof data === "string") {
        return new TextEncoder().encode(data);
    }

    throw new Error("CR.encrypt: Unsupported input type");
}

function assertKeyUsage(key, requiredUsage) {

    if (!key.usages.includes(requiredUsage)) {
        throw new Error(
            `CryptoKey missing required usage '${requiredUsage}'. ` +
            `Actual usages: [${key.usages.join(", ")}]`
        );
    }
}

/**
 * EXPORTED FUNCTIONS
 */
export const CR_ALG = {
    RSA: {
        DEFAULT: "RSA",
        OAEP: "RSA-OAEP"
    },
    HASH: {
        SHA256: "SHA-256"
    },
    AES: {
        GCM: "AES-GCM"
    },
    PBKDF2: "PBKDF2",
    HKDF: "HKDF",

    SALT_LENGTH: 16,
    PBKDF2_ITERATIONS: 100000,
    AES_GCM_IV_LENGTH: 12,
    RSA_MODULUS_LENGTH: 2048,
};

export function randomBytes(len = CR_ALG.SALT_LENGTH) {
    return crypto.getRandomValues(new Uint8Array(len));
}

export function generateUUID() {
    return crypto.randomUUID();
}

export async function deriveKey(pwd, kdf) {
    log("CR.deriveKey", "called");

    const rawKey = new TextEncoder().encode(pwd);
    const baseKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        CR_ALG.PBKDF2,
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: CR_ALG.PBKDF2,
            salt: b64ToBuf(kdf.salt),
            iterations: kdf.iterations,
            hash: CR_ALG.HASH.SHA256
        },
        baseKey,
        { name: CR_ALG.AES.GCM, length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function computePublicKeyFingerprint(pubBytes) {
    log("CR.computePublicKeyFingerprint", "called");

    const buf = pubBytes instanceof ArrayBuffer ? new Uint8Array(pubBytes) : pubBytes;
    const hashBuffer = await crypto.subtle.digest(CR_ALG.HASH.SHA256, buf);
    return bufToB64(new Uint8Array(hashBuffer));
}

export async function encrypt(data, key) {
    log("CR.encrypt", "called");

    const bytes = normalizeBytes(data);
    const iv = crypto.getRandomValues(new Uint8Array(CR_ALG.AES_GCM_IV_LENGTH));

    const enc = await crypto.subtle.encrypt({
        name: CR_ALG.AES.GCM,
        iv
    },
        key,
        bytes
    );

    return {
        iv: bufToB64(iv),
        data: bufToB64(enc)
    };
}

export async function decrypt(enc, key) {
    log("CR.decrypt", "called");
    return crypto.subtle.decrypt({
            name:CR_ALG.AES.GCM,
            iv: b64ToBuf(enc.iv)
        },
        key,
        b64ToBuf(enc.data)
    );
}

// CEK Wrap (Device or Recovery)
export async function wrapCEKForPublicKey(cek, publicKey) {
    log("CR.wrapCEKForPublicKey", "called");

    assertKeyUsage(publicKey, "wrapKey");

    const wrapped = await crypto.subtle.wrapKey(
        "raw",
        cek,
        publicKey,
        { name: CR_ALG.RSA.OAEP }
    );

    return bufToB64(wrapped);
}

// CEK Unwrap
export async function unwrapCEKWithPrivateKey(wrappedKeyB64, privateKey) {
    log("CR.unwrapCEKWithPrivateKey", "called");

    if (!(privateKey instanceof CryptoKey)) {
        throw new Error("unwrapCEKWithPrivateKey: privateKey must be CryptoKey");
    }

    assertKeyUsage(privateKey, "unwrapKey");

    const wrappedBytes = b64ToBuf(wrappedKeyB64);

    return crypto.subtle.unwrapKey(
        "raw",
        wrappedBytes,
        privateKey,
        { name: CR_ALG.RSA.OAEP },
        { name: CR_ALG.AES.GCM, length: 256 },
        true,
        ["encrypt","decrypt"]
    );
}

// RSA Keypair Generation
export async function generateRSAKeypair() {
    log("CR.generateRSAKeypair", "called");

    return crypto.subtle.generateKey(
        {
            name: CR_ALG.RSA.OAEP,
            modulusLength: CR_ALG.RSA_MODULUS_LENGTH,
            publicExponent: new Uint8Array([1,0,1]),
            hash: CR_ALG.HASH.SHA256
        },
        true,
        ["encrypt","decrypt"]
    );
}

// Export Keys
export async function exportPublicKey(publicKey) {
    return crypto.subtle.exportKey("spki", publicKey);
}

export async function exportPrivateKey(privateKey) {
    return crypto.subtle.exportKey("pkcs8", privateKey);
}

// Import Keys
export async function importRSAPrivateKey(pkcs8Bytes, usages=["decrypt","unwrapKey"]) {
    log("CR.importRSAPrivateKey", "called");

    return crypto.subtle.importKey(
        "pkcs8",
        pkcs8Bytes,
        { name:CR_ALG.RSA.OAEP, hash:CR_ALG.HASH.SHA256 },
        false,
        usages
    );
}

export async function importRSAPrivateKeyFromB64(b64, usages=["decrypt","unwrapKey"]) {
    log("CR.importRSAPrivateKeyFromB64", "called");
    return importRSAPrivateKey(b64ToBuf(b64), usages);
}

export async function importRSAPublicKey(spkiBytes, usages=["wrapKey"]) {
    log("CR.importRSAPublicKey", "called");

    return crypto.subtle.importKey(
        "spki",
        spkiBytes,
        { name:CR_ALG.RSA.OAEP, hash:CR_ALG.HASH.SHA256 },
        false,
        usages
    );
}

export async function importRSAPublicKeyFromB64(b64, usages=["wrapKey"]) {
    log("CR.importRSAPublicKeyFromB64", "called");
    return importRSAPublicKey(b64ToBuf(b64), usages);
}

export async function generateCEK() {
    log("CR.generateCEK", "called");

    return crypto.subtle.generateKey(
        {
            name: CR_ALG.AES.GCM,
            length: 256
        },
        true,
        ["encrypt","decrypt"]
    );
}

/**
 * Low-level HKDF derivation.
 * Moves the subtle crypto complexity out of the business logic.
 */
export async function deriveSubKey(baseKey, salt, info) {
    log("CR.deriveSubKey", "called");

    // 1. Export the Master Key (CEK) to raw bytes
    const rawByteKey = await crypto.subtle.exportKey("raw", baseKey);

    // 2. Import it specifically for HKDF
    const hkdfBase = await crypto.subtle.importKey(
        "raw",
        rawByteKey,
        CR_ALG.HKDF,
        false,
        ["deriveKey"]
    );

    // 3. Derive the specific AES-GCM key
    return crypto.subtle.deriveKey(
        {
            name: CR_ALG.HKDF,
            salt: normalizeBytes(salt),
            info: normalizeBytes(info),
            hash: CR_ALG.HASH.SHA256
        },
        hkdfBase,
        { name: CR_ALG.AES.GCM, length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

export function bufToB64(input) {

    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);

    let binary = "";
    const chunkSize = 0x8000; // 32k chunks

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }

    return btoa(binary);
}

export function b64ToBuf(b64) {

    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}
