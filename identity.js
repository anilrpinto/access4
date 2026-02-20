"use strict";

import { C } from './constants.js';
import { G } from './global.js';
import * as ID from './identity.js';

import * as GD from './gdrive.js';

import { log, trace, debug, info, warn, error } from './log.js';

//buildIdentityFromKeypair

/* ---------------------- DEVICE ---------------------- */
export function getDeviceId() {
    let id = localStorage.getItem(C.DEVICE_ID_KEY);
    if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem(C.DEVICE_ID_KEY, id);
        log("[getDeviceId] New device ID generated");
    }
    return id;
}

function identityKey() {
    return `access4.identity::${G.userEmail}::${getDeviceId()}`;
}

export function saveIdentity(id) {
    localStorage.setItem(identityKey(), JSON.stringify(id));
}

export async function loadIdentity() {
    log("[loadIdentity] called");
    log("[loadIdentity] G.sessionUnlocked:", !!G.sessionUnlocked);
    log("[loadIdentity] G.unlockedIdentity:", !!G.unlockedIdentity);

    if (G.sessionUnlocked && G.unlockedIdentity) {
        log("[loadIdentity] Returning G.unlockedIdentity from memory");
        return G.unlockedIdentity;
    }

    return loadIdentityFromStorage();
}

function loadIdentityFromStorage() {
    log("[loadIdentityFromStorage] called");

    const raw = localStorage.getItem(identityKey());
    log("[loadIdentityFromStorage] Identity in localStorage exists:", !!raw);

    if (!raw) return null;

    try {
        const id = JSON.parse(raw);
        //trace("[loadIdentityFromStorage] Identity loaded from localStorage:", JSON.stringify(id));
        if (G.sessionUnlocked && G.currentPrivateKey) {
            id._sessionPrivateKey = G.currentPrivateKey;
        }
        return id;
    } catch (e) {
        error("❌ Failed to parse identity:", e);
        return null;
    }
}

/* ---------------------- PUBLIC KEY ---------------------- */
export async function ensureDevicePublicKey() {
    log("[ensureDevicePublicKey] called");

    const folder = await GD.findOrCreateUserFolder();
    const id = await ID.loadIdentity();
    if (!id) throw new Error("Local identity missing");

    const deviceId = ID.getDeviceId();
    const filename = `${G.userEmail}__${deviceId}.json`;

    const q = `'${folder}' in parents and name='${filename}'`;
    const res = await GD.driveFetch(GD.buildDriveUrl("files", { q, fields:"files(id)" }));

    // Compute fingerprint (canonical keyId)
    const pubBytes = Uint8Array.from(atob(id.publicKey), c => c.charCodeAt(0));
    const hashBuffer = await crypto.subtle.digest("SHA-256", pubBytes);
    const fingerprint = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

    const pubData = {
        version:"1",
        account: G.userEmail,
        deviceId,
        keyId: fingerprint,
        fingerprint,
        state:"active",
        role:"device",
        supersedes: id.supersedes || null,
        created: new Date().toISOString(),
        algorithm: {
            type:"RSA",
            usage: ["wrapKey"],
            modulusLength: 2048,
            hash:"SHA-256"
        },
        publicKey: {
            format:"spki",
            encoding:"base64",
            data: id.publicKey
        },
        deviceName: `${navigator.platform} - ${navigator.userAgent}`.substring(0, 64),
        browser: navigator.userAgentData?.brands?.map(b => b.brand).join(",") || navigator.userAgent,
        os: navigator.platform
    };

    if (res.files.length > 0) {
        const fileId = res.files[0].id;

        // --- PATCH only the content fields (Drive forbids updating certain metadata) ---
        const contentOnly = {
            publicKey: pubData.publicKey,
            state: pubData.state,
            supersedes: pubData.supersedes
        };

        await GD.driveFetch(GD.buildDriveUrl(`files/${fileId}`, { uploadType:"media" }), {
            method:"PATCH",
            headers: { "Content-Type":"application/json" },
            body: JSON.stringify(contentOnly)
        });

        log("[ensureDevicePublicKey] Device public key UPDATED");
        return;
    }

    // File doesn't exist → create new
    await GD.driveMultipartUpload({
        metadata: { name: filename, parents: [folder] },
        content: JSON.stringify(pubData)
    });

    log("[ensureDevicePublicKey] Device public key UPLOADED");
}

export async function migrateIdentityWithVerifier(id, pwd) {
    log("[migrateIdentityWithVerifier] called - Migrating identity to add password verifier");

    const key = await deriveKey(pwd, id.kdf);

    // Prove password correctness by decrypting private key
    await decrypt(id.encryptedPrivateKey, key);

    // Create and attach verifier
    id.passwordVerifier = await createPasswordVerifier(key);

    ID.saveIdentity(id);

    log("[migrateIdentityWithVerifier] Identity auto-migrated with password verifier");
}

export async function deriveKey(pwd, kdf) {

    log("[deriveKey] called");

    const mat = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(pwd),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey({
        name:"PBKDF2",
        salt: Uint8Array.from(atob(kdf.salt), c => c.charCodeAt(0)),
        iterations: kdf.iterations,
        hash:"SHA-256"
    },
        mat, {
            name:"AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function decrypt(enc, key) {
    return crypto.subtle.decrypt({
        name:"AES-GCM",
        iv: Uint8Array.from(atob(enc.iv), c => c.charCodeAt(0))
    },
        key,
        Uint8Array.from(atob(enc.data), c => c.charCodeAt(0))
    );
}

async function createPasswordVerifier(key) {
    const data = new TextEncoder().encode("identity-ok");
    return encrypt(data, key);
}

async function encrypt(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({
        name:"AES-GCM",
        iv
    }, key, data);
    return {
        iv: btoa(String.fromCharCode(...iv)),
        data: btoa(String.fromCharCode(...new Uint8Array(enc)))
    };
}

export async function verifyPasswordVerifier(verifier, key) {
    const buf = await decrypt(verifier, key);
    const text = new TextDecoder().decode(buf);
    if (text !== "identity-ok") {
        throw new Error("INVALID_PASSWORD");
    }
}

export async function rotateDeviceIdentity(pwd) {
    log("[rotateDeviceIdentity] called - Rotating device identity key");

    const oldIdentity = await ID.loadIdentity();
    if (!oldIdentity) {
        throw new Error("Cannot rotate — no existing identity");
    }

    const keypair = await generateDeviceKeypair();

    const newIdentity = await buildIdentityFromKeypair(keypair, pwd, {
        supersedes: oldIdentity.fingerprint,
        previousKeys: [
            ...(oldIdentity.previousKeys || []),
            {
                fingerprint: oldIdentity.fingerprint,
                created: oldIdentity.created,
                encryptedPrivateKey: oldIdentity.encryptedPrivateKey, // <-- Store encrypted private key
                kdf: oldIdentity.kdf // <-- Include kdf so unwrapContentKey can derive correctly
            }
        ]
    }
    );

    saveIdentity(newIdentity);

    log("[rotateDeviceIdentity] Device identity rotated");
    log(`[rotateDeviceIdentity] New KeyId: ${newIdentity.fingerprint} supersedes Old keyId: ${oldIdentity.fingerprint}`);

    // --- Drive updates (best effort) ---
    try {
        await GD.markPreviousDriveKeyDeprecated(oldIdentity.fingerprint, newIdentity.fingerprint); // updates old key JSON
        await ensureDevicePublicKey();        // uploads NEW active key
        log("[rotateDeviceIdentity] Drive key lifecycle updated");
    } catch (e) {
        warn("[rotateDeviceIdentity] Drive update failed (local rotation preserved):", e.message);
    }
}

async function generateDeviceKeypair() {
    const pair = await crypto.subtle.generateKey({
        name:"RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash:"SHA-256"
    },
        true,
        ["encrypt", "decrypt"]
    );

    const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
    const publicKeySpki = await crypto.subtle.exportKey("spki", pair.publicKey);

    return {
        privateKeyPkcs8,
        publicKeySpki
    };
}

/* --------------- CREATE IDENTITY start ----------------- */
async function createIdentity(pwd) {
    log("🔐 Generating new device identity key pair");

    const keypair = await generateDeviceKeypair();
    const identity = await buildIdentityFromKeypair(keypair, pwd);

    saveIdentity(identity);

    log("✅ New identity created and stored locally");

    if (G.biometricIntent && !G.biometricRegistered) {
        log("👆 Biometric enrollment intent detected, enrolling now...");
        await enrollBiometric(pwd);
        G.biometricRegistered = true;
    }
}

async function buildIdentityFromKeypair({privateKeyPkcs8, publicKeySpki}, pwd, opts = {}) {
    const pubB64 = btoa(String.fromCharCode(...new Uint8Array(publicKeySpki)));
    const fingerprint = await computeFingerprintFromPublicKey(pubB64);

    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const kdf = {
        salt: btoa(String.fromCharCode(...saltBytes)),
        iterations: 100000
    };

    const key = await deriveKey(pwd, kdf);
    const passwordVerifier = await createPasswordVerifier(key);
    const encryptedPrivateKey = await encrypt(privateKeyPkcs8, key);

    return {
        passwordVerifier,
        encryptedPrivateKey,
        publicKey: pubB64,
        fingerprint,
        kdf,
        deviceId: ID.getDeviceId(),
        email: G.userEmail,
        created: new Date().toISOString(),
        ...opts
    };
}


async function computeFingerprintFromPublicKey(base64Spki) {
    const pubBytes = Uint8Array.from(atob(base64Spki), c => c.charCodeAt(0));
    const hash = await crypto.subtle.digest("SHA-256", pubBytes);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

export async function enrollBiometric(pwd) {
    if (!window.PublicKeyCredential) return;
    const cred = await navigator.credentials.create({
        publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: {
                name:"Access4"
            },
            user: {
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: G.userEmail,
                displayName: G.userEmail
            },
            pubKeyCredParams: [{
                type:"public-key",
                alg: -7
            }],
            authenticatorSelection: {
                userVerification:"required"
            },
            timeout: 60000
        }
    });
    localStorage.setItem(bioCredKey(), btoa(String.fromCharCode(...new Uint8Array(cred.rawId))));
    localStorage.setItem(bioPwdKey(), btoa(pwd));
    log("🧬 Hidden biometric shortcut enrolled");
}

export async function cacheDecryptedPrivateKey(decryptedPrivateKeyBytes) {

    log("[cacheDecryptedPrivateKey] called");
    try {
        if (!decryptedPrivateKeyBytes) throw new Error("No decrypted key available");

        const base64 = arrayBufferToBase64(decryptedPrivateKeyBytes);
        sessionStorage.setItem("sv_session_private_key", base64);

        // Keep in-memory reference for session restore
        G.currentPrivateKey = await crypto.subtle.importKey(
            "pkcs8",
            decryptedPrivateKeyBytes,
            { name:"RSA-OAEP", hash:"SHA-256" },
            false,
            ["decrypt", "unwrapKey"]
        );

        G.sessionUnlocked = true;
        log("[cacheDecryptedPrivateKey] Session private key cached");

    } catch (e) {
        warn("[cacheDecryptedPrivateKey] Session caching failed (non-fatal):" + e.message);
    }

    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000; // 32k chunks
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.subarray(i, i + chunkSize);
            binary += String.fromCharCode(...chunk);
        }
        return btoa(binary);
    }
}