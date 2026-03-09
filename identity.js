"use strict";

import { C } from './constants.js';
import { G } from './global.js';

import * as AU from './auth.js';
import * as BM from './biometrics.js';
import * as CR from './crypto.js';
import * as GD from './gdrive.js';
import * as U from './utils.js';

import { log, trace, debug, info, warn, error } from './log.js';

export const VERIFIER_TEXT = "identity-ok";

/* ---------------------- DEVICE ---------------------- */
export function getDeviceId() {
    let id = localStorage.getItem(C.DEVICE_ID_KEY);
    if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem(C.DEVICE_ID_KEY, id);
        log("ID.getDeviceId", "New device ID generated: " + id);
    }
    return id;
}

function identityKey() {
    return `access4.identity::${G.userEmail}::${getDeviceId()}`;
}

export function removeDeviceIdentity() {
    const key = identityKey();
    if (localStorage.getItem(key)) {
        warn("ID.removeDeviceIdentity", "Removing identity:" + key);
        localStorage.removeItem(C.DEVICE_ID_KEY);
        localStorage.removeItem(key);
    }
}

function saveIdentity(id) {
    localStorage.setItem(identityKey(), JSON.stringify(id));
}

export async function loadIdentity() {
    log("ID.loadIdentity", "called");
    trace("ID.loadIdentity", `G.sessionUnlocked: ${!!G.sessionUnlocked}, G.unlockedIdentity: ${!!G.unlockedIdentity}`);

    if (G.sessionUnlocked && G.unlockedIdentity) {
        log("ID.loadIdentity", "Returning G.unlockedIdentity from memory");
        return G.unlockedIdentity;
    }

    return loadIdentityFromStorage();
}

function loadIdentityFromStorage() {
    log("ID.loadIdentityFromStorage", "called");

    const raw = localStorage.getItem(identityKey());
    log("ID.loadIdentityFromStorage", "Identity in localStorage exists:", !!raw);

    if (!raw) return null;

    try {
        const id = JSON.parse(raw);
        //trace("ID.loadIdentityFromStorage", "Identity loaded from localStorage:", JSON.stringify(id));
        if (G.sessionUnlocked && G.currentPrivateKey) {
            id._sessionPrivateKey = G.currentPrivateKey;
        }
        return id;
    } catch (e) {
        error("ID.loadIdentityFromStorage", "Failed to parse identity:", e);
        return null;
    }
}

/* ---------------------- PUBLIC KEY ---------------------- */
export async function ensureDevicePublicKey() {
    log("ID.ensureDevicePublicKey", "called");

    const folder = await GD.findOrCreateUserFolder();
    const id = await loadIdentity();
    if (!id) throw new Error("Local identity missing");

    const deviceId = getDeviceId();
    const filename = `${G.userEmail}__${deviceId}.json`;

    const q = `'${folder}' in parents and name='${filename}'`;
    const res = await GD.driveFetch(GD.buildDriveUrl("files", { q, fields:"files(id)" }));

    // Compute fingerprint (canonical keyId)
    const pubBytes = Uint8Array.from(atob(id.publicKey), c => c.charCodeAt(0));
    //const hashBuffer = await crypto.subtle.digest("SHA-256", pubBytes);
    //const fingerprint = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

    const fingerprint = await CR.computePublicKeyFingerprint(pubBytes);

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
            body: U.format(contentOnly)
        });

        log("ID.ensureDevicePublicKey", `Device public key UPDATED in ${filename.slice(-30)}`);
        return;
    }

    // File doesn't exist → create new
    await GD.driveMultipartUpload({
        metadata: { name: filename, parents: [folder] },
        content: U.format(pubData)
    });

    log("ID.ensureDevicePublicKey", `Device public key UPLOADED to ${filename.slice(-30)}`);
}

export async function migrateIdentityWithVerifier(id, pwd) {
    log("ID.migrateIdentityWithVerifier", "called - Migrating identity to add password verifier");

    const key = await CR.deriveKey(pwd, id.kdf);

    // Prove password correctness by decrypting private key
    await CR.decrypt(id.encryptedPrivateKey, key);

    // Create and attach verifier
    id.passwordVerifier = await createPasswordVerifier(key);

    saveIdentity(id);

    log("ID.migrateIdentityWithVerifier", "Identity auto-migrated with password verifier");
}

export async function verifyPasswordVerifier(verifier, key) {
    log("ID.verifyPasswordVerifier", "called");
    const buf = await CR.decrypt(verifier, key);
    const text = new TextDecoder().decode(buf);
    if (text !== VERIFIER_TEXT) {
        throw new Error("INVALID_PASSWORD");
    }
}

export async function rotateDeviceIdentity(pwd) {
    log("ID.rotateDeviceIdentity", "called - Rotating device identity key");

    const oldIdentity = await loadIdentity();
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

    log("ID.rotateDeviceIdentity", "Device identity rotated");
    log("ID.rotateDeviceIdentity", `New KeyId: ${newIdentity.fingerprint} supersedes Old keyId: ${oldIdentity.fingerprint}`);

    // --- Drive updates (best effort) ---
    try {
        await GD.markPreviousDriveKeyDeprecated(oldIdentity.fingerprint, newIdentity.fingerprint); // updates old key JSON
        await ensureDevicePublicKey();        // uploads NEW active key
        log("ID.rotateDeviceIdentity", "Drive key lifecycle updated");
    } catch (e) {
        warn("ID.rotateDeviceIdentity", "Drive update failed (local rotation preserved):", e.message);
    }
}

async function generateDeviceKeypair() {
    log("ID.generateDeviceKeypair", "called");

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
export async function createIdentity(pwd) {
    log("ID.createIdentity", "called - Generating new device identity key pair");

    const keypair = await generateDeviceKeypair();
    const identity = await buildIdentityFromKeypair(keypair, pwd);

    saveIdentity(identity);

    // Use SAME Layer 1 initializer as unlock
    await cacheDecryptedPrivateKey(keypair.privateKeyPkcs8);

    // Mark identity as unlocked for this session
    G.unlockedIdentity = identity;

    log("ID.createIdentity", "New identity created and session unlocked");
}

export async function buildIdentityFromKeypair({privateKeyPkcs8, publicKeySpki}, pwd, opts = {}) {
    log("ID.buildIdentityFromKeypair", "called");

    // Note: Consider utils.bufferToBase64(publicKeySpki) in case of overflow error because of String.fromCharCode
    //const pubB64 = btoa(String.fromCharCode(...new Uint8Array(publicKeySpki)));

    // Actually faced a silent error that resulted in an empty base64 key data being written and had to switch to the helper method
    // TODO: Change similar code that commented above to the below implementation throughout the app
    const pubB64 = U.bufferToBase64(publicKeySpki);

    if (pubB64.length < 200) {
        throw new Error("Public key export failed");
    }

    const fingerprint = await CR.computePublicKeyFingerprint(publicKeySpki);

    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const kdf = {
        salt: btoa(String.fromCharCode(...saltBytes)),
        iterations: 100000
    };

    const key = await CR.deriveKey(pwd, kdf);
    const passwordVerifier = await createPasswordVerifier(key);
    const encryptedPrivateKey = await CR.encrypt(privateKeyPkcs8, key);

    return {
        passwordVerifier,
        encryptedPrivateKey,
        publicKey: pubB64,
        fingerprint,
        kdf,
        deviceId: getDeviceId(),
        email: G.userEmail,
        created: new Date().toISOString(),
        ...opts
    };
}

async function createPasswordVerifier(key) {
    log("ID.createPasswordVerifier", "called");
    const data = new TextEncoder().encode(VERIFIER_TEXT);
    return CR.encrypt(data, key);
}

export async function cacheDecryptedPrivateKey(decryptedPrivateKeyBytes) {

    log("ID.cacheDecryptedPrivateKey", "called");
    try {
        if (!decryptedPrivateKeyBytes) throw new Error("No decrypted key available");

        const base64 = U.bufferToBase64(decryptedPrivateKeyBytes);
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
        log("ID.cacheDecryptedPrivateKey", "Session private key cached");

    } catch (e) {
        warn("ID.cacheDecryptedPrivateKey", "Session caching failed (non-fatal):", e.message);
    }
}

export async function createRecoveryIdentity(pwd) {
    log("ID.createRecoveryIdentity", "called");

    // 1️⃣ Generate RSA keypair
    const keypair = await generateDeviceKeypair();

    // 2️⃣ Build recovery identity
    const recoveryIdentity = await buildIdentityFromKeypair(
        keypair,
        pwd,
        { type: "recovery", createdBy: getDeviceId() }
    );

    log("ID.createRecoveryIdentity", "Recovery identity built");

    // 3️⃣ Return identity (UI or envelope code will handle Drive writes)
    return recoveryIdentity;
}

// identity.js
export async function decryptPreviousKeys(id, pwd) {
    log("ID.decryptPreviousKeys", "called");

    id._decryptedPreviousKeys = [];

    if (!id.previousKeys?.length) return;

    for (const prev of id.previousKeys) {
        try {
            const derivedPrev = await CR.deriveKey(pwd, prev.kdf);
            const privateKeyPkcs8 = await CR.decrypt(prev.encryptedPrivateKey, derivedPrev);

            const privateKey = await crypto.subtle.importKey(
                "pkcs8",
                privateKeyPkcs8,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["unwrapKey"]
            );

            id._decryptedPreviousKeys.push({
                fingerprint: prev.fingerprint,
                privateKey
            });

            log("ID.decryptPreviousKeys", `Previous key ${prev.fingerprint} decrypted for session`);

        } catch {
            warn("ID.decryptPreviousKeys", `Failed to decrypt previous key ${prev.fingerprint}`);
        }
    }
}