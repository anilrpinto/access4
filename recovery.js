"use strict";

import { C } from './constants.js';
import { G } from './global.js';

import * as CR from './crypto.js';
import * as GD from './gdrive.js';

import { log, trace, debug, info, warn, error } from './log.js';
import { VERIFIER_TEXT } from './identity.js';

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

export async function unlockRecoveryIdentity(pwd) {

    log("R.unlockRecoveryIdentity", "called");

    try {
        // 1️⃣ Load recovery.private.json
        const blob = await GD.loadRecoveryPrivateBlob();

        // 2️⃣ Derive AES key
        const aesKey = await CR.deriveKey(pwd, blob.kdf);

        // 3️⃣ Verify password
        const verifierBytes = new Uint8Array(
            await CR.decrypt(blob.passwordVerifier, aesKey)
        );

        const expected = new TextEncoder().encode(VERIFIER_TEXT);

        if (!constantTimeEqual(verifierBytes, expected)) {
            throw new Error("Invalid recovery password");
        }

        // 4️⃣ Decrypt PKCS8
        const pkcs8Bytes = await CR.decrypt(
            blob.encryptedPrivateKey,
            aesKey
        );

        // 5️⃣ Import RSA private key
        const privateKey = await crypto.subtle.importKey(
            "pkcs8",
            pkcs8Bytes,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );

        // 6️⃣ Verify fingerprint integrity
        const publicKeySpki = Uint8Array.from(
            atob(blob.publicKey),
            c => c.charCodeAt(0)
        );

        const computedFingerprint =
        await CR.computePublicKeyFingerprint(publicKeySpki);

        if (computedFingerprint !== blob.fingerprint) {
            throw new Error("Recovery key integrity check failed");
        }

        log("R.unlockRecoveryIdentity", "Recovery identity unlocked successfully");

        return {
            privateKey,
            fingerprint: blob.fingerprint,
            type: "recovery"
        };

    } catch (err) {
        error("R.unlockRecoveryIdentity", err.message);
        throw err;
    }
}

async function importRecoveryPrivateKey(pkcs8Bytes) {
    return await crypto.subtle.importKey(
        "pkcs8",
        pkcs8Bytes,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        false,
        ["unwrapKey"]
    );
}

async function unwrapCEKWithRecoveryKey(envelope, recoveryPrivateKey) {
    const entry = envelope.keys.find(k => k.role === "recovery");
    if (!entry) {
        throw new Error("No recovery key entry in envelope.");
    }

    const wrappedBytes = CR.b64ToBuf(entry.wrappedKey);

    return await crypto.subtle.unwrapKey(
        "raw",
        wrappedBytes,
        recoveryPrivateKey,
        {
            name: "RSA-OAEP"
        },
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function restoreFromRecovery(password) {
    log("[restoreFromRecovery] starting");

    // 1️⃣ Unlock recovery private key
    const pkcs8 = await unlockRecoveryIdentity(password);
    if (!pkcs8) throw new Error("Recovery password invalid.");

    const recoveryPrivateKey = await importRecoveryPrivateKey(pkcs8);

    // 2️⃣ Load envelope
    const envelopeFile = await GD.findEnvelopeFile();
    if (!envelopeFile) throw new Error("Envelope not found.");

    const envelope = await GD.readEnvelope(envelopeFile.id);

    // 3️⃣ Unwrap CEK
    const contentKey = await unwrapCEKWithRecoveryKey(
        envelope,
        recoveryPrivateKey
    );

    log("[restoreFromRecovery] CEK unwrapped successfully");

    // 4️⃣ Create new device identity (LOCAL FIRST)
    const newIdentity = await createIdentity(password);
    // createIdentity already:
    // - generates RSA pair
    // - encrypts private key
    // - stores in localStorage
    // - uploads public key to Drive

    log("[restoreFromRecovery] new device identity created");

    // 5️⃣ Import new device public key
    const devicePublicKey = await crypto.subtle.importKey(
        "spki",
        CR.b64ToBuf(newIdentity.publicKey),
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        false,
        ["wrapKey"]
    );

    // 6️⃣ Wrap CEK for new device
    const wrapped = await crypto.subtle.wrapKey(
        "raw",
        contentKey,
        devicePublicKey,
        { name: "RSA-OAEP" }
    );

    const wrappedB64 = CR.bufToB64(wrapped);

    envelope.keys.push({
        role: "device",
        account: newIdentity.account,
        deviceId: newIdentity.deviceId,
        keyId: newIdentity.keyId,
        wrappedKey: wrappedB64,
        publicKeyCreated: newIdentity.publicKeyCreated
    });

    log("[restoreFromRecovery] CEK wrapped for new device");

    // 7️⃣ Write envelope
    await GD.writeEnvelopeWithLock(envelopeFile.id, envelope);

    log("[restoreFromRecovery] envelope updated");

    await UI.unlockIdentityFlow(password);

    G.unlockedIdentity = newIdentity;
    G.sessionUnlocked = true;

    log("[restoreFromRecovery] complete");

    return true;
}

export async function handleRecovery(pwd, onCEKSuccessCb) {

    log("R.handleRecovery", "called");

    // 1️⃣ Load recovery private key from Drive
    const recoveryBlob = await GD.loadRecoveryPrivateBlob();

    // 2️⃣ Decrypt recovery private key with user-supplied password
    const recoveryKey = await CR.deriveKey(pwd, recoveryBlob.kdf);

    let recoveryPrivateKeyBytes;

    // 3️⃣ Decrypt recovery private key
    try {
        recoveryPrivateKeyBytes = await CR.decrypt(recoveryBlob.encryptedPrivateKey, recoveryKey);
    } catch(e) {
        throw new Error("Incorrect recovery password or corrupted recovery key");
    }

    // Import decrypted private key into crypto subtle
    const recoveryPrivateKey = await crypto.subtle.importKey(
        "pkcs8",
        recoveryPrivateKeyBytes,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["unwrapKey"]
    );

    log("R.handleRecovery", "Recovery private key decrypted");

    // 4️⃣ Load vault envelope (grab CEK)
    const envelopeFile = await GD.readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile) throw new Error("Vault envelope not found");

    const envelope = envelopeFile.json; // <--- your missing line
    log("R.handleRecovery", "Vault envelope loaded");

    // 5️⃣ Find the CEK wrapped for recovery identity
    const wrappedCEK = envelope.keys.find(k => k.role === "recovery")?.wrappedKey;
    if (!wrappedCEK) throw new Error("Vault CEK not wrapped for recovery");

    // 3️⃣ Attempt to unwrap CEK using recovery private key
    const cek = await CR.unwrapCEKWithPrivateKey(wrappedCEK, recoveryPrivateKey);

    if (!cek) throw new Error("CEK unwrap failed — invalid recovery password or vault corrupted");

    G.recoverySession = true;
    G.recoveryCEK = cek;

    log("R.handleRecovery", `Vault CEK unwrapped successfully - G.recoverySession: ${G.recoverySession}, G.recoveryCEK: ${G.recoveryCEK}`);

    if (onCEKSuccessCb)
        await onCEKSuccessCb();
}

export async function ensureRecoveryKey(setupRecoveryCb) {
    log("R.ensureRecoveryKey", "called");

    if (await hasRecoveryKeyOnDrive()) {
        info("R.ensureRecoveryKey", "Recovery key already present");
        return;
    }

    log("R.ensureRecoveryKey", "No recovery key found — blocking for recovery setup");
    if (setupRecoveryCb)
        await setupRecoveryCb();
}

async function hasRecoveryKeyOnDrive() {
    log("R.hasRecoveryKeyOnDrive", "called");

    try {
        const folders = await GD.driveList({
            q: `'${C.ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`,
            pageSize: 1
        });

        log("R.hasRecoveryKeyOnDrive", "recovery folders found:", folders?.length);

        if (!folders.length) return false;

        const recoveryFolderId = folders[0].id;

        const files = await GD.driveList({
            q: `'${recoveryFolderId}' in parents and name='recovery.public.json'`,
            pageSize: 1
        });

        return files.length === 1;

    } catch (e) {
        error("R.hasRecoveryKeyOnDrive", "Recovery key check failed:", e.message);
        throw e; // mandatory block
    }
}