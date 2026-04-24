import { C, G, LS, CR, GD, log, trace, debug, info, warn, error } from '@/shared/exports.js';

export function getDeviceId() {
    // If no email is loaded yet, we can't reliably get a scoped ID
    if (!G.userEmail) {
        const err = "CRITICAL: getDeviceId called before G.userEmail was established.";
        error("ID.getDeviceId", err);
        throw new Error(err);
    }

    let id = LS.get(C.DEVICE_ID_KEY);

    if (!id) {
        id = CR.generateUUID();
        LS.set(C.DEVICE_ID_KEY, id);
        log("ID.getDeviceId", `New unique device ID generated for ${G.userEmail}: ${id}`);
    }
    return id;
}

export async function createIdentity(pwd) {
    log("ID.createIdentity", "called - Generating new device identity key pair");

    const keypair = await _generateDeviceKeypair();
    const identity = await _buildIdentityFromKeypair(keypair, pwd);

    _saveIdentity(identity);

    // Use SAME Layer 1 initializer as unlock
    await cacheDecryptedPrivateKey(keypair.privateKeyPkcs8);

    // Mark identity as unlocked for this session
    G.unlockedIdentity = identity;

    log("ID.createIdentity", "New identity created and session unlocked");
}

export async function loadIdentity() {
    log("ID.loadIdentity", "called");
    trace("ID.loadIdentity", `G.sessionUnlocked: ${!!G.sessionUnlocked}, G.unlockedIdentity: ${!!G.unlockedIdentity}`);

    if (G.sessionUnlocked && G.unlockedIdentity) {
        log("ID.loadIdentity", "Returning G.unlockedIdentity from memory");
        return G.unlockedIdentity;
    }

    return _loadIdentityFromStorage();
}

export function removeDeviceIdentity() {
    if (LS.get(C.IDENTITY_KEY)) {
        warn("ID.removeDeviceIdentity", "Removing identity:", C.IDENTITY_KEY);
        LS.remove(C.DEVICE_ID_KEY);
    }
}

export async function migrateIdentityWithVerifier(id, pwd) {
    log("ID.migrateIdentityWithVerifier", "called - Migrating identity to add password verifier");

    const key = await CR.deriveKey(pwd, id.kdf);

    // Prove password correctness by decrypting private key
    await CR.decrypt(id.encryptedPrivateKey, key);

    // Create and attach verifier
    id.passwordVerifier = await _createPasswordVerifier(key);

    _saveIdentity(id);

    log("ID.migrateIdentityWithVerifier", "Identity auto-migrated with password verifier");
}

export async function verifyPasswordVerifier(verifier, key) {
    log("ID.verifyPasswordVerifier", "called");
    const buf = await CR.decrypt(verifier, key);
    const text = CR.decodeBuf(buf);
    if (text !== C.PASSWORD_VERIFIER_TEXT) {
        throw new Error("INVALID_PASSWORD");
    }
}

export async function rotateDeviceIdentity(pwd) {
    log("ID.rotateDeviceIdentity", "called - Rotating device identity key");

    const oldIdentity = await loadIdentity();
    if (!oldIdentity) {
        throw new Error("Cannot rotate — no existing identity");
    }

    const keypair = await _generateDeviceKeypair();

    const newIdentity = await _buildIdentityFromKeypair(keypair, pwd, {
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

    _saveIdentity(newIdentity);

    log("ID.rotateDeviceIdentity", "Device identity rotated");
    log("ID.rotateDeviceIdentity", `New KeyId: ${newIdentity.fingerprint} supersedes Old keyId: ${oldIdentity.fingerprint}`);

    // --- Drive updates (best effort) ---
    try {
        await GD.markPreviousDriveKeyDeprecated(oldIdentity.fingerprint, newIdentity.fingerprint); // updates old key JSON
        await SV.ensureDevicePublicKey();        // uploads NEW active key
        log("ID.rotateDeviceIdentity", "Drive key lifecycle updated");
    } catch (e) {
        warn("ID.rotateDeviceIdentity", "Drive update failed (local rotation preserved):", e.message);
    }
}

export async function cacheDecryptedPrivateKey(decryptedPrivateKeyBytes) {

    log("ID.cacheDecryptedPrivateKey", "called");
    try {
        if (!decryptedPrivateKeyBytes) throw new Error("No decrypted key available");

        const base64 = CR.bufToB64(decryptedPrivateKeyBytes);
        sessionStorage.setItem("sv_session_private_key", base64);

        // Keep in-memory reference for session restore
        G.currentPrivateKey = await CR.importRSAPrivateKey(decryptedPrivateKeyBytes);
        G.sessionUnlocked = true;
        log("ID.cacheDecryptedPrivateKey", "Session private key cached");

    } catch (e) {
        warn("ID.cacheDecryptedPrivateKey", "Session caching failed (non-fatal):", e.message);
    }
}

export async function createRecoveryIdentity(pwd) {
    log("ID.createRecoveryIdentity", "called");

    // 1️⃣ Generate RSA keypair
    const keypair = await _generateDeviceKeypair();

    // 2️⃣ Build recovery identity
    const recoveryIdentity = await _buildIdentityFromKeypair(
        keypair,
        pwd,
        { type: "recovery", createdBy: getDeviceId() }
    );

    log("ID.createRecoveryIdentity", "Recovery identity built");

    // 3️⃣ Return identity (UI or envelope code will handle Drive writes)
    return recoveryIdentity;
}

export async function decryptPreviousKeys(id, pwd) {
    log("ID.decryptPreviousKeys", "called");

    id._decryptedPreviousKeys = [];

    if (!id.previousKeys?.length) return;

    for (const prev of id.previousKeys) {
        try {
            const derivedPrev = await CR.deriveKey(pwd, prev.kdf);
            const privateKeyPkcs8 = await CR.decrypt(prev.encryptedPrivateKey, derivedPrev);
            const privateKey = await CR.importRSAPrivateKey(privateKeyPkcs8, ["unwrapKey"]);

            id._decryptedPreviousKeys.push({ fingerprint: prev.fingerprint, privateKey });
            log("ID.decryptPreviousKeys", `Previous key ${prev.fingerprint} decrypted for session`);

        } catch {
            warn("ID.decryptPreviousKeys", `Failed to decrypt previous key ${prev.fingerprint}`);
        }
    }
}

/** INTERNAL FUNCTIONS **/
function _saveIdentity(id) {
    LS.set(C.IDENTITY_KEY, JSON.stringify(id));
}

function _loadIdentityFromStorage() {
    log("ID._loadIdentityFromStorage", "called");

    const raw = LS.get(C.IDENTITY_KEY);
    log("ID._loadIdentityFromStorage", "Identity in localStorage exists:", !!raw);

    if (!raw) return null;

    try {
        const id = JSON.parse(raw);
        //trace("ID._loadIdentityFromStorage", "Identity loaded from localStorage:", JSON.stringify(id));
        if (G.sessionUnlocked && G.currentPrivateKey) {
            id._sessionPrivateKey = G.currentPrivateKey;
        }
        return id;
    } catch (e) {
        error("ID._loadIdentityFromStorage", "Failed to parse identity:", e);
        return null;
    }
}

async function _generateDeviceKeypair() {
    log("ID._generateDeviceKeypair", "called");

    const pair = await CR.generateRSAKeypair();
    const privateKeyPkcs8 = await CR.exportPrivateKey(pair.privateKey);
    const publicKeySpki = await CR.exportPublicKey(pair.publicKey);

    return { privateKeyPkcs8, publicKeySpki };
}

async function _buildIdentityFromKeypair({privateKeyPkcs8, publicKeySpki}, pwd, opts = {}) {
    log("ID._buildIdentityFromKeypair", "called");

    const pubB64 = CR.bufToB64(publicKeySpki);

    if (pubB64.length < 300) {
        throw new Error("Invalid RSA public key export");
    }

    const fingerprint = await CR.computePublicKeyFingerprint(publicKeySpki);

    const saltBytes = CR.randomBytes(CR.CR_ALG.SALT_LENGTH);
    const kdf = { salt: CR.bufToB64(saltBytes), iterations: CR.CR_ALG.PBKDF2_ITERATIONS };

    const key = await CR.deriveKey(pwd, kdf);
    const passwordVerifier = await _createPasswordVerifier(key);
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

async function _createPasswordVerifier(key) {
    log("ID._createPasswordVerifier", "called");
    return CR.encrypt(C.PASSWORD_VERIFIER_TEXT, key);
}
