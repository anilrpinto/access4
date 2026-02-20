"use strict";

import { C } from './constants.js';
import { G, clearGlobals } from './global.js';

import * as GD from './gdrive.js';
import * as ID from './identity.js';
import * as E from './envelope.js';
import * as UI from './ui.js';

import { log, trace, debug, info, warn, error, setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from './log.js';

function onLoad() {

    //setLogLevel(INFO);
    //onlyLogLevels(INFO, TRACE);
    log("[onLoad] called");
    UI.init();

    // Wire handlers
    UI.bindClick(UI.signinBtn, () => initGIS());
    UI.bindClick(UI.logoutBtn, () => logout());
    //UI.bindClick(UI.unlockBtn, handleUnlockClick);
    UI.bindClick(UI.saveBtn, handleSaveClick());

    log("[onLoad] sessionStorage sv_session_private_key exists:", !!sessionStorage.getItem("sv_session_private_key"));
    log("[onLoad] G.unlockedIdentity:", !!G.unlockedIdentity);
    log("[onLoad] G.currentPrivateKey:", !!G.currentPrivateKey);
}

function initGIS() {

    log("[initGIS] called");

    G.tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: C.CLIENT_ID,
        scope: C.SCOPES,
        callback: handleAuth
    });

    // Do not show consent promts
    G.tokenClient.requestAccessToken({ prompt:"" });

    // Show consent promts
    //G.tokenClient.requestAccessToken({ prompt:"consent select_account" });
}

/* --------- GOOGLE SIGN-IN end --------- */

async function handleAuth(resp) {
    log("[handleAuth] called");

    if (resp.error) return;

    G.accessToken = resp.access_token;
    log(`[handleAuth] Access token acquired ${G.accessToken}`);

    await GD.fetchUserEmail();
    await GD.verifySharedRoot(C.ACCESS4_ROOT_ID);
    await GD.verifyWritable(C.ACCESS4_ROOT_ID);
    await ensureAuthorization();

    if (!isSessionAuthenticated())
        UI.promptUnlockPasword();

    G.biometricRegistered = !!localStorage.getItem(bioCredKey());

    onAuthReady(G.userEmail);
}

async function onAuthReady(email) {
    log("[onAuthReady] called");
    UI.showAuthorizedEmail(email);

    try {
        const id = await ID.loadIdentity();

        if (!id) {
            // New device → create identity
            setAuthMode("create");
            log("[onAuthReady] New device detected, prompting password creation");
            return;
        }

        if (!id.passwordVerifier) {
            // Legacy identity → migration
            setAuthMode("unlock", { migration: true });
            log("[onAuthReady] Identity missing password verifier — migration mode");
            return;
        }

        // Attempt session restore first
        if (await attemptSessionRestore()) {
            log("[onAuthReady] Session restore successful — skipping password");

            log("[onAuthReady] G.driveLockState after session restore:" + (G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null));
            await ID.ensureDevicePublicKey();
            await proceedAfterPasswordSuccess();
            return;
        }

        // Returning user → unlock
        setAuthMode("unlock");
        log("[onAuthReady] Existing device detected, prompting unlock");

    } catch (e) {
        error("Error loading identity:", e.message);
        UI.showUnlockMessage("Failed to load identity. Try again.");
    }
}

function setAuthMode(mode, options = {}) {
    log("[setAuthMode] called");
    G.authMode = mode;

    // reset fields
    UI.resetUnlockUi();

    UI.setupPasswordPrompt(mode, options, async () => await proceedAfterPasswordSuccess());
}

function isSessionAuthenticated() {
    return !!sessionStorage.getItem("sv_session_private_key");
}

async function attemptSessionRestore() {
    log("[attemptSessionRestore] called");

    try {
        const stored = sessionStorage.getItem("sv_session_private_key");

        log("[attemptSessionRestore] sessionStorage private key exists:", !!stored);
        if (!stored) {
            warn("[attemptSessionRestore] No session private key found in sessionStorage");
            return false;
        }

        log("[attemptSessionRestore] Restoring session private key...");

        const bytes = Uint8Array.from(atob(stored), c => c.charCodeAt(0));

        G.currentPrivateKey = await crypto.subtle.importKey(
            "pkcs8",
            bytes,
            { name:"RSA-OAEP", hash:"SHA-256" },
            false,
            ["decrypt", "unwrapKey"]
        );

        // Load identity from localStorage
        const id = await ID.loadIdentity(); // gets raw identity
        log("[attemptSessionRestore] loadIdentity returned:", !!id);

        if (!id) {
            log("[attemptSessionRestore] Identity not found in localStorage despite private key");
            return false;
        }

        // ✅ Attach session key
        id._sessionPrivateKey = G.currentPrivateKey;

        // ✅ Store as unlocked identity for ID.loadIdentity()
        G.unlockedIdentity = id;

        G.sessionUnlocked = true;
        log("[attemptSessionRestore] Session restored from sessionStorage");

        log("[attemptSessionRestore] Session restore check...");
        log("[attemptSessionRestore] G.unlockedIdentity exists:", !!G.unlockedIdentity);
        log("[attemptSessionRestore] fingerprint:", G.unlockedIdentity?.fingerprint);
        log("[attemptSessionRestore] deviceId:", G.unlockedIdentity?.deviceId);
        log("[attemptSessionRestore] G.currentPrivateKey exists:", !!G.currentPrivateKey);
        log("[attemptSessionRestore] privateKey type:", G.currentPrivateKey?.type);
        log("[attemptSessionRestore] privateKey algorithm:", JSON.stringify(G.currentPrivateKey?.algorithm));

        return true;

    } catch (err) {
        warn("[attemptSessionRestore] Session restore failed, clearing");
        sessionStorage.removeItem("sv_session_private_key");
        return false;
    }
}

async function proceedAfterPasswordSuccess() {
    log("[proceedAfterPasswordSuccess] called");
    log("[proceedAfterPasswordSuccess] G.unlockedIdentity exists:", !!G.unlockedIdentity);
    log("[proceedAfterPasswordSuccess] G.currentPrivateKey exists:", !!G.currentPrivateKey);
    log("[proceedAfterPasswordSuccess] G.driveLockState:", G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null);

    await E.ensureEnvelope();      // 🔐 guarantees CEK + envelope
    await ensureRecoveryKey();   // 🔑 may block UI

    // ---- New housekeeping: wrap CEK for registry ----
    if (G.driveLockState?.self && G.driveLockState.envelopeName === "envelope.json") {
        log("[proceedAfterPasswordSuccess] Performing CEK housekeeping for all valid devices + recovery keys");
        await wrapCEKForRegistryKeys();  // helper handles load & write
    } else {
        warn("[proceedAfterPasswordSuccess] Skipping CEK housekeeping — G.driveLockState not ready or not writable");
    }

    await loadEnvelopePayloadToUI();

    // Show unlocked UI in read-only mode if no write lock
    const readOnly = !G.driveLockState?.self || G.driveLockState.mode !== "write";
    if (readOnly) {
        warn("[proceedAfterPasswordSuccess] Showing unlocked UI in read-only mode");
    }
    UI.showVaultUI({ readOnly, onIdle: (type) => logout() });

    log("[proceedAfterPasswordSuccess] Unlock successful!@");
}

async function releaseDriveLock() {
    log("[releaseDriveLock] called");

    if (!G.driveLockState?.fileId) return;

    G.driveLockState.heartbeat?.stop();

    const cleared = {
        ...G.driveLockState.lock,
        expiresAt: new Date(0).toISOString()
    };

    await GD.writeLockToDrive(
        G.driveLockState.envelopeName,
        cleared,
        G.driveLockState.fileId
    );

    log("[releaseDriveLock] Drive lock released");
    G.driveLockState = null;
}



async function generateContentKey() {
    log("[generateContentKey] called");

    return crypto.subtle.generateKey({
        name:"AES-GCM",
        length: 256
    },
        true,
        ["encrypt", "decrypt"]
    );
}

/* --- Encrypt Payload with CEK --- */
async function encryptPayload(plainText, cek) {
    log("[encryptPayload] called");

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);

    const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM", iv}, cek, encoded);

    return {
        iv: btoa(String.fromCharCode(...iv)),
        data: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
    };
}



async function ensureRecoveryKey() {
    log("[ensureRecoveryKey] called");

    if (await GD.hasRecoveryKeyOnDrive()) {
        info("[ensureRecoveryKey] Recovery key already present");
        return;
    }

    log("[ensureRecoveryKey] No recovery key found — blocking for recovery setup");
    await promptRecoverySetupUI();   // ← UI + user input
}

async function wrapCEKForRegistryKeys(forceWrite = false) {

    log("[wrapCEKForRegistryKeys] called");
    log("[wrapCEKForRegistryKeys] G.unlockedIdentity:", !!G.unlockedIdentity);
    log("[wrapCEKForRegistryKeys] G.currentPrivateKey:", !!G.currentPrivateKey);

    const envelopeName = "envelope.json";

    const envelopeFile = await GD.readEnvelopeFromDrive(envelopeName);
    if (!envelopeFile || !envelopeFile.json) {
        throw new Error("Envelope missing — cannot wrap CEK for registry");
    }

    const envelope = envelopeFile.json;

    log("[wrapCEKForRegistryKeys] envelope keys count:" + envelope?.keys?.length ?? 0);

    if (!envelope.keys || !envelope.payload) {
        throw new Error("Invalid envelope structure for CEK housekeeping");
    }

    const activeDevices = G.keyRegistry.flat.activeDevices;
    const recoveryKeys = G.keyRegistry.flat.recoveryKeys;

    log("[wrapCEKForRegistryKeys] Selecting device key entry...");
    log("[wrapCEKForRegistryKeys] G.userEmail:", G.userEmail);
    log("[wrapCEKForRegistryKeys] self.deviceId:", G.driveLockState?.self?.deviceId);

    // Unwrap CEK using any current device key
    const currentDeviceKeyEntry = envelope.keys.find(k =>
    k.account === G.userEmail &&
    k.deviceId === G.driveLockState.self.deviceId) || envelope.keys[0]; // Added temporary comment to debug refresh errors

    if (!currentDeviceKeyEntry) {
        throw new Error("No device key available to unwrap CEK");
    }

    log("[wrapCEKForRegistryKeys] Selected keyId for unwrap:", currentDeviceKeyEntry.keyId);
    log("[wrapCEKForRegistryKeys] Selected deviceId:", currentDeviceKeyEntry.deviceId);

    log("[wrapCEKForRegistryKeys] Attempting CEK unwrap");
    log("[wrapCEKForRegistryKeys] unwrap keyId:", currentDeviceKeyEntry.keyId);
    log("[wrapCEKForRegistryKeys] G.unlockedIdentity fingerprint:", G.unlockedIdentity?.fingerprint);
    log("[wrapCEKForRegistryKeys] G.currentPrivateKey exists:", !!G.currentPrivateKey);

    const cek = await unwrapContentKey(currentDeviceKeyEntry.wrappedKey, currentDeviceKeyEntry.keyId);
    let updated = false;

    // Wrap CEK for each active device not already present
    for (const device of activeDevices) {
        const existing = envelope.keys.find(k => k.keyId === device.fingerprint);
        if (!existing) {
            const wrappedKey = await wrapContentKeyForDevice(cek, device.publicKey.data);
            envelope.keys.push({
                role:"device",
                account: device.account,
                deviceId: device.deviceId,
                keyId: device.fingerprint,
                wrappedKey
            });
            log(`[wrapCEKForRegistryKeys] CEK wrapped for device ${device.deviceId}`);
            updated = true;
        } else if (forceWrite) {
            // Re-wrap CEK even if key exists
            existing.wrappedKey = await wrapContentKeyForDevice(cek, device.publicKey.data);
            log(`[wrapCEKForRegistryKeys] CEK re-wrapped for device ${device.deviceId} (forceWrite)`);
            updated = true;
        }
    }

    // Wrap CEK for recovery keys not already present
    for (const recovery of recoveryKeys) {
        const existing = envelope.keys.find(k => k.keyId === recovery.fingerprint);
        if (!existing) {
            const wrappedKey = await wrapContentKeyForDevice(cek, recovery.publicKey.data);
            envelope.keys.push({
                role:"recovery",
                keyId: recovery.fingerprint,
                wrappedKey
            });
            log(`[wrapCEKForRegistryKeys] CEK wrapped for recovery key ${recovery.fingerprint}`);
            updated = true;
        } else if (forceWrite) {
            existing.wrappedKey = await wrapContentKeyForDevice(cek, recovery.publicKey.data);
            log(`[wrapCEKForRegistryKeys] CEK re-wrapped for recovery key ${recovery.fingerprint} (forceWrite)`);
            updated = true;
        }
    }

    // Write back if updated OR forceWrite
    if (updated || forceWrite) {
        log("[wrapCEKForRegistryKeys] Envelope updated with wrapped keys — writing to Drive");
        await writeEnvelopeSafely(envelopeName, envelope);
    } else {
        log("[wrapCEKForRegistryKeys] Envelope up to date — skipping write");
    }

    return envelope;
}

/* ---Unwrap CEK Using Local Private Key (rotation-safe) --- */
async function unwrapContentKey(wrappedKeyBase64, keyId) {

    log("[unwrapContentKey] called");
    const id = await ID.loadIdentity();
    if (!id) throw new Error("Local identity missing");

    // Helper to unwrap with a given CryptoKey
    async function unwrapWithKey(privateKey) {
        const wrappedBytes = Uint8Array.from(atob(wrappedKeyBase64), c => c.charCodeAt(0));
        return crypto.subtle.unwrapKey(
            "raw",
            wrappedBytes,
            privateKey,
            { name:"RSA-OAEP" },
            { name:"AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // 1️⃣ Try current in-memory private key if keyId matches
    if (G.currentPrivateKey && keyId === id.fingerprint) {
        log(`[unwrapContentKey] Using G.currentPrivateKey for keyId ${keyId}`);
        return unwrapWithKey(G.currentPrivateKey);
    }

    // 2️⃣ Try previous keys
    if (id.previousKeys?.length) {
        const prev = id.previousKeys.find(k => k.fingerprint === keyId);
        if (prev) {
            if (!G.unlockedPassword) throw new Error("Identity not unlocked for previous key");

            log(`[unwrapContentKey] Using previous key for keyId ${keyId}`);
            const derivedKey = await deriveKey(G.unlockedPassword, prev.kdf);
            const privateKeyPkcs8 = await decrypt(prev.encryptedPrivateKey, derivedKey);
            const privateKey = await crypto.subtle.importKey(
                "pkcs8",
                privateKeyPkcs8,
                { name:"RSA-OAEP", hash:"SHA-256" },
                false,
                ["unwrapKey"]
            );
            return unwrapWithKey(privateKey);
        }
    }

    // 3️⃣ Fallback: use G.currentPrivateKey even if fingerprint mismatch
    if (G.currentPrivateKey) {
        log(`[unwrapContentKey] Fallback: using G.currentPrivateKey despite fingerprint mismatch for keyId ${keyId}`);
        return unwrapWithKey(G.currentPrivateKey);
    }

    // 4️⃣ Nothing found
    error(`[unwrapContentKey] No private key available for keyId ${keyId}`);
    throw new Error("No private key available for keyId:" + keyId);
}



/* --- Wrap CEK for a Device Public Key --- */
async function wrapContentKeyForDevice(cek, devicePublicKeyBase64) {
    const pubKeyBytes = Uint8Array.from(atob(devicePublicKeyBase64), c => c.charCodeAt(0));

    const publicKey = await crypto.subtle.importKey(
        "spki",
        pubKeyBytes, {
            name:"RSA-OAEP",
            hash:"SHA-256"
        },
        false,
        ["wrapKey"]
    );

    const wrapped = await crypto.subtle.wrapKey(
        "raw",
        cek,
        publicKey, {
            name:"RSA-OAEP"
        }
    );

    return btoa(String.fromCharCode(...new Uint8Array(wrapped)));
}

async function writeEnvelopeSafely(envelopeName, envelopeData, maxRetries = 3, retryDelayMs = 1000) {
    let attempt = 0;

    while (attempt < maxRetries) {
        attempt++;

        // Ensure we hold the lock
        if (!G.driveLockState || G.driveLockState.envelopeName !== envelopeName) {
            log(`🔒 Attempting to acquire lock for "${envelopeName}" (attempt ${attempt})`);
            try {
                await E.acquireDriveWriteLock(() => UI.updateLockStatusUI());
            } catch (err) {
                log(`⚠️ Lock acquisition failed: ${err.message}`);
                await new Promise(r => setTimeout(r, retryDelayMs));
                continue;
            }
        }

        await assertEnvelopeWrite(envelopeName);

        try {
            const result = await writeEnvelopeWithLock(envelopeName, envelopeData);
            return result;
        } catch (err) {
            log(`⚠️ Write attempt failed: ${err.message}`);
            // If lock was lost mid-write, retry
            await new Promise(r => setTimeout(r, retryDelayMs));
        }
    }

    throw new Error(`Failed to write envelope "${envelopeName}" after ${maxRetries} attempts`);
}

async function loadEnvelopePayloadToUI(envelopeName = "envelope.json") {
    log(`[loadEnvelopePayloadToUI] Loading envelope payload from Drive: ${envelopeName}`);

    // 1️⃣ Read envelope file
    const envelopeFile = await GD.readEnvelopeFromDrive(envelopeName);
    if (!envelopeFile) {
        warn("️[loadEnvelopePayloadToUI] Envelope file not found");
        return;
    }

    const envelope = envelopeFile.json;

    if (!envelope.payload) {
        log("️[loadEnvelopePayloadToUI] Envelope has no payload");
        return;
    }

    try {
        // 2️⃣ Decrypt payload using openEnvelope()
        const plaintext = await openEnvelope(envelope);

        log(`[loadEnvelopePayloadToUI] plaintext: |${plaintext}|`);

        // 3️⃣ Populate plaintext area in UI
        plaintextInput.value = plaintext;

        log("[loadEnvelopePayloadToUI] Payload loaded into plaintext UI");
    } catch (err) {
        error("[loadEnvelopePayloadToUI] Failed to decrypt envelope payload:", err.message);
    }
}

async function openEnvelope(envelope) {

    log("[openEnvelope] called");

    validateEnvelope(envelope);

    const entry = await selectDecryptableKey(envelope);

    log(`[openEnvelope] Using keyId: ${entry.keyId}`);

    const cek = await unwrapContentKey(
        entry.wrappedKey,
        entry.keyId
    );

    const iv = Uint8Array.from(atob(envelope.payload.iv), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob(envelope.payload.data), c => c.charCodeAt(0));

    const decrypted = await crypto.subtle.decrypt(
        { name:"AES-GCM", iv },
        cek,
        data
    );

    return new TextDecoder().decode(decrypted);
}

function validateEnvelope(envelope) {
    if (!envelope.version) {
        throw new Error("Envelope missing version");
    }

    if (!Array.isArray(envelope.keys) || envelope.keys.length === 0) {
        throw new Error("Envelope has no key entries");
    }

    let hasUsableKey = false;

    for (const k of envelope.keys) {
        // wrapped CEK is always required
        if (!k.wrappedKey) {
            throw new Error("Key entry missing wrappedKey");
        }

        // keyId is REQUIRED for rotation safety (all key types)
        if (!k.keyId) {
            throw new Error("Key entry missing keyId (rotation unsafe)");
        }

        // Type-aware validation
        if (k.role === "device") {
            if (!k.deviceId) {
                throw new Error("Device key entry missing deviceId");
            }
            hasUsableKey = true;
        } else if (k.role === "recovery") {
            // recovery entries intentionally do NOT have deviceId
            // optional: validate recoveryId / method if you want
            hasUsableKey = true;
        } else {
            throw new Error(`Unknown key entry role: ${k.role || "missing"}`);
        }
    }

    if (!hasUsableKey) {
        throw new Error("Envelope contains no usable key entries");
    }
}

async function selectDecryptableKey(envelope) {

    const id = await ID.loadIdentity();
    if (!id) throw new Error("Local identity missing");

    if (!Array.isArray(envelope.keys)) {
        throw new Error("Envelope missing keys array");
    }

    // 1️⃣ Prefer current device key (rotation-aware)
    const deviceEntry = envelope.keys.find(k => {
        if (k.role !== "device") return false;
        if (!k.deviceId) return false;
        if (k.deviceId !== id.deviceId) return false;

        // Allow current or superseded key
        return keyMatchesOrIsSuperseded(k.keyId, id);
    });

    if (deviceEntry) {
        if (deviceEntry.keyId !== id.fingerprint) {
            log("🔁 Envelope encrypted with previous device key — rotation detected");
        }
        return deviceEntry;
    }

    // 2️⃣ Optional fallback: recovery key (NO deviceId expected)
    const recoveryEntry = envelope.keys.find(k => k.role === "recovery");

    if (recoveryEntry) {
        log("🛟 Falling back to recovery key for decryption");
        return recoveryEntry;
    }

    throw new Error("No decryptable key found for this device or recovery");
}

function keyMatchesOrIsSuperseded(entryKeyId, localIdentity) {
    if (!localIdentity?.fingerprint) return false;
    // Exact match (current key)
    if (entryKeyId === localIdentity.fingerprint) return true;
    // Superseded key (previous rotation)
    if (localIdentity.previousKeys?.some(k => k.fingerprint === entryKeyId)) return true;
    return false;
}

/*function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}*/

/* ================= AUTH ================= */
async function ensureAuthorization() {
    const q = `'${C.ACCESS4_ROOT_ID}' in parents and name='${C.AUTH_FILE_NAME}'`;
    const res = await GD.driveFetch(GD.buildDriveUrl("files", { q, fields:"files(id)" }));
    
    if (!res.files.length) {
        log("? authorized.json not found, creating genesis authorization...");
        await createGenesisAuthorization();
        return;
    }
    const data = await GD.driveFetch(GD.buildDriveUrl(`files/${res.files[0].id}`, {
        alt:"media"
    }));
    if (!data.admins.includes(G.userEmail) && !data.members.includes(G.userEmail))
    throw new Error("Unauthorized user");
    log("? Authorized user verified");
}

async function createGenesisAuthorization() {
    const file = await GD.driveFetch(GD.buildDriveUrl("files"), {
        method:"POST",
        headers: {
            "Content-Type":"application/json"
        },
        body: JSON.stringify({
            name: C.AUTH_FILE_NAME,
            parents: [C.ACCESS4_ROOT_ID]
        })
    });
    await GD.driveFetch(GD.buildDriveUrl(`files/${file.id}`, {
        uploadType:"media"
    }), {
        method:"PATCH",
        headers: {
            "Content-Type":"application/json"
        },
        body: JSON.stringify({
            admins: [G.userEmail],
            members: [G.userEmail],
            created: new Date().toISOString(),
            version: 1
        })
    });
    log(`? Genesis authorization created for ${G.userEmail}`);
}

async function encryptPrivateKeyWithPassword(privateKey, password) {
    // 1️⃣ Export private key (raw)
    const rawPrivate = await crypto.subtle.exportKey("raw", privateKey);

    // 2️⃣ Derive AES key from password
    const kdf = {
        salt: crypto.getRandomValues(new Uint8Array(16)),
        iterations: 200_000,
        hash:"SHA-256"
    };

    const aesKey = await deriveKey(password, kdf);

    // 3️⃣ Encrypt
    const encrypted = await encrypt(rawPrivate, aesKey);

    // 4️⃣ Package
    return {
        version: 1,
        kdf,
        cipher:"AES-256-GCM",
        encrypted
    };
}

/* ================= BIOMETRIC ================= */
function bioCredKey() {
    return `access4.bio.cred::${G.userEmail}::${ID.getDeviceId()}`;
}

function bioPwdKey() {
    return `access4.bio.pwd::${G.userEmail}::${ID.getDeviceId()}`;
}

async function biometricAuthenticateFromGesture() {
    if (!window.PublicKeyCredential) {
        log("⚠️ Biometric not supported on this browser");
        return;
    }

    const rawId = localStorage.getItem(bioCredKey());
    const storedPwd = localStorage.getItem(bioPwdKey());
    if (!rawId || !storedPwd) {
        log("⚠️ No biometric credential stored");
        return;
    }

    try {
        log("👆 Triggering biometric prompt...");
        await navigator.credentials.get({
            publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                allowCredentials: [{
                    type:"public-key",
                    id: Uint8Array.from(atob(rawId), c => c.charCodeAt(0))
                }],
                userVerification:"required"
            }
        });
        log("✅ Biometric authentication prompt completed successfully");
        log("🔓 Using stored password to unlock identity...");
        await unlockIdentityFlow(atob(storedPwd));
    } catch (e) {
        log("⚠️ Biometric prompt failed or canceled:" + e.message);
    }
}

/* ================= HIDDEN GESTURE ================= */


/* ================= STEP 4.1: DEVICE PUBLIC KEY ================= */
async function hasRecoveryKey() {
    // TEMP: replace with Drive check later
    const marker = localStorage.getItem("recoveryKeyPresent");
    return !!marker;
}

/* ================= ENVELOPE WRITE ASSERTION + HOUSEKEEPING HELPER ================= */
async function assertEnvelopeWrite(envelopeName) {

    if (!G.driveLockState) {
        throw new Error(`Cannot write: no drive lock state for "${envelopeName}"`);
    }

    if (G.driveLockState.envelopeName !== envelopeName) {
        throw new Error(`Cannot write: lock does not match envelope "${envelopeName}"`);
    }

    if (G.driveLockState.mode !== "write") {
        throw new Error(`Read-only session — write not permitted for envelope "${envelopeName}"`);
    }

    log(`[assertEnvelopeWrite] Ownership confirmed for envelope "${envelopeName}"`);

    // Future housekeeping hook: missing device/recovery keys
    // log(`[housekeeping] Envelope ownership confirmed for "${envelopeName}"`);
}

/*function finalizeKeyRegistry(registry) {
    Object.freeze(registry.flat.activeDevices);
    Object.freeze(registry.flat.deprecatedDevices);
    Object.freeze(registry.flat.recoveryKeys);
    Object.freeze(registry.flat);
    Object.freeze(registry.accounts);
    Object.freeze(registry);
}*/

async function addRecoveryKeyToEnvelope({ publicKey, keyId }) {
    log("[addRecoveryKeyToEnvelope] called - Adding recovery key to envelope...");

    const envelopeName = "envelope.json";

    // 1️⃣ Load existing envelope from Drive
    const envelopeFile = await GD.readEnvelopeFromDrive(envelopeName);
    if (!envelopeFile) {
        throw new Error("Envelope missing — cannot add recovery key");
    }

    await assertEnvelopeWrite(envelopeName);

    const envelope = envelopeFile.json;

    // 2️⃣ Check if recovery key already exists
    if (envelope.keys?.some(k => k.role === "recovery" && k.keyId === keyId)) {
        warn("[addRecoveryKeyToEnvelope] Recovery key already present in envelope, skipping add");
    } else {
        // 3️⃣ Unwrap CEK using the first active device key
        log("[addRecoveryKeyToEnvelope] Unwrapping CEK with active device key...");
        const cek = await unwrapContentKey(
            envelope.keys[0].wrappedKey,
            envelope.keys[0].keyId
        );
        log("[addRecoveryKeyToEnvelope] CEK unwrapped");

        // 4️⃣ Wrap CEK for the new recovery key
        log("[addRecoveryKeyToEnvelope] Wrapping CEK for recovery key...");
        let wrappedKey;
        try {
            wrappedKey = await wrapContentKeyForDevice(cek, publicKey);
            log("[addRecoveryKeyToEnvelope] CEK wrapped for recovery key");
        } catch (err) {
            error("[addRecoveryKeyToEnvelope] Error wrapping CEK:", err);
            throw err;
        }

        // 5️⃣ Add recovery key to envelope
        envelope.keys.push({
            role:"recovery",
            keyId,
            wrappedKey
        });

        log("[addRecoveryKeyToEnvelope] Added recovery key to envelope.keys:" + envelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));
    }

    // ---- Housekeeping CEK wrap for all devices & recovery keys (force write) ----
    if (G.driveLockState?.self && G.driveLockState.envelopeName === envelopeName) {
        log("[addRecoveryKeyToEnvelope] Performing CEK housekeeping with force write");
        const updatedEnvelope = await wrapCEKForRegistryKeys(true); // <- forceWrite = true

        log("[addRecoveryKeyToEnvelope] Updated envelope after wrapCEKForRegistryKeys:" + updatedEnvelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));

        // 6️⃣ Write updated envelope safely
        await writeEnvelopeSafely(envelopeName, updatedEnvelope);
    }

    log("[addRecoveryKeyToEnvelope] Recovery key added to envelope and saved");
}

/*-------------- Drive lock file io helpers recently added after baseline  ------------------------*/


/* ================= LOGOUT ================= */
function logout() {
    log("[logout] Logging out...");

    releaseDriveLock();

    // 1️⃣ Release Drive lock if held
    E.handleDriveLockLost(); // stops heartbeat & clears local G.driveLockState

    // 2️⃣ Clear user-specific memory
    //G.accessToken = null;
    //G.userEmail = null;
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");
    UI.resetUnlockUi();

    // 4️⃣ Clear biometric data (optional)
    localStorage.removeItem(bioCredKey());
    localStorage.removeItem(bioPwdKey());
    G.biometricRegistered = false;
    G.biometricIntent = false;

    log("[logout] completed");
}

/* ----------------- UI action handlers -------------------*/

async function handleCreateRecoveryClick() {
    log("[handleCreateRecoveryClick] called - Starting recovery key creation");

    const pwd = passwordInput.value;
    const confirm = confirmPasswordInput.value;

    if (!pwd || pwd.length < 7) {
        throw new Error("Recovery password must be at least 7 characters.");
    }
    if (pwd !== confirm) {
        throw new Error("Recovery passwords do not match.");
    }

    unlockBtn.disabled = true;
    UI.showUnlockMessage("Creating recovery key…");

    // 1️⃣ Generate RSA keypair (same as device)
    const keypair = await crypto.subtle.generateKey(
        {
            name:"RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash:"SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
    log("[handleCreateRecoveryClick] Recovery keypair generated");

    // 2️⃣ Export keys
    const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", keypair.privateKey);
    const publicKeySpki = await crypto.subtle.exportKey("spki", keypair.publicKey);
    log("[handleCreateRecoveryClick] Recovery keys exported");

    // 3️⃣ Build recovery identity
    const recoveryIdentity = await buildIdentityFromKeypair(
        { privateKeyPkcs8, publicKeySpki },
        pwd,
        { type:"recovery", createdBy: ID.getDeviceId() }
    );
    log("[handleCreateRecoveryClick] Private key encrypted with recovery password");

    // 4️⃣ Ensure recovery folder
    const recoveryFolderId = await GD.ensureRecoveryFolder();

    // 5️⃣ Write private recovery file
    await GD.driveCreateJsonFile({ name:"recovery.private.json", parents: [recoveryFolderId], json: recoveryIdentity });
    log("[handleCreateRecoveryClick] recovery.private.json written");

    // 6️⃣ Write public recovery file (matching device key structure)
    const recoveryPublicJson = {
        type:"recovery",
        role:"recovery",
        keyId: recoveryIdentity.fingerprint,
        fingerprint: recoveryIdentity.fingerprint,
        created: recoveryIdentity.created,
        algorithm: {
            name:"RSA-OAEP",
            modulusLength: 2048,
            hash:"SHA-256",
            usage: ["encrypt"]
        },
        publicKey: {
            format:"spki",
            encoding:"base64",
            data: btoa(String.fromCharCode(...new Uint8Array(publicKeySpki)))
        }
    };

    await GD.driveCreateJsonFile({
        name:"recovery.public.json",
        parents: [recoveryFolderId],
        json: recoveryPublicJson
    });
    log("[handleCreateRecoveryClick] recovery.public.json written");

    // 7️⃣ Add to envelope for CEK housekeeping
    await addRecoveryKeyToEnvelope({
        publicKey: publicKeySpki,
        keyId: recoveryIdentity.fingerprint
    });

    log("[handleCreateRecoveryClick] Recovery key successfully established");
    UI.showUnlockMessage("Recovery key created!", "unlock-message success");
    unlockBtn.disabled = false;
}

async function handleSaveClick() {
    const text = plaintextInput.value;
    if (!text) {
        log("⚠️ Nothing to encrypt");
        return;
    }

    try {
        await encryptAndPersistPlaintext(text);
        plaintextInput.value = "";
    } catch (e) {
        error("Encryption failed:" + e.message);
    }
}

async function encryptAndPersistPlaintext(plainText) {
    const envelopeName = "envelope.json";

    // Ensure we own the lock
    if (!G.driveLockState || G.driveLockState.envelopeName !== envelopeName) {
        await E.acquireDriveWriteLock(() => UI.updateLockStatusUI());
    }

    await assertEnvelopeWrite(envelopeName);

    // Load envelope
    const envelopeFile = await GD.readEnvelopeFromDrive(envelopeName);
    if (!envelopeFile?.json) {
        throw new Error("Envelope missing");
    }

    const envelope = envelopeFile.json;

    log("[encryptAndPersistPlaintext] envelope:" + envelope)

    // Unwrap CEK using this device
    const selfEntry = envelope.keys.find(k =>
    k.deviceId === G.driveLockState.self.deviceId
    );

    if (!selfEntry) {
        throw new Error("No device key to unwrap CEK");
    }

    const cek = await unwrapContentKey(
        selfEntry.wrappedKey,
        selfEntry.keyId
    );

    log('cek: ${JSON.stringify(cek)}');

    // Encrypt new payload
    const payload = await encryptPayload(plainText, cek);

    // Update envelope payload only
    const updatedEnvelope = {
        ...envelope,
        payload
    };

    // Persist safely (generation + lock heartbeat preserved)
    const written = await writeEnvelopeSafely(envelopeName, updatedEnvelope);

    log("🔒 Payload encrypted & written to envelope");

    // Verify decrypt immediately (sanity + demo)
    const decrypted = await openEnvelope(written);
    log("🔓 Decrypted payload:");
    log(decrypted);
}

function isEnvelopeReadOnly() {
    return !G.driveLockState || G.driveLockState.mode !== "write";
}


// Button to invoke it doens't exist in the latest ui, add to enable (for testing biometric behavior)
function handleResetBiometricClick() {
    localStorage.removeItem(bioCredKey());
    localStorage.removeItem(bioPwdKey());
    G.biometricRegistered = false;
    G.biometricIntent = false;
    log("⚠️ Biometric registration cleared for testing");
};

/* ---------- TEMPORARY ---------*/


/*-------- TEMPORARY ENDS -------*/

// IMPORTANT - DO NOT DELETE
window.onload = async () => {
    await onLoad();
    //await initGIS();

    // Clear any lingering G.driveLockState in memory
    //G.driveLockState = null;
    clearGlobals();
    UI.resetUnlockUi();

    // Optional: detect if a user was partially logged in
    // If you want logout to be final, skip restoring user session
    // Otherwise, you could try reacquiring the lock here
};
