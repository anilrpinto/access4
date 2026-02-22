"use strict";

import { C } from './constants.js';
import { G } from './global.js';

import * as CR from './crypto.js';
import * as ID from './identity.js';
import * as GD from './gdrive.js';
import * as UI from './ui.js';

import { log, trace, debug, info, warn, error } from './log.js';

export async function ensureEnvelope() {
    log("[E.ensureEnvelope] called");
    const envelopeName = "envelope.json";

    // ─── Fast path: skip lock re-acquire if already initialized ───
    if (G.driveLockState && G.driveLockState.mode) {
        log("[E.ensureEnvelope] Drive lock already initialized — skipping lock acquisition");
        log("[E.ensureEnvelope] G.driveLockState:", JSON.stringify(G.driveLockState));
    } else {
        const lockFile = await GD.readLockFromDrive(envelopeName);
        const { identity, self } = await getDriveLockSelf();
        const evalResult = evaluateEnvelopeLock(lockFile?.json, self);

        if (evalResult.status === "owned") {
            G.driveLockState = { envelopeName, fileId: lockFile?.fileId, lock: lockFile?.json, self, mode:"write" };
        } else if (evalResult.status === "locked") {
            log("[E.ensureEnvelope] Envelope locked by another device — entering read-only mode");
            G.driveLockState = { envelopeName, fileId: lockFile.fileId, lock: lockFile.json, self, mode:"read" };
        } else {
            await acquireDriveWriteLock(envelopeName);
        }
    }

    log("[E.ensureEnvelope] Drive mode:", G.driveLockState.mode);
    log("[E.ensureEnvelope] Drive self deviceId:", G.driveLockState.self.deviceId);

    // ─── Load key registry from pub-keys on Drive ───
    const rawPublicKeyJsons = await GD.loadPublicKeyJsonsFromDrive();
    G.keyRegistry = await buildKeyRegistryFromDrive(rawPublicKeyJsons);

    log("[E.ensureEnvelope] Active devices registry:", G.keyRegistry.flat.activeDevices.length);
    log("[E.ensureEnvelope] recoveryKeys registry:", G.keyRegistry.flat.recoveryKeys.length);

    // ─── Fast path: load existing envelope ───
    const existing = await GD.readEnvelopeFromDrive(envelopeName);
    if (existing?.json) {
        log("[E.ensureEnvelope] Envelope already exists");
        return existing.json;
    }

    // ─── Genesis envelope path ───
    log("[E.ensureEnvelope] Envelope missing — creating genesis envelope");
    const { identity } = await getDriveLockSelf();
    const selfKey = G.keyRegistry.flat.activeDevices.find(k => k.deviceId === identity.deviceId);
    if (!selfKey) throw new Error("Active device public key not found for envelope genesis");

    const envelope = await createEnvelope(JSON.stringify({ initialized: true }), selfKey);
    return await writeEnvelopeWithLock(envelopeName, envelope);
}

async function buildKeyRegistryFromDrive(rawPublicKeyJsons) {
    log("[E.buildKeyRegistryFromDrive] called");

    resetKeyRegistry();

    for (const raw of rawPublicKeyJsons) {
        const normalized = normalizePublicKey(raw);
        if (!normalized) continue; // skip invalid
        registerPublicKey(normalized);
    }

    G.keyRegistry.loadedAt = new Date().toISOString();

    // Validate structural integrity
    try {
        validateKeyRegistry(G.keyRegistry);
    } catch (e) {
        warn("[E.buildKeyRegistryFromDrive] Key registry validation warning:", e.message);
    }

    // Resolve terminal active devices
    const activeDevices = resolveEffectiveActiveDevices(G.keyRegistry.flat);

    // 🔒 Freeze resolved device lists
    G.keyRegistry.flat.activeDevices = Object.freeze(
        activeDevices.map(d => Object.freeze(d))
    );

    G.keyRegistry.flat.deprecatedDevices = Object.freeze(
        G.keyRegistry.flat.deprecatedDevices.map(d => Object.freeze(d))
    );

    // 🔒 Freeze flat view
    Object.freeze(G.keyRegistry.flat);

    // 🔒 Freeze entire registry
    Object.freeze(G.keyRegistry);

    return G.keyRegistry;
}

function normalizePublicKey(raw) {

    if (!raw || typeof raw !== "object") {
        throw new Error("Invalid public key JSON");
    }

    if (!raw.keyId || !raw.fingerprint || !raw.publicKey) {
        throw new Error("Missing required public key fields (keyId, fingerprint, publicKey)");
    }
    trace("[E.normalizePublicKey] fingerprint:", raw.fingerprint);

    return {
        version: Number(raw.version) || 1,

        account: raw.account || null,
        role: raw.role,

        keyId: raw.keyId,
        fingerprint: raw.fingerprint,
        state: raw.state || "active",

        deviceId: raw.role === "device" ? raw.deviceId : null,
        supersedes: raw.supersedes || null,
        created: raw.created || null,

        algorithm: {
            type: raw.algorithm?.type,
            usage: raw.algorithm?.usage || [],
            modulusLength: raw.algorithm?.modulusLength,
            hash: raw.algorithm?.hash
        },

        publicKey: {
            format: raw.publicKey.format,
            encoding: raw.publicKey.encoding,
            data: raw.publicKey.data
        },

        meta: {
            deviceName: raw.deviceName || null,
            browser: raw.browser || null,
            os: raw.os || null
        }
    };
}

function resetKeyRegistry() {
    log("[E.resetKeyRegistry] called");
    G.keyRegistry.accounts = {};
    G.keyRegistry.flat.activeDevices = [];
    G.keyRegistry.flat.deprecatedDevices = [];
    G.keyRegistry.flat.recoveryKeys = [];
    G.keyRegistry.loadedAt = new Date().toISOString();
}

function registerPublicKey(key) {

    if (!key || !key.fingerprint) {
        throw new Error("Cannot register invalid key");
    }
    trace("[E.registerPublicKey] for fingerprint:", key.fingerprint);

    // --- account bucket ---
    if (!G.keyRegistry.accounts[key.account]) {
        G.keyRegistry.accounts[key.account] = {
            devices: {},
            recovery: {}
        };
    }

    const accountBucket = G.keyRegistry.accounts[key.account];

    // --- role routing ---
    if (key.role === "device") {
        accountBucket.devices[key.fingerprint] = key;

        if (key.state === "active") {
            G.keyRegistry.flat.activeDevices.push(key);
        } else if (key.state === "deprecated") {
            G.keyRegistry.flat.deprecatedDevices.push(key);
        }
    }

    if (key.role === "recovery") {
        accountBucket.recovery[key.fingerprint] = key;
        G.keyRegistry.flat.recoveryKeys.push(key);
    }
}

function validateKeyRegistry(registry) {
    log("[E.validateKeyRegistry] called");

    if (!registry.loadedAt) {
        throw new Error("Registry missing loadedAt timestamp");
    }

    const seen = new Set();

    for (const key of [
        ...registry.flat.activeDevices,
        ...registry.flat.deprecatedDevices,
        ...registry.flat.recoveryKeys
    ]) {
        if (!key.fingerprint) {
            throw new Error("Registry contains key without fingerprint");
        }

        if (seen.has(key.fingerprint)) {
            throw new Error("Duplicate fingerprint in registry:" + key.fingerprint);
        }

        seen.add(key.fingerprint);
    }
}

function resolveEffectiveActiveDevices(flat) {
    log("[E.resolveEffectiveActiveDevices] called");

    const superseded = buildSupersedenceIndex([
        ...flat.activeDevices,
        ...flat.deprecatedDevices
    ]);

    return flat.activeDevices.filter(key => {
        // Must be active
        if (key.state !== "active") return false;

        // Must NOT be superseded by another key
        if (superseded.has(key.fingerprint)) return false;

        return true;
    });
}

function buildSupersedenceIndex(keys) {
    const superseded = new Set();

    for (const key of keys) {
        if (key.supersedes) {
            superseded.add(key.supersedes);
        }
    }

    return superseded;
}

async function getDriveLockSelf() {
    log("[E.getDriveLockSelf] called");
    const identity = await ID.loadIdentity();
    if (!identity) throw new Error("Identity not unlocked — cannot ensure envelope");
    const self = { account: G.userEmail, deviceId: identity.deviceId };
    return { identity, self };
}

async function createEnvelope(plainText, devicePublicKeyRecord) {
    log("[E.createEnvelope] called");

    if (!isKeyUsableForEncryption(devicePublicKeyRecord)) {
        throw new Error("Cannot encrypt for non-active key");
    }

    const cek = await generateContentKey();
    const payload = await encryptPayload(plainText, cek);

    const wrappedKey = await wrapContentKeyForDevice(cek, devicePublicKeyRecord.publicKey.data);

    return {
        version:"1.0",
        cipher: {
            payload:"AES-256-GCM",
            keyWrap:"RSA-OAEP-SHA256"
        },
        payload,
        keys: [{
            role:"device",
            account: devicePublicKeyRecord.account,
            deviceId: devicePublicKeyRecord.deviceId,
            keyId: devicePublicKeyRecord.fingerprint,
            keyVersion: devicePublicKeyRecord.version,
            wrappedKey
        }],
        created: new Date().toISOString()
    };
}

function isKeyUsableForEncryption(pubKeyRecord) {
    return pubKeyRecord.state === "active";
}

function isKeyUsableForDecryption(pubKeyRecord) {
    return pubKeyRecord.state === "active" ||
    pubKeyRecord.state === "deprecated";
}

async function writeEnvelopeWithLock(envelopeName, envelopeData) {
    log("[E.writeEnvelopeWithLock] called");

    await assertEnvelopeWrite(envelopeName);

    try {
        // 1️⃣ Find envelope file (metadata only)
        const envelopeFile = await GD.findDriveFileByName(envelopeName);

        let currentEnvelope = null;

        if (envelopeFile) {
            try {
                currentEnvelope = await GD.driveReadJsonFile(envelopeFile.id);
            } catch {
                warn("[E.writeEnvelopeWithLock] Failed to parse existing envelope — will overwrite");
            }
        }

        // 2️⃣ Increment generation
        const currentGen = currentEnvelope?.generation ?? 0;
        const newGeneration = currentGen + 1;

        // 3️⃣ Build new envelope
        const newEnvelopeContent = {
            ...envelopeData,
            generation: newGeneration,
            lastModifiedBy: G.driveLockState.self.deviceId,
            lastModifiedAt: new Date().toISOString()
        };

        // 4️⃣ Write envelope (content-only)
        if (envelopeFile?.id) {
            await GD.drivePatchJsonFile(envelopeFile.id, newEnvelopeContent);
        } else {
            await GD.driveCreateJsonFile({
                name: envelopeName,
                parents: [C.ACCESS4_ROOT_ID],
                json: newEnvelopeContent
            });
        }

        // 5️⃣ IMPORTANT: update lock generation to match
        G.driveLockState.lock.generation = newGeneration;

        await GD.writeLockToDrive(
            envelopeName,
            G.driveLockState.lock,
            G.driveLockState.fileId
        );

        // Update UI to reflect new lock generation
        UI.updateLockStatusUI();

        log(`[writeEnvelopeWithLock] Envelope "${envelopeName}" written, generation=${newGeneration}`);
        return newEnvelopeContent;

    } catch (err) {
        error(`[writeEnvelopeWithLock] Failed to write envelope "${envelopeName}": ${err.message}`);
        throw err;
    }
}

function evaluateEnvelopeLock(lock, self) {
    //trace("[E.evaluateEnvelopeLock] called");

    if (!lock) return { status:"free" };

    const now = Date.now();
    const expired = Date.parse(lock.expiresAt) <= now;

    if (expired) return { status:"free", reason:"expired" };

    if (lock.owner.account === self.account && lock.owner.deviceId === self.deviceId) {
        return { status:"owned", lock };
    }

    return { status:"locked", lock };
}

export async function acquireDriveWriteLock({ onUpdate = () => {} } = {}) {
    log("[E.acquireDriveWriteLock] called");

    const identity = await ID.loadIdentity();
    const self = { account: G.userEmail, deviceId: identity.deviceId };

    const lockFile = await GD.readLockFromDrive(C.ENVELOPE_NAME).catch(() => null);
    const evalResult = evaluateEnvelopeLock(lockFile?.json, self);

    if (evalResult.status === "locked") {
        throw new Error("Failed to acquire lock: locked-by-other");
    }

    const envelope = await GD.readEnvelopeFromDrive(C.ENVELOPE_NAME).catch(() => null);
    const generation = envelope?.generation ?? 0;

    const lock = createLockPayload(self, generation);

    log("[E.acquireDriveWriteLock] writing lock to Drive...");
    const fileId = await GD.writeLockToDrive(C.ENVELOPE_NAME, lock, lockFile?.fileId);

    log("[E.acquireDriveWriteLock] lock written, fileId:", fileId);

    // ✅ Initialize G.driveLockState safely
    G.driveLockState = {
        envelopeName: C.ENVELOPE_NAME,
        fileId: fileId || null,
        lock,
        self,
        mode:"write",
        heartbeat: startLockHeartbeat({
            envelopeName: C.ENVELOPE_NAME,
            self,
            readLockFromDrive: (name) => GD.readLockFromDrive(name),
            writeLockToDrive: (name, lock, id) => GD.writeLockToDrive(name, lock, id),
            onLost: info => handleDriveLockLost(info)
        })
    };

    onUpdate();

    log("[E.acquireDriveWriteLock] completed");
    return G.driveLockState;
}

function createLockPayload(self, generation) {
    log("[E.createLockPayload] called");

    const now = Date.now();
    return {
        version: 1,
        envelope: C.ENVELOPE_NAME,
        owner: {
            account: self.account,
            deviceId: self.deviceId
        },
        mode:"write",
        generation,
        acquiredAt: new Date(now).toISOString(),
        expiresAt: new Date(now + C.LOCK_TTL_MS).toISOString()
    };
}

function startLockHeartbeat({envelopeName, self, readLockFromDrive, writeLockToDrive, onLost}) {

    log("[E.startLockHeartbeat] args:", { readLockFromDrive, writeLockToDrive, onLost });

    let stopped = false;

    const tick = async () => {
        if (stopped || !G.driveLockState) return;

        const activeState = G.driveLockState;

        try {

            const lockFile = await readLockFromDrive(envelopeName);

            if (stopped || !G.driveLockState) return;

            const diskLock = lockFile?.json;
            const evalResult = evaluateEnvelopeLock(diskLock, self);

            if (evalResult.status !== "owned") {
                stopped = true;
                onLost?.(evalResult);
                return;
            }

            const currentGen = activeState.lock?.generation ?? 0;

            // 🔑 MERGE: never allow generation to move backwards
            const mergedLock = {
                ...diskLock,
                generation: Math.max(diskLock?.generation ?? 0, currentGen)
            };

            const extended = extendLock(mergedLock, C.LOCK_TTL_MS);

            if (extended.generation < G.driveLockState.lock.generation) {
                throw new Error("Heartbeat attempted to regress generation");
            }

            await writeLockToDrive(envelopeName, extended, lockFile.fileId);

            if (G.driveLockState) {
                G.driveLockState.lock = extended;   // keep local state authoritative
                //debug(`[startLockHeartbeat.tick] Heartbeat OK (gen=${extended.generation}, expires ${extended.expiresAt})`);
                UI.updateLockStatusUI();
            }
        } catch (err) {
            const errorMessage = err instanceof Error ? err.stack : JSON.stringify(err, Object.getOwnPropertyNames(err));
            error("[E.startLockHeartbeat.tick] CRITICAL FAILURE:", errorMessage);

            stopped = true;
            onLost?.({ reason:"heartbeat-failed", error: err });
        }
    };

    const timer = setInterval(tick, C.HEARTBEAT_INTERVAL);

    return {
        stop() {
            stopped = true;
            clearInterval(timer);
        }
    };
}

function extendLock(lock, ttlMs) {
    return {
        ...lock,
        expiresAt: new Date(Date.now() + ttlMs).toISOString()
    };
}

export function handleDriveLockLost(info) {
    warn("[E.handleDriveLockLost] Reason:", info?.reason || "Timed out");

    if (G.driveLockState?.heartbeat) {
        G.driveLockState.heartbeat.stop();
    }

    G.driveLockState = null;

    UI.updateLockStatusUI();
}

export async function wrapCEKForRegistryKeys(forceWrite = false) {

    log("[E.wrapCEKForRegistryKeys] called");
    log("[E.wrapCEKForRegistryKeys] G.unlockedIdentity:", !!G.unlockedIdentity);
    log("[E.wrapCEKForRegistryKeys] G.currentPrivateKey:", !!G.currentPrivateKey);

    const envelopeFile = await GD.readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile || !envelopeFile.json) {
        throw new Error("Envelope missing — cannot wrap CEK for registry");
    }

    const envelope = envelopeFile.json;

    log("[E.wrapCEKForRegistryKeys] envelope keys count:" + envelope?.keys?.length ?? 0);

    if (!envelope.keys || !envelope.payload) {
        throw new Error("Invalid envelope structure for CEK housekeeping");
    }

    const activeDevices = G.keyRegistry.flat.activeDevices;
    const recoveryKeys = G.keyRegistry.flat.recoveryKeys;

    log("[E.wrapCEKForRegistryKeys] Selecting device key entry...");
    log("[E.wrapCEKForRegistryKeys] G.userEmail:", G.userEmail);
    log("[E.wrapCEKForRegistryKeys] self.deviceId:", G.driveLockState?.self?.deviceId);

    // Unwrap CEK using any current device key
    const currentDeviceKeyEntry = envelope.keys.find(k =>
    k.account === G.userEmail &&
    k.deviceId === G.driveLockState.self.deviceId)/* || envelope.keys[0]*/; // Added temporary comment to debug refresh errors

    if (!currentDeviceKeyEntry) {
        error("[E.wrapCEKForRegistryKeys] No device key available to unwrap CEK");
        throw new Error("New user isn't authorized to access vault data yet. talk to admin");
    }

    log("[E.wrapCEKForRegistryKeys] Selected keyId for unwrap:", currentDeviceKeyEntry.keyId);
    log("[E.wrapCEKForRegistryKeys] Selected deviceId:", currentDeviceKeyEntry.deviceId);

    log("[E.wrapCEKForRegistryKeys] Attempting CEK unwrap");
    log("[E.wrapCEKForRegistryKeys] unwrap keyId:", currentDeviceKeyEntry.keyId);
    log("[E.wrapCEKForRegistryKeys] G.unlockedIdentity fingerprint:", G.unlockedIdentity?.fingerprint);
    log("[E.wrapCEKForRegistryKeys] G.currentPrivateKey exists:", !!G.currentPrivateKey);

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
        log("[E.wrapCEKForRegistryKeys] Envelope updated with wrapped keys — writing to Drive");
        await writeEnvelopeSafely(C.ENVELOPE_NAME, envelope);
    } else {
        log("[E.wrapCEKForRegistryKeys] Envelope up to date — skipping write");
    }

    return envelope;
}

/* ---Unwrap CEK Using Local Private Key (rotation-safe) --- */
async function unwrapContentKey(wrappedKeyBase64, keyId) {

    log("[E.unwrapContentKey] called");
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
            const derivedKey = await CR.deriveKey(G.unlockedPassword, prev.kdf);
            const privateKeyPkcs8 = await CR.decrypt(prev.encryptedPrivateKey, derivedKey);
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

async function addRecoveryKeyToEnvelope({ publicKey, keyId }) {
    log("[E.addRecoveryKeyToEnvelope] called - Adding recovery key to envelope...");

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
        warn("[E.addRecoveryKeyToEnvelope] Recovery key already present in envelope, skipping add");
    } else {
        // 3️⃣ Unwrap CEK using the first active device key
        log("[E.addRecoveryKeyToEnvelope] Unwrapping CEK with active device key...");
        const cek = await unwrapContentKey(
            envelope.keys[0].wrappedKey,
            envelope.keys[0].keyId
        );
        log("[E.addRecoveryKeyToEnvelope] CEK unwrapped");

        // 4️⃣ Wrap CEK for the new recovery key
        log("[E.addRecoveryKeyToEnvelope] Wrapping CEK for recovery key...");
        let wrappedKey;
        try {
            wrappedKey = await wrapContentKeyForDevice(cek, publicKey);
            log("[E.addRecoveryKeyToEnvelope] CEK wrapped for recovery key");
        } catch (err) {
            error("[E.addRecoveryKeyToEnvelope] Error wrapping CEK:", err);
            throw err;
        }

        // 5️⃣ Add recovery key to envelope
        envelope.keys.push({
            role:"recovery",
            keyId,
            wrappedKey
        });

        log("[E.addRecoveryKeyToEnvelope] Added recovery key to envelope.keys:" + envelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));
    }

    // ---- Housekeeping CEK wrap for all devices & recovery keys (force write) ----
    if (G.driveLockState?.self && G.driveLockState.envelopeName === envelopeName) {
        log("[E.addRecoveryKeyToEnvelope] Performing CEK housekeeping with force write");
        const updatedEnvelope = await wrapCEKForRegistryKeys(true); // <- forceWrite = true

        log("[E.addRecoveryKeyToEnvelope] Updated envelope after wrapCEKForRegistryKeys:" + updatedEnvelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));

        // 6️⃣ Write updated envelope safely
        await writeEnvelopeSafely(envelopeName, updatedEnvelope);
    }

    log("[E.addRecoveryKeyToEnvelope] Recovery key added to envelope and saved");
}

export async function encryptAndPersistPlaintext(plainText) {

    // Ensure we own the lock
    if (!G.driveLockState || G.driveLockState.envelopeName !== C.ENVELOPE_NAME) {
        await E.acquireDriveWriteLock(() => UI.updateLockStatusUI());
    }

    await assertEnvelopeWrite(C.ENVELOPE_NAME);

    // Load envelope
    const envelopeFile = await GD.readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile?.json) {
        throw new Error("Envelope missing");
    }

    const envelope = envelopeFile.json;

    log("[E.encryptAndPersistPlaintext] envelope:" + envelope)

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
    const written = await writeEnvelopeSafely(C.ENVELOPE_NAME, updatedEnvelope);

    log("🔒 Payload encrypted & written to envelope");

    // Verify decrypt immediately (sanity + demo)
    const decrypted = await openEnvelope(written);
    log("Decrypted payload:");
    log(decrypted);
}

/* --- Encrypt Payload with CEK --- */
async function encryptPayload(plainText, cek) {
    log("[E.encryptPayload] called");

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);

    const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM", iv}, cek, encoded);

    return {
        iv: btoa(String.fromCharCode(...iv)),
        data: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
    };
}

async function openEnvelope(envelope) {

    log("[E.openEnvelope] called");

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

export async function loadEnvelopePayloadToUI(envelopeName = C.ENVELOPE_NAME) {
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

        log("[E.loadEnvelopePayloadToUI] Payload loaded into plaintext UI");
    } catch (err) {
        error("[E.loadEnvelopePayloadToUI] Failed to decrypt envelope payload:", err.message);
    }
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
    log("[E.writeEnvelopeSafely] called");

    let attempt = 0;

    while (attempt < maxRetries) {
        attempt++;

        // Ensure we hold the lock
        if (!G.driveLockState || G.driveLockState.envelopeName !== envelopeName) {
            log(`[E.writeEnvelopeSafely] Attempting to acquire lock for "${envelopeName}" (attempt ${attempt})`);
            try {
                await E.acquireDriveWriteLock(() => UI.updateLockStatusUI());
            } catch (err) {
                warn(`[E.writeEnvelopeSafely] Lock acquisition failed: ${err.message} retrying...`);
                await new Promise(r => setTimeout(r, retryDelayMs));
                continue;
            }
        }

        await assertEnvelopeWrite(envelopeName);

        try {
            const result = await writeEnvelopeWithLock(envelopeName, envelopeData);
            return result;
        } catch (err) {
            warn(`[writeEnvelopeSafely] Write attempt failed: ${err.message} retrying...`);
            // If lock was lost mid-write, retry
            await new Promise(r => setTimeout(r, retryDelayMs));
        }
    }

    throw new Error(`Failed to write envelope "${envelopeName}" after ${maxRetries} attempts`);
}

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

async function generateContentKey() {
    log("[E.generateContentKey] called");

    return crypto.subtle.generateKey({
        name:"AES-GCM",
        length: 256
    },
        true,
        ["encrypt", "decrypt"]
    );
}