import { C, G, CR, ID, GD, EN, log, trace, debug, info, warn, error, isTraceEnabled } from '@/shared/exports.js';

import { updateLockStatusUI }  from '@/ui/vault.js';

let _transientCEK = null;
let _transientEnvelope = null;

export async function getDriveLockSelf() {
    log("SV.getDriveLockSelf", "called");
    const identity = await ID.loadIdentity();
    if (!identity) throw new Error("Identity not unlocked — cannot ensure envelope");
    const self = { account: G.userEmail, deviceId: identity.deviceId };
    return { identity, self };
}

function isKeyUsableForDecryption(pubKeyRecord) {
    return pubKeyRecord.state === "active" || pubKeyRecord.state === "deprecated";
}

function createLockPayload(self, generation) {
    log("SV.createLockPayload", "called");

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

function startLockHeartbeat({self, readLockFromDrive, writeLockToDrive, onLost}) {

    log("SV.startLockHeartbeat", "called - args:", { readLockFromDrive, writeLockToDrive, onLost });

    let stopped = false;

    const tick = async () => {
        if (stopped || !G.driveLockState) return;

        const activeState = G.driveLockState;

        try {

            const lockFile = await readLockFromDrive();

            if (stopped || !G.driveLockState) return;

            const diskLock = lockFile?.json;
            const evalResult = evaluateEnvelopeLock(diskLock, self);

            if (evalResult.status !== "owned") {
                // If we were throttled, we might see 'expired' here.
                // But our new evaluateEnvelopeLock above will return 'owned'
                // if the deviceId still matches, so this block won't even trigger!
                stopped = true;
                onLost?.(evalResult);
                return;
            }

            const currentGen = activeState.lock?.generation ?? 0;

            // MERGE: never allow generation to move backwards
            const mergedLock = {
                ...diskLock,
                generation: Math.max(diskLock?.generation ?? 0, currentGen)
            };

            const extended = extendLock(mergedLock, C.LOCK_TTL_MS);

            if (extended.generation < G.driveLockState.lock.generation) {
                throw new Error("Heartbeat attempted to regress generation");
            }

            await writeLockToDrive(extended, lockFile.fileId);

            if (G.driveLockState) {
                G.driveLockState.lock = extended;   // keep local state authoritative
                trace("SV.startLockHeartbeat.tick", `Heartbeat OK (gen=${extended.generation}, expires ${extended.expiresAt})`);
                updateLockStatusUI();
            }
        } catch (err) {
            const errorMessage = err instanceof Error ? err.stack : JSON.stringify(err, Object.getOwnPropertyNames(err));
            error("SV.startLockHeartbeat.tick", "CRITICAL FAILURE:", errorMessage);

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

export function evaluateEnvelopeLock(lock, self) {
    //trace("EN.evaluateEnvelopeLock", "called");

    if (!lock) return { status:"free" };

    const now = Date.now();
    const expired = Date.parse(lock.expiresAt) <= now;

    if (expired) return { status:"free", reason:"expired" };

    if (lock.owner.account === self.account && lock.owner.deviceId === self.deviceId) {
        return { status:"owned", lock };
    }

    return { status:"locked", lock };
}

export async function tryAcquireEnvelopeWriteLock(options = {}) {
    log("SV.tryAcquireEnvelopeWriteLock", "called");

    // 1️⃣ Already have it? Success.
    if (G.driveLockState?.mode === "write") return true;

    // 2️⃣ State is null or Read-Only? Try to get/promote it.
    log("SV.tryAcquireEnvelopeWriteLock", "No active write lock. Attempting re-acquisition...");
    try {
        await acquireDriveWriteLock(options);
        return true;
    } catch (err) {
        if (err.message?.includes("locked-by-other")) {
            warn("SV.tryAcquireEnvelopeWriteLock", "Locked by another device.");
            return false;
        }
        throw err;
    }
}

function extendLock(lock, ttlMs) {
    return { ...lock, expiresAt: new Date(Date.now() + ttlMs).toISOString() };
}

async function reconcileWrapSet({ envelope, cek, registryItems, role, forceWrite, buildEntryMeta }) {
    let updated = false;

    for (const item of registryItems) {
        const keyId = item.fingerprint;

        const existing = envelope.keys.find(k => k.keyId === keyId && k.role === role);

        const now = new Date().toISOString();

        if (!existing) {
            const wrappedKey = await wrapContentKeyForDevice(cek, item.publicKey.data);
            envelope.keys.push({ role, keyId, created: now, updated: null, publicKeyCreated: item.created || now, wrappedKey, ...buildEntryMeta(item) });
            updated = true;
        } else if (forceWrite) {
            existing.wrappedKey = await wrapContentKeyForDevice(cek, item.publicKey.data);
            existing.updated = now;
            existing.publicKeyCreated = existing.publicKeyCreated || item.created || now;
            updated = true;
        }
    }
    return updated;
}

/* ---Unwrap CEK Using Local Private Key (rotation-safe) --- */
export async function unwrapContentKey(wrappedKeyBase64, keyId) {

    log("SV.unwrapContentKey", "called");
    const id = await ID.loadIdentity();
    if (!id) throw new Error("Local identity missing");

    // 1️⃣ Try current in-memory private key if keyId matches
    if (G.currentPrivateKey && keyId === id.fingerprint) {
        log("SV.unwrapContentKey", `Using G.currentPrivateKey for keyId ${keyId}`);
        return CR.unwrapCEKWithPrivateKey(wrappedKeyBase64, G.currentPrivateKey);
    }

    // 2️⃣ Try decrypted previous keys from session
    if (id._decryptedPreviousKeys?.length) {
        const prev = id._decryptedPreviousKeys.find(k => k.fingerprint === keyId);
        if (prev) {
            log("SV.unwrapContentKey", `Using decrypted previous key for keyId ${keyId}`);
            return CR.unwrapCEKWithPrivateKey(wrappedKeyBase64, prev.privateKey);
        }
    }

    // 3️⃣ Fallback: use G.currentPrivateKey even if fingerprint mismatch
    if (G.currentPrivateKey) {
        log("SV.unwrapContentKey", `Fallback: using G.currentPrivateKey despite fingerprint mismatch for keyId ${keyId}`);
        return CR.unwrapCEKWithPrivateKey(wrappedKeyBase64, G.currentPrivateKey);
    }

    // 4️⃣ Nothing found
    error("SV.unwrapContentKey", `No private key available for keyId ${keyId}`);
    throw new Error("No private key available for keyId:" + keyId);
}


/* --- Wrap CEK for a Device Public Key --- */
export async function wrapContentKeyForDevice(cek, devicePublicKeyBase64) {
    log("SV.wrapContentKeyForDevice", "called");

    const publicKey = await CR.importRSAPublicKeyFromB64(devicePublicKeyBase64, ["wrapKey"]);
    return await CR.wrapCEKForPublicKey(cek, publicKey);
}

export async function acquireDriveWriteLock({ onUpdate = () => {} } = {}) {
    log("SV.acquireDriveWriteLock", "called");

    const identity = await ID.loadIdentity();
    const self = { account: G.userEmail, deviceId: identity.deviceId };

    const lockFile = await readLockFromDrive().catch(() => null);
    const evalResult = evaluateEnvelopeLock(lockFile?.json, self);

    if (evalResult.status === "locked") {
        throw new Error("Failed to acquire lock: locked-by-other");
    }

    const envelope = await EN.readEnvelopeFromDrive().catch(() => null);
    const generation = envelope?.generation ?? 0;

    const lock = createLockPayload(self, generation);

    log("SV.acquireDriveWriteLock", "writing lock to Drive...");
    const fileId = await writeLockToDrive(lock, lockFile?.fileId);

    log("SV.acquireDriveWriteLock", "lock written, fileId:", fileId);

    // ✅ Initialize G.driveLockState safely
    G.driveLockState = {
        envelopeName: C.ENVELOPE_NAME,
        fileId: fileId || null,
        lock,
        self,
        mode:"write",
        heartbeat: startLockHeartbeat({
            self,
            readLockFromDrive: () => readLockFromDrive(),
            writeLockToDrive: (lock, id) => writeLockToDrive(lock, id),
            onLost: info => handleDriveLockLost(info)
        })
    };

    onUpdate();

    log("SV.acquireDriveWriteLock", "completed");
    return G.driveLockState;
}

export async function readLockFromDrive() {
    //trace("SV.readLockFromDrive", "called");
    return await GD.readJsonByName(`${C.ENVELOPE_NAME}.lock`);
}

/**
 * EXPORTED FUNCTIONS
 */
export async function ensureDevicePublicKey() {
    log("SV.ensureDevicePublicKey", "called");

    const id = await ID.loadIdentity();
    if (!id) throw new Error("Local identity missing");

    const deviceId = ID.getDeviceId();

    const folder = await GD.ensureUserPubKeyFolder();

    //const filename = `${G.userEmail}_${deviceId}.json`;
    const filename = `${deviceId}.json`;
    const file = await GD.findDriveFileByNameInFolder(filename, folder);

    if (file?.id) {
        info("SV.ensureDevicePublicKey", `Device public key ...${filename} exists on drive`);
        return;
    }

    const pubBytes = CR.b64ToBuf(id.publicKey);
    const fingerprint = await CR.computePublicKeyFingerprint(pubBytes);

    const pubData = {
        version: "1",
        account: G.userEmail,
        deviceId,
        keyId: fingerprint,
        fingerprint,
        state:"active",
        role:"device",
        supersedes: id.supersedes || null,
        created: new Date().toISOString(),
        algorithm: {
            type: CR.CR_ALG.RSA.DEFAULT,
            usage: ["wrapKey"],
            modulusLength: CR.CR_ALG.RSA_MODULUS_LENGTH,
            hash: CR.CR_ALG.HASH.SHA256
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

    //File doesn't exist → create new
    await GD.upsertJsonFile({ name: filename, parentId: folder, json: pubData });

    log("SV.ensureDevicePublicKey", `Device public key UPLOADED to ${filename}`);
    return pubData;
}

export function handleDriveLockLost(info) {
    warn("SV.handleDriveLockLost", "Reason:", info?.reason || "Timed out");

    if (G.driveLockState?.heartbeat) {
        G.driveLockState.heartbeat.stop();
    }

    G.driveLockState = null;
    updateLockStatusUI("Lock lost!");
}

export async function writeLockToDrive(lockJson, existingFileId = null) {
    //trace("SV.writeLockToDrive", "called lockJson:", JSON.stringify(lockJson));

    if (existingFileId) {
        // ✅ Content-only update
        await GD.drivePatchJsonFile(existingFileId, lockJson);
        return existingFileId;
    }

    // ✅ New file creation
    return await GD.upsertJsonFile({
        name: `${C.ENVELOPE_NAME}.lock`,
        parentId: C.ACCESS4_ROOT_ID,
        json: lockJson
    });
}

export async function wrapCEKForRegistryKeys(envelope = null, forceWrite = false) {

    log("SV.wrapCEKForRegistryKeys", "called");
    log("SV.wrapCEKForRegistryKeys", `G.unlockedIdentity: ${!!G.unlockedIdentity}, G.currentPrivateKey: ${!!G.currentPrivateKey}, G.recoverySession: ${G.recoverySession}`);

    // HARD GUARD — must have private key loaded
    if (!G.currentPrivateKey && !(G.recoverySession && G.recoveryCEK)) {
        throw new Error("wrapCEKForRegistryKeys called without private key loaded");
    }

    if (!envelope) {
        const file = await EN.readEnvelopeFromDrive();
        envelope = file?.json;

        if (!envelope) {
            throw new Error("Envelope missing — cannot wrap CEK for registry");
        }
    }

    log("SV.wrapCEKForRegistryKeys", "envelope keys count:" + (envelope?.keys?.length ?? 0));

    if (!envelope.keys || !envelope.payload) {
        throw new Error("Invalid envelope structure for CEK housekeeping");
    }

    let updated = false;

    const activeDevices = G.keyRegistry.flat.activeDevices;
    const recoveryKeys = G.keyRegistry.flat.recoveryKeys;

    /*
     * ============================================================
     * ROLE CONFIGURATION (single source of truth)
     * ============================================================
     */
    const ROLE_CONFIG = [
        { role: "device", items: activeDevices },
        { role: "recovery", items: recoveryKeys }
    ];

    /*
     * ============================================================
     * ORPHAN CLEANUP (WRITE MODE ONLY)
     * ============================================================
     */
    if (G.driveLockState?.mode === "write") {

        const allowedByRole = new Map();

        for (const { role, items } of ROLE_CONFIG) {
            allowedByRole.set(role, new Set(items.map(i => i.fingerprint)));
        }

        const originalLength = envelope.keys.length;

        envelope.keys = envelope.keys.filter(entry => {
            const allowedSet = allowedByRole.get(entry.role);

            // Preserve unknown roles defensively
            if (!allowedSet) return true;

            const exists = allowedSet.has(entry.keyId);

            if (!exists)
                warn("SV.wrapCEKForRegistryKeys", `Removing orphan keyId: ${entry.keyId}`);

            return exists;
        });

        if (envelope.keys.length !== originalLength) {
            updated = true;
            warn("SV.wrapCEKForRegistryKeys", `Orphan CEK entries removed: ${originalLength - envelope.keys.length}`);
        }
    }

    log("SV.wrapCEKForRegistryKeys", "Selecting device key entry...");
    log("SV.wrapCEKForRegistryKeys", `G.userEmail: ${G.userEmail.slice(-12)}, self.deviceId: ${G.driveLockState?.self?.deviceId}`);

    /*
     * ============================================================
     * UNWRAP ELIGIBLE CEK
     * ============================================================
     */
    let cek;

    if (G.recoverySession === true && G.recoveryCEK) {
        log("SV.wrapCEKForRegistryKeys", "Using recovery CEK (recovery mode)");
        cek = G.recoveryCEK;
        //G.recoveryCEK = null;   // null it immediately as it's role is done
    } else {
        const currentDeviceKeyEntry = await EN.selectDecryptableKey(envelope);

        if (!currentDeviceKeyEntry) {
            error("SV.wrapCEKForRegistryKeys", "No device key available to unwrap CEK");
            throw new Error("Missing envelope CEK error] This user+device isn't authorized to access vault data yet");
        }

        log("SV.wrapCEKForRegistryKeys", "Attempting CEK unwrap");
        log("SV.wrapCEKForRegistryKeys", `Selected deviceId: ${currentDeviceKeyEntry.deviceId}, unwrap keyId: ${currentDeviceKeyEntry.keyId}, G.unlockedIdentity fingerprint: ${G.unlockedIdentity?.fingerprint}`);

        cek = await unwrapContentKey(currentDeviceKeyEntry.wrappedKey, currentDeviceKeyEntry.keyId);
    }

    /*
     * ============================================================
     * ROLE-DRIVEN WRAP RECONCILIATION
     * ============================================================
     */
    for (const { role, items } of ROLE_CONFIG) {

        const roleUpdated = await reconcileWrapSet({ envelope, cek, registryItems: items, role, forceWrite,
            buildEntryMeta: (item) => {
                if (role === "device") {
                    return {
                        account: item.account,
                        deviceId: item.deviceId
                    };
                }
                return {}; // recovery or future roles
            }
        });

        updated = updated || roleUpdated;

        log("SV.wrapCEKForRegistryKeys", `${role} keys updated: ${roleUpdated}, forceWrite: ${forceWrite}`);
    }

    /*
     * ============================================================
     * WRITE BACK IF UPDATED OR forceWrite
     * ============================================================
     */
    if (updated || forceWrite) {
        log("SV.wrapCEKForRegistryKeys", "Envelope updated with wrapped keys — writing to Drive");
        await EN.writeEnvelopeSafely(envelope);
    } else {
        log("SV.wrapCEKForRegistryKeys", "Envelope up to date — skipping write");
    }

    return envelope;
}

export async function encryptAndPersistPlaintext(plainText, options = {}) {
    log("SV.encryptAndPersistPlaintext", "called");

    // Ensure we own the lock
    if (!G.driveLockState || G.driveLockState.envelopeName !== C.ENVELOPE_NAME) {
        await acquireDriveWriteLock(options);
    }

    await EN.assertEnvelopeWrite(C.ENVELOPE_NAME);

    const envelopeFile = await EN.readEnvelopeFromDrive();
    const envelope = envelopeFile.json;

    // Use the centralized helper to get the CEK
    // This handles the Drive fetch, the self-entry lookup, and the unwrap
    const cek = await getActiveCEK(envelope);

    // Encrypt new payload
    const payload = await CR.encrypt(plainText, cek);

    // Update envelope payload only
    const updatedEnvelope = {
        ...envelope,
        payload
    };

    // Persist safely (generation + lock heartbeat preserved)
    const written = await EN.writeEnvelopeSafely(updatedEnvelope);

    info("SV.encryptAndPersistPlaintext", "Payload encrypted & written to envelope");
}

// only use with logic that is okay to use the transients - attachment logic
export async function getTransientCEK() {
    if (!_transientEnvelope) {
        const envelopeFile = await EN.readEnvelopeFromDrive();
        if (!envelopeFile?.json) {
            throw new Error("Active envelope not found on Drive.");
        }
        _transientEnvelope = envelopeFile.json;
    }

    return await getActiveCEK(_transientEnvelope);
}


/**
 * Wipes the cached CEK.
 * Call this when the user closes the Vault or logs out.
 */
export function flushCachedTransients() {
    _transientCEK = null;
    _transientEnvelope = null;
    log("SV.flushCachedTransients", "Transient CEK and envelope wiped from memory, if cached.");
}

/**
 * Internal helper to retrieve and unwrap the CEK for the current session.
 * Reuses the existing logic from encryptAndPersistPlaintext but returns the key object.
 */
async function getActiveCEK(envelope) {
    // 1. Check if we already unwrapped it this session/view
    if (_transientCEK) {
        trace("SV.getActiveCEK", "Returning cached transient CEK");
        return _transientCEK;
    }

    log("SV.getActiveCEK", "Cache miss - unwrapping CEK from envelope");

    /*if (isTraceEnabled())
        trace("SV.getActiveCEK", "envelope:", envelope);*/

    const selfEntry = envelope.keys.find(k => k.deviceId === G.driveLockState.self.deviceId);

    if (!selfEntry) {
        error("SV.getActiveCEK", "This device is not authorized in the current envelope.");
        throw new Error("Device authorization missing.");
    }

    // 2. Perform the expensive RSA unwrap
    const cek = await unwrapContentKey(selfEntry.wrappedKey, selfEntry.keyId);

    // 3. Store in the transient variable for subsequent calls
    _transientCEK = cek;

    return _transientCEK;
}
