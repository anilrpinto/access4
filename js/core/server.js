import { C, G, CR, RG, ID, GD, log, trace, debug, info, warn, error, isTraceEnabled } from '@/shared/exports.js';

import { updateLockStatusUI }  from '@/ui/vault.js';

let _transientCEK = null;
let _transientEnvelope = null;

async function getDriveLockSelf() {
    log("SV.getDriveLockSelf", "called");
    const identity = await ID.loadIdentity();
    if (!identity) throw new Error("Identity not unlocked — cannot ensure envelope");
    const self = { account: G.userEmail, deviceId: identity.deviceId };
    return { identity, self };
}

async function createEnvelope(plainText, devicePublicKeyRecord) {
    log("SV.createEnvelope", "called");

    if (!isKeyUsableForEncryption(devicePublicKeyRecord)) {
        throw new Error("Cannot encrypt for non-active key");
    }

    const cek = await CR.generateCEK();
    const payload = await CR.encrypt(plainText, cek);

    const wrappedKey = await wrapContentKeyForDevice(cek, devicePublicKeyRecord.publicKey.data);
    const now = new Date().toISOString();

    return {
        version:"1.0",
        cipher: {
            payload:"AES-256-GCM",
            keyWrap:"RSA-OAEP-SHA256"
        },
        payload,
        keys: [{
            role: "device",
            account: devicePublicKeyRecord.account,
            deviceId: devicePublicKeyRecord.deviceId,
            keyId: devicePublicKeyRecord.fingerprint,
            keyVersion: devicePublicKeyRecord.version,
            created: now,
            updated: null,
            publicKeyCreated: devicePublicKeyRecord.created,
            wrappedKey
        }],
        created: now,
    };
}

function isKeyUsableForEncryption(pubKeyRecord) {
    return pubKeyRecord.state === "active";
}

function isKeyUsableForDecryption(pubKeyRecord) {
    return pubKeyRecord.state === "active" || pubKeyRecord.state === "deprecated";
}

async function writeEnvelopeWithLock(envelopeData) {
    log("SV.writeEnvelopeWithLock", "called");

    await assertEnvelopeWrite(C.ENVELOPE_NAME);

    try {

        // 1️⃣ Read envelope (includes fileId)
        const existing = await GD.readJsonByName(C.ENVELOPE_NAME);

        const currentEnvelope = existing?.json ?? null;
        const fileId = existing?.fileId ?? null;

        // 2️⃣ Increment generation
        const newGeneration = (currentEnvelope?.generation ?? 0) + 1;

        // 3️⃣ Build new envelope
        const newEnvelopeContent = {
            ...envelopeData,
            generation: newGeneration,
            lastModifiedBy: G.driveLockState.self.deviceId,
            lastModifiedAt: new Date().toISOString()
        };

        // 4️⃣ Write envelope
        if (fileId)
            await GD.drivePatchJsonFile(fileId, newEnvelopeContent);
        else
            await GD.upsertJsonFile({ name: C.ENVELOPE_NAME, parentId: C.ACCESS4_ROOT_ID, json: newEnvelopeContent });

        // 5️⃣ Update lock generation
        G.driveLockState.lock.generation = newGeneration;

        await writeLockToDrive(C.ENVELOPE_NAME, G.driveLockState.lock, G.driveLockState.fileId);

        // Update UI to reflect new lock generation
        updateLockStatusUI();

        log("SV.writeEnvelopeWithLock", `Envelope "${C.ENVELOPE_NAME}" written, generation=${newGeneration}`);
        return newEnvelopeContent;

    } catch (err) {
        error("writeEnvelopeWithLock", `Failed to write envelope "${C.ENVELOPE_NAME}": ${err.message}`);
        throw err;
    }
}

function evaluateEnvelopeLock(lock, self) {
    //trace("SV.evaluateEnvelopeLock", "called");

    if (!lock) return { status:"free" };

    const now = Date.now();
    const expired = Date.parse(lock.expiresAt) <= now;

    if (expired) return { status:"free", reason:"expired" };

    if (lock.owner.account === self.account && lock.owner.deviceId === self.deviceId) {
        return { status:"owned", lock };
    }

    return { status:"locked", lock };
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

function startLockHeartbeat({envelopeName, self, readLockFromDrive, writeLockToDrive, onLost}) {

    log("SV.startLockHeartbeat", "called - args:", { readLockFromDrive, writeLockToDrive, onLost });

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

            // MERGE: never allow generation to move backwards
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

function extendLock(lock, ttlMs) {
    return {
        ...lock,
        expiresAt: new Date(Date.now() + ttlMs).toISOString()
    };
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
async function unwrapContentKey(wrappedKeyBase64, keyId) {

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

async function openEnvelope(envelope) {
    log("SV.openEnvelope", "called");

    validateEnvelope(envelope);

    const entry = await selectDecryptableKey(envelope);
    log("SV.openEnvelope", `Using keyId: ${entry.keyId}`);

    const cek = await unwrapContentKey(entry.wrappedKey, entry.keyId);
    const decrypted = await CR.decrypt(envelope.payload, cek);

    return new TextDecoder().decode(decrypted);
}

async function selectDecryptableKey(envelope) {
    log("SV.selectDecryptableKey", "called");

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
            warn("SV.selectDecryptableKey", "Envelope encrypted with previous device key — rotation detected");
        }
        return deviceEntry;
    }

    // 2️⃣ Optional fallback: recovery key (NO deviceId expected)
    const recoveryEntry = envelope.keys.find(k => k.role === "recovery");

    if (recoveryEntry) {
        warn("SV.selectDecryptableKey", "Falling back to recovery key for decryption");
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
    log("SV.validateEnvelope", "called");

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

/* --- Wrap CEK for a Device Public Key --- */
async function wrapContentKeyForDevice(cek, devicePublicKeyBase64) {
    log("SV.wrapContentKeyForDevice", "called");

    const publicKey = await CR.importRSAPublicKeyFromB64(devicePublicKeyBase64, ["wrapKey"]);
    return await CR.wrapCEKForPublicKey(cek, publicKey);
}

async function writeEnvelopeSafely(envelopeData, maxRetries = 3, retryDelayMs = 1000) {
    log("SV.writeEnvelopeSafely", "called");

    let attempt = 0;

    while (attempt < maxRetries) {
        attempt++;

        // Ensure we hold the lock
        if (!G.driveLockState || G.driveLockState.envelopeName !== C.ENVELOPE_NAME) {
            log("SV.writeEnvelopeSafely", `Attempting to acquire lock for "${C.ENVELOPE_NAME}" (attempt ${attempt})`);
            try {
                await acquireDriveWriteLock();
            } catch (err) {
                warn("SV.writeEnvelopeSafely", `Lock acquisition failed: ${err.message} retrying...`);
                await new Promise(r => setTimeout(r, retryDelayMs));
                continue;
            }
        }

        await assertEnvelopeWrite(C.ENVELOPE_NAME);

        try {
            const result = await writeEnvelopeWithLock(envelopeData);
            return result;
        } catch (err) {
            warn("SV.writeEnvelopeSafely", `Write attempt failed: ${err.message} retrying...`);
            // If lock was lost mid-write, retry
            await new Promise(r => setTimeout(r, retryDelayMs));
        }
    }

    throw new Error(`Failed to write envelope "${C.ENVELOPE_NAME}" after ${maxRetries} attempts`);
}

async function assertEnvelopeWrite(envelopeName) {
    log("SV.assertEnvelopeWrite", "called");

    if (!G.driveLockState) {
        throw new Error(`Cannot write: no drive lock state for "${envelopeName}"`);
    }

    if (G.driveLockState.envelopeName !== envelopeName) {
        throw new Error(`Cannot write: lock does not match envelope "${envelopeName}"`);
    }

    if (G.driveLockState.mode !== "write") {
        throw new Error(`Read-only session — write not permitted for envelope "${envelopeName}"`);
    }

    log("SV.assertEnvelopeWrite", `Ownership confirmed for envelope "${envelopeName}"`);

    // Future housekeeping hook: missing device/recovery keys
    // log(`[housekeeping] Envelope ownership confirmed for "${envelopeName}"`);
}

async function acquireDriveWriteLock({ onUpdate = () => {} } = {}) {
    log("SV.acquireDriveWriteLock", "called");

    const identity = await ID.loadIdentity();
    const self = { account: G.userEmail, deviceId: identity.deviceId };

    const lockFile = await readLockFromDrive(C.ENVELOPE_NAME).catch(() => null);
    const evalResult = evaluateEnvelopeLock(lockFile?.json, self);

    if (evalResult.status === "locked") {
        throw new Error("Failed to acquire lock: locked-by-other");
    }

    const envelope = await readEnvelopeFromDrive(C.ENVELOPE_NAME).catch(() => null);
    const generation = envelope?.generation ?? 0;

    const lock = createLockPayload(self, generation);

    log("SV.acquireDriveWriteLock", "writing lock to Drive...");
    const fileId = await writeLockToDrive(C.ENVELOPE_NAME, lock, lockFile?.fileId);

    log("SV.acquireDriveWriteLock", "lock written, fileId:", fileId);

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
            readLockFromDrive: (name) => readLockFromDrive(name),
            writeLockToDrive: (name, lock, id) => writeLockToDrive(name, lock, id),
            onLost: info => handleDriveLockLost(info)
        })
    };

    onUpdate();

    log("SV.acquireDriveWriteLock", "completed");
    return G.driveLockState;
}

async function readLockFromDrive(envelopeName) {
    //trace("SV.readLockFromDrive", "called");
    const lockName = `${envelopeName}.lock`;

    const file = await GD.findDriveFileByNameInRoot(lockName);
    if (!file) return null;

    const json = await GD.readJsonByFileId(file.id);

    return {
        fileId: file.id,
        json
    };
}

function _createStarterVaultJson() {
    return {
        "meta": {
            "version": "1.0",
            "lastModified": null,
        },
        "groups": [
            {
                "id": "g-12345567890",
                "name": "Genesis",
                "items": [
                    {
                        "id": "i-1234567890",
                        "label": "Access4",
                        "created": "2026-01-10T08:00:00Z",
                        "modified": "2026-02-20T15:30:00Z",
                        "fields": [
                            {
                                "type": "text",
                                "key": "username",
                                "val": "username1234"
                            },
                            {
                                "type": "secure",
                                "key": "Password",
                                "val": "password1234"
                            },
                            {
                                "type": "note",
                                "key": "Notes",
                                "val": "Some important notes"
                            }
                        ],
                        "attachments": []
                    }
                ]
            }
        ]
    };
}

/**
 * EXPORTED FUNCTIONS
 */
export async function readEnvelopeFromDrive(envelopeName) {
    return GD.readJsonByName(envelopeName);
}

export async function ensureEnvelope() {
    log("SV.ensureEnvelope", "called");

    // CACHE identity + self for this entire function
    const { identity, self } = await getDriveLockSelf();

    // ─── Fast path: skip lock re-acquire if already initialized ───
    if (G.driveLockState?.mode) {
        log("SV.ensureEnvelope", "Drive lock already initialized — skipping lock acquisition");
        log("SV.ensureEnvelope", "G.driveLockState:", JSON.stringify(G.driveLockState));
    } else {
        const lockFile = await readLockFromDrive(C.ENVELOPE_NAME);
        const result = evaluateEnvelopeLock(lockFile?.json, self);

        log("SV.ensureEnvelope", "Envelope lock result.status:", result.status);

        if (result.status === "owned") {
            log("SV.ensureEnvelope", "Envelope lock owned");
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile?.fileId, lock: lockFile?.json, self, mode:"write" };
        } else if (result.status === "locked") {
            log("SV.ensureEnvelope", "Envelope locked by another device — entering read-only mode");
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile.fileId, lock: lockFile.json, self, mode:"read" };
        } else {
            log("SV.ensureEnvelope", "No lock found — entering read mode (no auto-acquire)");
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile?.fileId ?? null, lock: lockFile?.json ?? null, self, mode: "read" };
        }
    }

    log("SV.ensureEnvelope", `G.driveLockState - mode: ${G.driveLockState.mode} self.deviceId: ${G.driveLockState.self.deviceId}`);

    //REF: do NOT assign frozen object to G.keyRegistry
    await RG.buildKeyRegistryFromDrive(); // updates mutable G.keyRegistry internally

    // Optional snapshot for read-only usage (UI or debug)
    const keyRegistrySnapshot = structuredClone(G.keyRegistry);

    //Uncomment only if UI consumes it
    //Object.freeze(keyRegistrySnapshot); // if you want deepFreeze, do it here

    log("SV.ensureEnvelope", "activeDevices registry:", G.keyRegistry.flat.activeDevices.length);
    log("SV.ensureEnvelope", "recoveryKeys registry:", G.keyRegistry.flat.recoveryKeys.length);

    if (!G.keyRegistry.flat.recoveryKeys.length)
        warn("SV.ensureEnvelope", "WARNING: NO RECOVERY KEY ENTRY IN ENVELOPE. CREATE ONE IMMEDIATELY!!");

    // ─── Fast path: load existing envelope ───
    const existing = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (existing?.json) {
        log("SV.ensureEnvelope", "Envelope already exists");
        return existing.json;
    }

    // ─── Genesis envelope path ───
    log("SV.ensureEnvelope", "Envelope missing — creating genesis envelope");

    // GENESIS LOCK ESCALATION
    if (G.driveLockState.mode !== "write") {
        log("SV.ensureEnvelope", "Genesis escalation — acquiring envelope write lock");
        await acquireDriveWriteLock();

        // Re-check envelope after acquiring write lock (race protection)
        const raceCheck = await readEnvelopeFromDrive(C.ENVELOPE_NAME);

        if (raceCheck?.json) {
            log("SV.ensureEnvelope", "Envelope created by another device during lock escalation");
            return raceCheck.json;
        }
    }

    const selfKey = G.keyRegistry.flat.activeDevices.find(k => k.deviceId === self.deviceId);
    if (!selfKey) throw new Error("Active device public key not found for envelope genesis");

    const envelope = await createEnvelope(JSON.stringify(_createStarterVaultJson()), selfKey);
    return await writeEnvelopeWithLock(envelope);
}

export async function checkEnvelopeAuthorization() {
    log("SV.checkEnvelopeAuthorization", "called");

    /*
     * ============================================================
     * RECOVERY AUTHORIZATION PATH
     * ============================================================
     */
    if (G.recoverySession === true) {
        if (!G.recoveryCEK) {
            warn("SV.checkEnvelopeAuthorization", "Recovery session active but no session CEK present");
            return { authorized: false, reason: "Recovery CEK missing" };
        }

        log("SV.checkEnvelopeAuthorization", "Authorization granted via recovery session");
        return { authorized: true, entry: { role: "recovery-session" } };
    }

    /*
     * ============================================================
     * NORMAL DEVICE AUTHORIZATION
     * ============================================================
     */
    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);

    if (!envelopeFile?.json) {
        throw new Error("Envelope missing — cannot authorize");
    }

    const envelope = envelopeFile.json;

    try {
        const entry = await selectDecryptableKey(envelope);

        if (!entry) {
            throw new Error("No decryptable key entry found");
        }

        // 🔒 CRITICAL: actually try to unwrap CEK
        const cek = await unwrapContentKey(entry.wrappedKey, entry.keyId);

        if (!cek) {
            throw new Error("CEK unwrap returned null");
        }

        log("SV.checkEnvelopeAuthorization", `Authorization confirmed via keyId ${entry.keyId}`);
        return { authorized: true, entry };

    } catch (err) {
        warn("SV.checkEnvelopeAuthorization", "Device not authorized to decrypt envelope:", err.message);
        return { authorized: false, reason: err.message };
    }
}

export async function tryAcquireEnvelopeWriteLock(options = {}) {
    log("SV.tryAcquireEnvelopeWriteLock", "called");

    // Must already have driveLockState initialized
    if (!G.driveLockState) {
        warn("SV.tryAcquireEnvelopeWriteLock", "No driveLockState — cannot escalate");
        return false;
    }

    // Already write mode
    if (G.driveLockState.mode === "write") {
        info("SV.tryAcquireEnvelopeWriteLock", "Already in write mode");
        return true;
    }

    try {
        await acquireDriveWriteLock(options);
        info("SV.tryAcquireEnvelopeWriteLock", "Write lock acquired successfully");
        return true;
    } catch (err) {
        if (err.message?.includes("locked-by-other")) {
            warn("SV.tryAcquireEnvelopeWriteLock", "Lock held by another device — proceeding as read-only");
            return false;
        }

        // Unexpected failure should still surface
        error("SV.tryAcquireEnvelopeWriteLock", "Unexpected lock acquisition failure:", err.message);
        throw err;
    }
}

export function handleDriveLockLost(info) {
    warn("SV.handleDriveLockLost", "Reason:", info?.reason || "Timed out");

    if (G.driveLockState?.heartbeat) {
        G.driveLockState.heartbeat.stop();
    }

    G.driveLockState = null;
    updateLockStatusUI();
}

export async function writeLockToDrive(envelopeName, lockJson, existingFileId = null) {
    //trace("SV.writeLockToDrive", "called lockJson:", JSON.stringify(lockJson));

    const lockName = `${envelopeName}.lock`;

    if (existingFileId) {
        // ✅ Content-only update
        await GD.drivePatchJsonFile(existingFileId, lockJson);
        return existingFileId;
    }

    // ✅ New file creation
    return await GD.upsertJsonFile({
        name: lockName,
        parentId: C.ACCESS4_ROOT_ID,
        json: lockJson
    });
}

export async function wrapCEKForRegistryKeys(forceWrite = false) {

    log("SV.wrapCEKForRegistryKeys", "called");
    log("SV.wrapCEKForRegistryKeys", `G.unlockedIdentity: ${!!G.unlockedIdentity}, G.currentPrivateKey: ${!!G.currentPrivateKey}`);

    // HARD GUARD — must have private key loaded
    if (!G.currentPrivateKey) {
        throw new Error("wrapCEKForRegistryKeys called without private key loaded");
    }

    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile || !envelopeFile.json) {
        throw new Error("Envelope missing — cannot wrap CEK for registry");
    }

    const envelope = envelopeFile.json;

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
        G.recoveryCEK = null;   // null it immediately as it's role is done
    } else {
        const currentDeviceKeyEntry = await selectDecryptableKey(envelope);

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
        await writeEnvelopeSafely(envelope);
    } else {
        log("SV.wrapCEKForRegistryKeys", "Envelope up to date — skipping write");
    }

    return envelope;
}

//rename to registerRecoveryKey()
export async function addRecoveryKeyToEnvelope({ publicKey, keyId }) {
    log("SV.addRecoveryKeyToEnvelope", "called - Adding recovery key to envelope...");

    // 1️⃣ Load existing envelope from Drive
    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile) {
        throw new Error("Envelope missing — cannot add recovery key");
    }

    await assertEnvelopeWrite(C.ENVELOPE_NAME);

    const envelope = envelopeFile.json;

    // 2️⃣ Check if recovery key already exists
    if (envelope.keys?.some(k => k.role === "recovery" && k.keyId === keyId)) {
        warn("SV.addRecoveryKeyToEnvelope", "Recovery key already present in envelope, skipping add");
    } else {
        // 3️⃣ Select decryptable envelope entry safely
        log("SV.addRecoveryKeyToEnvelope", "Selecting decryptable envelope key...");
        const entry = await selectDecryptableKey(envelope);

        const cek = await unwrapContentKey(entry.wrappedKey, entry.keyId);
        log("SV.addRecoveryKeyToEnvelope", "CEK unwrapped");

        // 4️⃣ Wrap CEK for the new recovery key
        log("SV.addRecoveryKeyToEnvelope", "Wrapping CEK for recovery key...");

        let wrappedKey;
        try {
            wrappedKey = await wrapContentKeyForDevice(cek, publicKey);
            log("SV.addRecoveryKeyToEnvelope", "CEK wrapped for recovery key");
        } catch (err) {
            error("SV.addRecoveryKeyToEnvelope", "Error wrapping recovery CEK:", err);
            throw err;
        }

        const now = new Date().toISOString();

        // 5️⃣ Add recovery key to envelope
        envelope.keys.push({
            role:"recovery",
            keyId,
            wrappedKey,
            created: now,
            updated: null,
            publicKeyCreated: now
        });

        log("SV.addRecoveryKeyToEnvelope", "Added recovery key to envelope.keys:" + envelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));
    }

    // ---- Housekeeping CEK wrap for all devices & recovery keys (force write) ----
    if (G.driveLockState?.self && G.driveLockState.envelopeName === C.ENVELOPE_NAME) {
        log("SV.addRecoveryKeyToEnvelope", "Performing CEK housekeeping with force write");
        const updatedEnvelope = await wrapCEKForRegistryKeys(true); // <- forceWrite = true

        log("SV.addRecoveryKeyToEnvelope", "Updated envelope after wrapCEKForRegistryKeys:" + updatedEnvelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));

        // 6️⃣ Write updated envelope safely
        await writeEnvelopeSafely(updatedEnvelope);
    }

    log("SV.addRecoveryKeyToEnvelope", "Recovery key added to envelope and saved");
}

export async function encryptAndPersistPlaintext(plainText, options = {}) {
    log("SV.encryptAndPersistPlaintext", "called");

    // Ensure we own the lock
    if (!G.driveLockState || G.driveLockState.envelopeName !== C.ENVELOPE_NAME) {
        await acquireDriveWriteLock(options);
    }

    await assertEnvelopeWrite(C.ENVELOPE_NAME);

    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
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
    const written = await writeEnvelopeSafely(updatedEnvelope);

    info("SV.encryptAndPersistPlaintext", "Payload encrypted & written to envelope");
}

export async function loadEnvelopePayloadToUI(uiCallback) {
    log("SV.loadEnvelopePayloadToUI", "called - loading envelope payload from Drive");

    // 1️⃣ Read envelope file
    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile) {
        warn("️[E.loadEnvelopePayloadToUI", "Envelope file not found");
        return;
    }

    const envelope = envelopeFile.json;

    if (!envelope.payload) {
        log("SV.loadEnvelopePayloadToUI", "Envelope has no payload");
        return;
    }

    try {
        // 2️⃣ Decrypt payload using openEnvelope()
        const plaintext = await openEnvelope(envelope);

        //trace("SV.loadEnvelopePayloadToUI", `plaintext: |${plaintext}|`);

        // 3️⃣ Populate plaintext area in UI
        if (uiCallback)
            uiCallback(plaintext);

        log("SV.loadEnvelopePayloadToUI", "Payload loaded into plaintext UI");
    } catch (err) {
        error("SV.loadEnvelopePayloadToUI", "Failed to decrypt envelope payload:", err.message);
    }
}

/**
 * Logs envelope structure and optionally validates key usability.
 * Non-throwing, meant for debugging/testing multi-device/recovery envelopes.
 */
export async function logEnvelopeStatus(envelope, devicePrivateKey = null) {
    log("SV.logEnvelopeStatus", "called");

    if (!envelope) {
        console.warn("Envelope is null/undefined");
        return;
    }

    log("SV.logEnvelopeStatus", "Envelope Status");
    log("SV.logEnvelopeStatus", "Version:", envelope.version);
    log("SV.logEnvelopeStatus", "Number of keys:", envelope.keys?.length || 0);

    if (!Array.isArray(envelope.keys)) {
        warn("Keys property is not an array");
        return;
    }

    for (const k of envelope.keys) {
        log("SV.logEnvelopeStatus", `KeyId: ${k.keyId || "missing"}`);
        log("SV.logEnvelopeStatus", "Role:", k.role);
        log("SV.logEnvelopeStatus", "DeviceId:", k.deviceId || "(none)");
        log("SV.logEnvelopeStatus", "RecoveryId:", k.recoveryId || "(none)");
        log("SV.logEnvelopeStatus", "WrappedKey exists:", !!k.wrappedKey);

        if (devicePrivateKey && k.role === "device" && k.wrappedKey) {
            try {
                const cek = await CR.unwrapCEKWithPrivateKey(k.wrappedKey, devicePrivateKey);
                log("SV.logEnvelopeStatus", "CEK unwrap success ✅", cek.byteLength, "bytes");
            } catch (e) {
                error("CEK unwrap failed ❌", e.message);
            }
        }

        console.groupEnd();
    }

    console.groupEnd();
}

export async function validateEnvelopeDecryption(envelope, devicePrivateKey) {

    log("SV.validateEnvelopeDecryption", "called");

    const entry = envelope.keys.find(
        k => k.role === "device" && k.keyId === G.deviceId
    );

    if (!entry) {
        warn("No CEK entry for this device");
        return false;
    }

    try {

        const cek = await CR.unwrapCEKWithPrivateKey(
            entry.wrappedKey,
            devicePrivateKey
        );

        await CR.decrypt(envelope.payload, cek);

        info("Envelope decrypt validation SUCCESS");

        return true;

    } catch (err) {

        error("Envelope decrypt validation FAILED", err);

        return false;
    }
}

/**
 * Derives a unique AES-GCM key for a specific file using the Vault CEK.
 */
async function deriveFileKey(cek, fileUuid) {
    log("SV.deriveFileKey", `Deriving key for ${fileUuid}`);

    // We pass the CEK, a versioned salt, and the unique UUID.
    // normalizeBytes in CR handles the string-to-buffer conversion for us.
    return CR.deriveSubKey(cek, C.ATTACHMENT_FILEKEY_SALT, fileUuid);
}

/**
 * Encrypts a binary blob (Uint8Array) for Drive storage.
 */
export async function encryptAttachment(binaryData, fileUuid) {
    log("SV.encryptAttachment", "called");

    // Get the CEK (Borrowing your existing unwrap logic)
    const cek = await _getTransientCEK();

    // Derive the unique key for this specific UUID
    const fek = await deriveFileKey(cek, fileUuid);

    // Use existing CR.encrypt (it returns {iv, data} in B64)
    // NOTE: For large binaries, we convert to a flat Uint8Array for Drive efficiency
    const encrypted = await CR.encrypt(binaryData, fek);

    const ivBuf = CR.b64ToBuf(encrypted.iv);
    const dataBuf = CR.b64ToBuf(encrypted.data);

    // Combine into a single binary packet: [IV (12 bytes)][Ciphertext]
    const combined = new Uint8Array(ivBuf.length + dataBuf.length);
    combined.set(ivBuf, 0);
    combined.set(dataBuf, ivBuf.length);

    return combined;
}

// only use with logic that is okay to use the transients - attachment logic
async function _getTransientCEK() {
    if (!_transientEnvelope) {
        const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
        if (!envelopeFile?.json) {
            throw new Error("Active envelope not found on Drive.");
        }
        _transientEnvelope = envelopeFile.json;
    }

    return await getActiveCEK(_transientEnvelope);
}

/**
 * Decrypts a binary blob from Drive.
 */
export async function decryptAttachment(combinedBuffer, fileUuid) {
    log("SV.decryptAttachment", "called");

    const cek = await _getTransientCEK();
    const fek = await deriveFileKey(cek, fileUuid);

    const iv = combinedBuffer.slice(0, 12);
    const data = combinedBuffer.slice(12);

    // Reconstruct the format CR.decrypt expects
    const enc = {
        iv: CR.bufToB64(iv),
        data: CR.bufToB64(data)
    };

    return CR.decrypt(enc, fek);
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

    if (isTraceEnabled())
        trace("SV.getActiveCEK", "envelope:", envelope);

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

/**
 * Handles the encryption and Drive upload of an attachment.
 * Returns the metadata object to be stored in the Vault JSON.
 * @param {string} name - The display name/label for the file.
 * @param {Uint8Array} binary - The raw file bytes.
 * @param {string} mimeType - The original mime type (for metadata).
 */
/**
 * Refactored: Coordination only.
 * Cryptography is delegated to E.encryptAttachment.
 */
export async function saveAttachment(name, binary, mimeType) {
    log("SV.saveAttachment", `Processing: ${name}`);

    const fileUuid = CR.generateUUID();
    const encryptedBytes = await encryptAttachment(binary, fileUuid);

    // 1. Get the folder ID (this should be cached in G.attachmentsFolderId eventually)
    const folderId = await GD.findOrCreateFolder("attachments", C.ACCESS4_ROOT_ID);

    // --- TEMP DEV LOGIC ---
    const driveName = getDevDriveName(name);    //`${fileUuid}.bin`

    // 2. Use the new wrapper
    const driveFileId = await GD.upsertBinaryFile({
        name: driveName,/*`${fileUuid}.bin`,*/
        parentId: folderId,
        content: encryptedBytes,
        mimeType: "application/octet-stream"
    });

    // 3. Construct the Vault Entry
    // 'val' is now explicitly the driveFileId for direct access
    return {
        key: name,
        type: "file",
        val: driveFileId,
        uuid: fileUuid,
        oid: G.userId,
        meta: {
            size: binary.length,
            mime: mimeType,
            updated: new Date().toISOString(),
            uploadedBy: G.userEmail
        }
    };
}

/**
 * TEMPORARY DEV HELPER:
 * Creates a readable name for Google Drive to assist in testing.
 * REVERT THIS BEFORE PRODUCTION.
 */
function getDevDriveName(originalName) {
    const timestamp = new Date().toLocaleTimeString().replace(/:/g, '-');
    // We keep the original name but append 'DEV' and a time to avoid collisions
    return `DEV_${timestamp}_${originalName}.enc`;
}

/**
 * High-level coordinator to fetch and decrypt an attachment.
 * @param {Object} attachment - The attachment entry from the Vault JSON.
 * @returns {Uint8Array} - The decrypted file bytes.
 */
export async function openAttachment(attachment) {
    log("SV.openAttachment", `Fetching and decrypting: ${attachment.key}`);

    // 1. Fetch encrypted bytes via Drive (using your existing GD helper)
    // Note: ensure GD is imported at the top of server.js
    const buffer = await GD.readBinaryByFileId(attachment.val);
    const encryptedCombined = new Uint8Array(buffer);

    // 2. Perform the Decryption
    // This calls your decryptAttachment logic (getting CEK, deriving FEK, splitting IV)
    const plaintext = await decryptAttachment(encryptedCombined, attachment.uuid);

    return plaintext;
}

/**
 * Universal file removal: Tries permanent delete, falls back to trash.
 * Returns true if the file is gone or the attempt was made.
 */
export async function deleteAttachmentFile(fileId) {
    if (!fileId) return true;

    try {
        log("SV.deleteAttachmentFile", `Primary: Attempting DELETE for ${fileId}`);
        await GD.deleteFileById(fileId);
        return true;

    } catch (err) {
        // 1. EXTRACT THE CODE (Google often buries it in err.message or err.body)
        const errMsg = err.message || "";
        const statusCode = err.status || (errMsg.includes("403") ? 403 : errMsg.includes("405") ? 405 : 0);

        // 2. CHECK FOR PERMISSION/METHOD ERRORS
        if (statusCode === 403 || statusCode === 405 || errMsg.toLowerCase().includes("permission")) {
            warn("SV.deleteAttachmentFile", `DELETE blocked (${statusCode}). Trying Trash fallback...`);

            try {
                await GD.trashFileById(fileId);
                return true;
            } catch (trashErr) {
                // If even Trash fails, we've done our best.
                warn("SV.deleteAttachmentFile", `Ownership wall for ${fileId}. Skipping physical delete.`);
                return false; // This 'false' tells doSaveClick it was a handled skip
            }
        }

        // 3. IF 404, IT'S ALREADY GONE
        if (statusCode === 404 || errMsg.includes("404")) return true;

        // 4. REAL SYSTEM ERROR (Network down, Auth expired, etc)
        throw err;
    }
}