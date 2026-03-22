import { C, G, CR, RG, ID, GD, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { updateLockStatusUI }  from '@/ui/vault.js';

async function getDriveLockSelf() {
    log("E.getDriveLockSelf", "called");
    const identity = await ID.loadIdentity();
    if (!identity) throw new Error("Identity not unlocked — cannot ensure envelope");
    const self = { account: G.userEmail, deviceId: identity.deviceId };
    return { identity, self };
}

async function createEnvelope(plainText, devicePublicKeyRecord) {
    log("E.createEnvelope", "called");

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
    log("E.writeEnvelopeWithLock", "called");

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

        log("E.writeEnvelopeWithLock", `Envelope "${C.ENVELOPE_NAME}" written, generation=${newGeneration}`);
        return newEnvelopeContent;

    } catch (err) {
        error("writeEnvelopeWithLock", `Failed to write envelope "${C.ENVELOPE_NAME}": ${err.message}`);
        throw err;
    }
}

function evaluateEnvelopeLock(lock, self) {
    //trace("E.evaluateEnvelopeLock", "called");

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
    log("E.createLockPayload", "called");

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

    log("E.startLockHeartbeat", "called - args:", { readLockFromDrive, writeLockToDrive, onLost });

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
                trace("E.startLockHeartbeat.tick", `Heartbeat OK (gen=${extended.generation}, expires ${extended.expiresAt})`);
                updateLockStatusUI();
            }
        } catch (err) {
            const errorMessage = err instanceof Error ? err.stack : JSON.stringify(err, Object.getOwnPropertyNames(err));
            error("E.startLockHeartbeat.tick", "CRITICAL FAILURE:", errorMessage);

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

    log("E.unwrapContentKey", "called");
    const id = await ID.loadIdentity();
    if (!id) throw new Error("Local identity missing");

    // 1️⃣ Try current in-memory private key if keyId matches
    if (G.currentPrivateKey && keyId === id.fingerprint) {
        log("E.unwrapContentKey", `Using G.currentPrivateKey for keyId ${keyId}`);
        return CR.unwrapCEKWithPrivateKey(wrappedKeyBase64, G.currentPrivateKey);
    }

    // 2️⃣ Try decrypted previous keys from session
    if (id._decryptedPreviousKeys?.length) {
        const prev = id._decryptedPreviousKeys.find(k => k.fingerprint === keyId);
        if (prev) {
            log("E.unwrapContentKey", `Using decrypted previous key for keyId ${keyId}`);
            return CR.unwrapCEKWithPrivateKey(wrappedKeyBase64, prev.privateKey);
        }
    }

    // 3️⃣ Fallback: use G.currentPrivateKey even if fingerprint mismatch
    if (G.currentPrivateKey) {
        log("E.unwrapContentKey", `Fallback: using G.currentPrivateKey despite fingerprint mismatch for keyId ${keyId}`);
        return CR.unwrapCEKWithPrivateKey(wrappedKeyBase64, G.currentPrivateKey);
    }

    // 4️⃣ Nothing found
    error("E.unwrapContentKey", `No private key available for keyId ${keyId}`);
    throw new Error("No private key available for keyId:" + keyId);
}

async function openEnvelope(envelope) {
    log("E.openEnvelope", "called");

    validateEnvelope(envelope);

    const entry = await selectDecryptableKey(envelope);
    log("E.openEnvelope", `Using keyId: ${entry.keyId}`);

    const cek = await unwrapContentKey(entry.wrappedKey, entry.keyId);
    const decrypted = await CR.decrypt(envelope.payload, cek);

    return new TextDecoder().decode(decrypted);
}

async function selectDecryptableKey(envelope) {
    log("E.selectDecryptableKey", "called");

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
            warn("E.selectDecryptableKey", "Envelope encrypted with previous device key — rotation detected");
        }
        return deviceEntry;
    }

    // 2️⃣ Optional fallback: recovery key (NO deviceId expected)
    const recoveryEntry = envelope.keys.find(k => k.role === "recovery");

    if (recoveryEntry) {
        warn("E.selectDecryptableKey", "Falling back to recovery key for decryption");
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
    log("E.validateEnvelope", "called");

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
    log("E.wrapContentKeyForDevice", "called");

    const publicKey = await CR.importRSAPublicKeyFromB64(devicePublicKeyBase64, ["wrapKey"]);
    return await CR.wrapCEKForPublicKey(cek, publicKey);
}

async function writeEnvelopeSafely(envelopeData, maxRetries = 3, retryDelayMs = 1000) {
    log("E.writeEnvelopeSafely", "called");

    let attempt = 0;

    while (attempt < maxRetries) {
        attempt++;

        // Ensure we hold the lock
        if (!G.driveLockState || G.driveLockState.envelopeName !== C.ENVELOPE_NAME) {
            log("E.writeEnvelopeSafely", `Attempting to acquire lock for "${C.ENVELOPE_NAME}" (attempt ${attempt})`);
            try {
                await acquireDriveWriteLock();
            } catch (err) {
                warn("E.writeEnvelopeSafely", `Lock acquisition failed: ${err.message} retrying...`);
                await new Promise(r => setTimeout(r, retryDelayMs));
                continue;
            }
        }

        await assertEnvelopeWrite(C.ENVELOPE_NAME);

        try {
            const result = await writeEnvelopeWithLock(envelopeData);
            return result;
        } catch (err) {
            warn("E.writeEnvelopeSafely", `Write attempt failed: ${err.message} retrying...`);
            // If lock was lost mid-write, retry
            await new Promise(r => setTimeout(r, retryDelayMs));
        }
    }

    throw new Error(`Failed to write envelope "${C.ENVELOPE_NAME}" after ${maxRetries} attempts`);
}

async function assertEnvelopeWrite(envelopeName) {
    log("E.assertEnvelopeWrite", "called");

    if (!G.driveLockState) {
        throw new Error(`Cannot write: no drive lock state for "${envelopeName}"`);
    }

    if (G.driveLockState.envelopeName !== envelopeName) {
        throw new Error(`Cannot write: lock does not match envelope "${envelopeName}"`);
    }

    if (G.driveLockState.mode !== "write") {
        throw new Error(`Read-only session — write not permitted for envelope "${envelopeName}"`);
    }

    log("E.assertEnvelopeWrite", `Ownership confirmed for envelope "${envelopeName}"`);

    // Future housekeeping hook: missing device/recovery keys
    // log(`[housekeeping] Envelope ownership confirmed for "${envelopeName}"`);
}

async function acquireDriveWriteLock({ onUpdate = () => {} } = {}) {
    log("E.acquireDriveWriteLock", "called");

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

    log("E.acquireDriveWriteLock", "writing lock to Drive...");
    const fileId = await writeLockToDrive(C.ENVELOPE_NAME, lock, lockFile?.fileId);

    log("E.acquireDriveWriteLock", "lock written, fileId:", fileId);

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

    log("E.acquireDriveWriteLock", "completed");
    return G.driveLockState;
}

async function readLockFromDrive(envelopeName) {
    //trace("E.readLockFromDrive", "called");
    const lockName = `${envelopeName}.lock`;

    const file = await GD.findDriveFileByNameInRoot(lockName);
    if (!file) return null;

    const json = await GD.readJsonByFileId(file.id);

    return {
        fileId: file.id,
        json
    };
}

/**
 * EXPORTED FUNCTIONS
 */
export async function readEnvelopeFromDrive(envelopeName) {
    return GD.readJsonByName(envelopeName);
}

export async function ensureEnvelope() {
    log("E.ensureEnvelope", "called");

    // CACHE identity + self for this entire function
    const { identity, self } = await getDriveLockSelf();

    // ─── Fast path: skip lock re-acquire if already initialized ───
    if (G.driveLockState?.mode) {
        log("E.ensureEnvelope", "Drive lock already initialized — skipping lock acquisition");
        log("E.ensureEnvelope", "G.driveLockState:", JSON.stringify(G.driveLockState));
    } else {
        const lockFile = await readLockFromDrive(C.ENVELOPE_NAME);
        const result = evaluateEnvelopeLock(lockFile?.json, self);

        log("E.ensureEnvelope", "Envelope lock result.status:", result.status);

        if (result.status === "owned") {
            log("E.ensureEnvelope", "Envelope lock owned");
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile?.fileId, lock: lockFile?.json, self, mode:"write" };
        } else if (result.status === "locked") {
            log("E.ensureEnvelope", "Envelope locked by another device — entering read-only mode");
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile.fileId, lock: lockFile.json, self, mode:"read" };
        } else {
            log("E.ensureEnvelope", "No lock found — entering read mode (no auto-acquire)");
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile?.fileId ?? null, lock: lockFile?.json ?? null, self, mode: "read" };
        }
    }

    log("E.ensureEnvelope", `G.driveLockState - mode: ${G.driveLockState.mode} self.deviceId: ${G.driveLockState.self.deviceId}`);

    // 🔹 REF: do NOT assign frozen object to G.keyRegistry
    await RG.buildKeyRegistryFromDrive(); // updates mutable G.keyRegistry internally

    // Optional snapshot for read-only usage (UI or debug)
    const keyRegistrySnapshot = structuredClone(G.keyRegistry);

    //Uncomment only if UI consumes it
    //Object.freeze(keyRegistrySnapshot); // if you want deepFreeze, do it here

    log("E.ensureEnvelope", "activeDevices registry:", G.keyRegistry.flat.activeDevices.length);
    log("E.ensureEnvelope", "recoveryKeys registry:", G.keyRegistry.flat.recoveryKeys.length);

    if (!G.keyRegistry.flat.recoveryKeys.length)
    warn("E.ensureEnvelope", "WARNING: NO RECOVERY KEY ENTRY IN ENVELOPE. CREATE ONE IMMEDIATELY!!");

    // ─── Fast path: load existing envelope ───
    const existing = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (existing?.json) {
        log("E.ensureEnvelope", "Envelope already exists");
        return existing.json;
    }

    // ─── Genesis envelope path ───
    log("E.ensureEnvelope", "Envelope missing — creating genesis envelope");

    // GENESIS LOCK ESCALATION
    if (G.driveLockState.mode !== "write") {
        log("E.ensureEnvelope", "Genesis escalation — acquiring envelope write lock");
        await acquireDriveWriteLock();

        // Re-check envelope after acquiring write lock (race protection)
        const raceCheck = await readEnvelopeFromDrive(C.ENVELOPE_NAME);

        if (raceCheck?.json) {
            log("E.ensureEnvelope", "Envelope created by another device during lock escalation");
            return raceCheck.json;
        }
    }

    const selfKey = G.keyRegistry.flat.activeDevices.find(k => k.deviceId === self.deviceId);
    if (!selfKey) throw new Error("Active device public key not found for envelope genesis");

    const envelope = await createEnvelope(JSON.stringify({ initialized: true }), selfKey);
    return await writeEnvelopeWithLock(envelope);
}

export function normalizePublicKey(raw) {

    if (!raw || typeof raw !== "object") {
        throw new Error("Invalid public key JSON");
    }

    if (!raw.keyId || !raw.fingerprint || !raw.publicKey) {
        throw new Error("Missing required public key fields (keyId, fingerprint, publicKey)");
    }
    trace("E.normalizePublicKey", "fingerprint:", raw.fingerprint);

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

export async function checkEnvelopeAuthorization() {
    log("E.checkEnvelopeAuthorization", "called");

    /*
     * ============================================================
     * RECOVERY AUTHORIZATION PATH
     * ============================================================
     */
    if (G.recoverySession === true) {
        if (!G.recoveryCEK) {
            warn("E.checkEnvelopeAuthorization", "Recovery session active but no session CEK present");
            return { authorized: false, reason: "Recovery CEK missing" };
        }

        log("E.checkEnvelopeAuthorization", "Authorization granted via recovery session");
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

        log("E.checkEnvelopeAuthorization", `Authorization confirmed via keyId ${entry.keyId}`);
        return { authorized: true, entry };

    } catch (err) {
        warn("E.checkEnvelopeAuthorization", "Device not authorized to decrypt envelope:", err.message);
        return { authorized: false, reason: err.message };
    }
}

export async function tryAcquireEnvelopeWriteLock(options = {}) {
    log("E.tryAcquireEnvelopeWriteLock", "called");

    // Must already have driveLockState initialized
    if (!G.driveLockState) {
        warn("E.tryAcquireEnvelopeWriteLock", "No driveLockState — cannot escalate");
        return false;
    }

    // Already write mode
    if (G.driveLockState.mode === "write") {
        info("E.tryAcquireEnvelopeWriteLock", "Already in write mode");
        return true;
    }

    try {
        await acquireDriveWriteLock(options);
        info("E.tryAcquireEnvelopeWriteLock", "Write lock acquired successfully");
        return true;
    } catch (err) {
        if (err.message?.includes("locked-by-other")) {
            warn("E.tryAcquireEnvelopeWriteLock", "Lock held by another device — proceeding as read-only");
            return false;
        }

        // Unexpected failure should still surface
        error("E.tryAcquireEnvelopeWriteLock", "Unexpected lock acquisition failure:", err.message);
        throw err;
    }
}

export function handleDriveLockLost(info) {
    warn("E.handleDriveLockLost", "Reason:", info?.reason || "Timed out");

    if (G.driveLockState?.heartbeat) {
        G.driveLockState.heartbeat.stop();
    }

    G.driveLockState = null;
    updateLockStatusUI();
}

export async function writeLockToDrive(envelopeName, lockJson, existingFileId = null) {
    //trace("E.writeLockToDrive", "called lockJson:", JSON.stringify(lockJson));

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

    log("E.wrapCEKForRegistryKeys", "called");
    log("E.wrapCEKForRegistryKeys", `G.unlockedIdentity: ${!!G.unlockedIdentity}, G.currentPrivateKey: ${!!G.currentPrivateKey}`);

    // HARD GUARD — must have private key loaded
    if (!G.currentPrivateKey) {
        throw new Error("wrapCEKForRegistryKeys called without private key loaded");
    }

    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile || !envelopeFile.json) {
        throw new Error("Envelope missing — cannot wrap CEK for registry");
    }

    const envelope = envelopeFile.json;

    log("E.wrapCEKForRegistryKeys", "envelope keys count:" + (envelope?.keys?.length ?? 0));

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
            warn("E.wrapCEKForRegistryKeys", `Removing orphan keyId: ${entry.keyId}`);

            return exists;
        });

        if (envelope.keys.length !== originalLength) {
            updated = true;
            warn("E.wrapCEKForRegistryKeys", `Orphan CEK entries removed: ${originalLength - envelope.keys.length}`);
        }
    }

    log("E.wrapCEKForRegistryKeys", "Selecting device key entry...");
    log("E.wrapCEKForRegistryKeys", `G.userEmail: ${G.userEmail.slice(-12)}, self.deviceId: ${G.driveLockState?.self?.deviceId}`);

    /*
     * ============================================================
     * UNWRAP ELIGIBLE CEK
     * ============================================================
     */
    let cek;

    if (G.recoverySession === true && G.recoveryCEK) {
        log("E.wrapCEKForRegistryKeys", "Using recovery CEK (recovery mode)");
        cek = G.recoveryCEK;
        G.recoveryCEK = null;   // null it immediately as it's role is done
    } else {
        const currentDeviceKeyEntry = await selectDecryptableKey(envelope);

        if (!currentDeviceKeyEntry) {
            error("E.wrapCEKForRegistryKeys", "No device key available to unwrap CEK");
            throw new Error("Missing envelope CEK error] This user+device isn't authorized to access vault data yet");
        }

        log("E.wrapCEKForRegistryKeys", "Attempting CEK unwrap");
        log("E.wrapCEKForRegistryKeys", `Selected deviceId: ${currentDeviceKeyEntry.deviceId}, unwrap keyId: ${currentDeviceKeyEntry.keyId}, G.unlockedIdentity fingerprint: ${G.unlockedIdentity?.fingerprint}`);

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

        log("E.wrapCEKForRegistryKeys", `${role} keys updated: ${roleUpdated}, forceWrite: ${forceWrite}`);
    }

    /*
     * ============================================================
     * WRITE BACK IF UPDATED OR forceWrite
     * ============================================================
     */
    if (updated || forceWrite) {
        log("E.wrapCEKForRegistryKeys", "Envelope updated with wrapped keys — writing to Drive");
        await writeEnvelopeSafely(envelope);
    } else {
        log("E.wrapCEKForRegistryKeys", "Envelope up to date — skipping write");
    }

    return envelope;
}

//rename to registerRecoveryKey()
export async function addRecoveryKeyToEnvelope({ publicKey, keyId }) {
    log("E.addRecoveryKeyToEnvelope", "called - Adding recovery key to envelope...");

    // 1️⃣ Load existing envelope from Drive
    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile) {
        throw new Error("Envelope missing — cannot add recovery key");
    }

    await assertEnvelopeWrite(C.ENVELOPE_NAME);

    const envelope = envelopeFile.json;

    // 2️⃣ Check if recovery key already exists
    if (envelope.keys?.some(k => k.role === "recovery" && k.keyId === keyId)) {
        warn("E.addRecoveryKeyToEnvelope", "Recovery key already present in envelope, skipping add");
    } else {
        // 3️⃣ Select decryptable envelope entry safely
        log("E.addRecoveryKeyToEnvelope", "Selecting decryptable envelope key...");
        const entry = await selectDecryptableKey(envelope);

        const cek = await unwrapContentKey(entry.wrappedKey, entry.keyId);
        log("E.addRecoveryKeyToEnvelope", "CEK unwrapped");

        // 4️⃣ Wrap CEK for the new recovery key
        log("E.addRecoveryKeyToEnvelope", "Wrapping CEK for recovery key...");

        let wrappedKey;
        try {
            wrappedKey = await wrapContentKeyForDevice(cek, publicKey);
            log("E.addRecoveryKeyToEnvelope", "CEK wrapped for recovery key");
        } catch (err) {
            error("E.addRecoveryKeyToEnvelope", "Error wrapping recovery CEK:", err);
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

        log("E.addRecoveryKeyToEnvelope", "Added recovery key to envelope.keys:" + envelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));
    }

    // ---- Housekeeping CEK wrap for all devices & recovery keys (force write) ----
    if (G.driveLockState?.self && G.driveLockState.envelopeName === C.ENVELOPE_NAME) {
        log("E.addRecoveryKeyToEnvelope", "Performing CEK housekeeping with force write");
        const updatedEnvelope = await wrapCEKForRegistryKeys(true); // <- forceWrite = true

        log("E.addRecoveryKeyToEnvelope", "Updated envelope after wrapCEKForRegistryKeys:" + updatedEnvelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));

        // 6️⃣ Write updated envelope safely
        await writeEnvelopeSafely(updatedEnvelope);
    }

    log("E.addRecoveryKeyToEnvelope", "Recovery key added to envelope and saved");
}

export async function encryptAndPersistPlaintext(plainText, options = {}) {
    log("E.encryptAndPersistPlaintext", "called");

    // Ensure we own the lock
    if (!G.driveLockState || G.driveLockState.envelopeName !== C.ENVELOPE_NAME) {
        await acquireDriveWriteLock(options);
    }

    await assertEnvelopeWrite(C.ENVELOPE_NAME);

    // Load envelope
    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile?.json) {
        throw new Error("Envelope missing");
    }

    const envelope = envelopeFile.json;

    trace("E.encryptAndPersistPlaintext", "envelope:", envelope);

    // Unwrap CEK using this device
    const selfEntry = envelope.keys.find(k => k.deviceId === G.driveLockState.self.deviceId);

    if (!selfEntry) {
        throw new Error("No device key to unwrap CEK");
    }

    const cek = await unwrapContentKey(selfEntry.wrappedKey, selfEntry.keyId);

    // Encrypt new payload
    const payload = await CR.encrypt(plainText, cek);

    // Update envelope payload only
    const updatedEnvelope = {
        ...envelope,
        payload
    };

    // Persist safely (generation + lock heartbeat preserved)
    const written = await writeEnvelopeSafely(updatedEnvelope);

    info("E.encryptAndPersistPlaintext", "Payload encrypted & written to envelope");

    // Verify decrypt immediately (sanity + demo)
    //const decrypted = await openEnvelope(written);
    //log("E.encryptAndPersistPlaintext", "Decrypted payload:", decrypted);
}

export async function loadEnvelopePayloadToUI(uiCallback) {
    log("E.loadEnvelopePayloadToUI", "called - loading envelope payload from Drive");

    // 1️⃣ Read envelope file
    const envelopeFile = await readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile) {
        warn("️[E.loadEnvelopePayloadToUI", "Envelope file not found");
        return;
    }

    const envelope = envelopeFile.json;

    if (!envelope.payload) {
        log("E.loadEnvelopePayloadToUI", "Envelope has no payload");
        return;
    }

    try {
        // 2️⃣ Decrypt payload using openEnvelope()
        const plaintext = await openEnvelope(envelope);

        //trace("E.loadEnvelopePayloadToUI", `plaintext: |${plaintext}|`);

        // 3️⃣ Populate plaintext area in UI
        if (uiCallback)
            uiCallback(plaintext);

        log("E.loadEnvelopePayloadToUI", "Payload loaded into plaintext UI");
    } catch (err) {
        error("E.loadEnvelopePayloadToUI", "Failed to decrypt envelope payload:", err.message);
    }
}

/**
 * Logs envelope structure and optionally validates key usability.
 * Non-throwing, meant for debugging/testing multi-device/recovery envelopes.
 */
export async function logEnvelopeStatus(envelope, devicePrivateKey = null) {
    log("E.logEnvelopeStatus", "called");

    if (!envelope) {
        console.warn("Envelope is null/undefined");
        return;
    }

    log("E.logEnvelopeStatus", "Envelope Status");
    log("E.logEnvelopeStatus", "Version:", envelope.version);
    log("E.logEnvelopeStatus", "Number of keys:", envelope.keys?.length || 0);

    if (!Array.isArray(envelope.keys)) {
        warn("Keys property is not an array");
        return;
    }

    for (const k of envelope.keys) {
        log("E.logEnvelopeStatus", `KeyId: ${k.keyId || "missing"}`);
        log("E.logEnvelopeStatus", "Role:", k.role);
        log("E.logEnvelopeStatus", "DeviceId:", k.deviceId || "(none)");
        log("E.logEnvelopeStatus", "RecoveryId:", k.recoveryId || "(none)");
        log("E.logEnvelopeStatus", "WrappedKey exists:", !!k.wrappedKey);

        if (devicePrivateKey && k.role === "device" && k.wrappedKey) {
            try {
                const cek = await CR.unwrapCEKWithPrivateKey(k.wrappedKey, devicePrivateKey);
                log("E.logEnvelopeStatus", "CEK unwrap success ✅", cek.byteLength, "bytes");
            } catch (e) {
                error("CEK unwrap failed ❌", e.message);
            }
        }

        console.groupEnd();
    }

    console.groupEnd();
}

export async function validateEnvelopeDecryption(envelope, devicePrivateKey) {

    log("E.validateEnvelopeDecryption", "called");

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
