import { C, G, ID, CR, SV, GD, log, trace, debug, info, warn, error, isTraceEnabled } from '@/shared/exports.js';
import { updateLockStatusUI }  from '@/ui/vault.js';

export async function selectDecryptableKey(envelope) {
    log("EN.selectDecryptableKey", "called");

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
        return _keyMatchesOrIsSuperseded(k.keyId, id);
    });

    if (deviceEntry) {
        if (deviceEntry.keyId !== id.fingerprint) {
            warn("EN.selectDecryptableKey", "Envelope encrypted with previous device key — rotation detected");
        }
        return deviceEntry;
    }

    // 2️⃣ Optional fallback: recovery key (NO deviceId expected)
    const recoveryEntry = envelope.keys.find(k => k.role === "recovery");

    if (recoveryEntry) {
        warn("EN.selectDecryptableKey", "Falling back to recovery key for decryption");
        return recoveryEntry;
    }

    throw new Error("No decryptable key found for this device or recovery");
}

export async function readEnvelopeFromDrive() {
    return GD.readJsonByName(C.ENVELOPE_NAME);
}

export async function ensureEnvelope(deviceRecord) {
    log("EN.ensureEnvelope", "called");

    // 1️⃣ Get identity context (Local/Fast)
    const { identity, self } = await SV.getDriveLockSelf();

    // 2️⃣ Parallelize: Read Lock + Read Envelope (Saves ~700ms-1s)
    // We fetch both immediately. If the envelope exists, we're 90% done.
    const [lockFile, existingEnvelope] = await Promise.all([
        SV.readLockFromDrive().catch(() => null),
        readEnvelopeFromDrive().catch(() => null)
    ]);

    // 3️⃣ Set up G.driveLockState (Read-only initially)
    if (!G.driveLockState?.mode) {
        const result = SV.evaluateEnvelopeLock(lockFile?.json, self);

        if (result.status === "owned") {
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile?.fileId, lock: lockFile?.json, self, mode: "write" };
        } else if (result.status === "locked") {
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile.fileId, lock: lockFile.json, self, mode: "read" };
        } else {
            // Free or missing lock
            G.driveLockState = { envelopeName: C.ENVELOPE_NAME, fileId: lockFile?.fileId ?? null, lock: lockFile?.json ?? null, self, mode: "read" };
        }
    }

    // ─── 🚀 THE FAST PATH ───
    if (existingEnvelope?.json) {
        log("EN.ensureEnvelope", "Envelope found — returning for immediate render");
        return existingEnvelope.json;
    }

    // ─── 🐣 THE GENESIS PATH ───
    log("EN.ensureEnvelope", "No envelope found — starting GENESIS");

    // Must have write lock to create the first envelope
    if (G.driveLockState.mode !== "write") {
        log("EN.ensureEnvelope", "Genesis: Escalating to write lock...");
        await SV.acquireDriveWriteLock();

        // Double check for race conditions
        const raceCheck = await readEnvelopeFromDrive();
        if (raceCheck?.json) {
            log("EN.ensureEnvelope", "Envelope created by another device during lock escalation");
            return raceCheck.json;
        }
    }

    const envelope = await _createEnvelope(JSON.stringify(_createStarterVaultJson()), deviceRecord);
    return await _writeEnvelopeWithLock(envelope);
}

export async function checkEnvelopeAuthorization(envelope) {
    log("EN.checkEnvelopeAuthorization", "called");

    //RECOVERY AUTHORIZATION PATH
    if (G.recoverySession === true) {
        if (!G.recoveryCEK) {
            warn("EN.checkEnvelopeAuthorization", "Recovery session active but no session CEK present");
            return { authorized: false, reason: "Recovery CEK missing" };
        }

        log("EN.checkEnvelopeAuthorization", "Authorization granted via recovery session");
        return { authorized: true, entry: { role: "recovery-session" } };
    }

    //NORMAL DEVICE AUTHORIZATION
    try {
        const entry = await selectDecryptableKey(envelope);

        if (!entry) {
            throw new Error("No decryptable key entry found");
        }

        // CRITICAL: verify the device can actually unwrap the CEK
        // This ensures the local private key matches what's in the envelope
        const cek = await SV.unwrapContentKey(entry.wrappedKey, entry.keyId);

        if (!cek) {
            throw new Error("CEK unwrap returned null");
        }

        log("EN.checkEnvelopeAuthorization", `Authorization confirmed via keyId ${entry.keyId}`);
        return { authorized: true, entry };

    } catch (err) {
        warn("EN.checkEnvelopeAuthorization", "*** Device not authorized to decrypt envelope:" + err);
        return { authorized: false, reason: err.message };
    }
}

export async function registerRecoveryKey({ publicKey, keyId }) {
    log("EN.registerRecoveryKey", "called - Adding recovery key to envelope...");

    // 1️⃣ Load existing envelope from Drive
    const envelopeFile = await readEnvelopeFromDrive();
    if (!envelopeFile) {
        throw new Error("Envelope missing — cannot add recovery key");
    }

    await assertEnvelopeWrite(C.ENVELOPE_NAME);

    const envelope = envelopeFile.json;

    // 2️⃣ Check if recovery key already exists
    if (envelope.keys?.some(k => k.role === "recovery" && k.keyId === keyId)) {
        warn("EN.registerRecoveryKey", "Recovery key already present in envelope, skipping add");
    } else {
        // 3️⃣ Select decryptable envelope entry safely
        log("EN.registerRecoveryKey", "Selecting decryptable envelope key...");
        const entry = await selectDecryptableKey(envelope);

        const cek = await SV.unwrapContentKey(entry.wrappedKey, entry.keyId);
        log("EN.registerRecoveryKey", "CEK unwrapped");

        // 4️⃣ Wrap CEK for the new recovery key
        log("EN.registerRecoveryKey", "Wrapping CEK for recovery key...");

        let wrappedKey;
        try {
            wrappedKey = await SV.wrapContentKeyForDevice(cek, publicKey);
            log("EN.registerRecoveryKey", "CEK wrapped for recovery key");
        } catch (err) {
            error("EN.registerRecoveryKey", "Error wrapping recovery CEK:", err);
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

        log("EN.registerRecoveryKey", "Added recovery key to envelope.keys:" + envelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));
    }

    // ---- Housekeeping CEK wrap for all devices & recovery keys (force write) ----
    if (G.driveLockState?.self && G.driveLockState.envelopeName === C.ENVELOPE_NAME) {
        log("EN.registerRecoveryKey", "Performing CEK housekeeping with force write");
        const updatedEnvelope = await SV.wrapCEKForRegistryKeys(envelope, true); // <- forceWrite = true

        log("EN.registerRecoveryKey", "Updated envelope after wrapCEKForRegistryKeys:" + updatedEnvelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));

        // 6️⃣ Write updated envelope safely
        await writeEnvelopeSafely(updatedEnvelope);
    }

    log("EN.registerRecoveryKey", "Recovery key added to envelope and saved");
}

export async function writeEnvelopeSafely(envelopeData, maxRetries = 3, retryDelayMs = 1000) {
    log("EN.writeEnvelopeSafely", "called");

    let attempt = 0;

    while (attempt < maxRetries) {
        attempt++;

        // Ensure we hold the lock
        if (!G.driveLockState || G.driveLockState.envelopeName !== C.ENVELOPE_NAME) {
            log("EN.writeEnvelopeSafely", `Attempting to acquire lock for "${C.ENVELOPE_NAME}" (attempt ${attempt})`);
            try {
                await SV.acquireDriveWriteLock();
            } catch (err) {
                warn("EN.writeEnvelopeSafely", `Lock acquisition failed: ${err.message} retrying...`);
                await new Promise(r => setTimeout(r, retryDelayMs));
                continue;
            }
        }

        await assertEnvelopeWrite(C.ENVELOPE_NAME);

        try {
            const result = await _writeEnvelopeWithLock(envelopeData);
            return result;
        } catch (err) {
            warn("EN.writeEnvelopeSafely", `Write attempt failed: ${err.message} retrying...`);
            // If lock was lost mid-write, retry
            await new Promise(r => setTimeout(r, retryDelayMs));
        }
    }

    throw new Error(`Failed to write envelope "${C.ENVELOPE_NAME}" after ${maxRetries} attempts`);
}

export async function assertEnvelopeWrite(envelopeName) {
    log("EN.assertEnvelopeWrite", "called");

    if (!G.driveLockState) {
        throw new Error(`Cannot write: no drive lock state for "${envelopeName}"`);
    }

    if (G.driveLockState.envelopeName !== envelopeName) {
        throw new Error(`Cannot write: lock does not match envelope "${envelopeName}"`);
    }

    if (G.driveLockState.mode !== "write") {
        throw new Error(`Read-only session — write not permitted for envelope "${envelopeName}"`);
    }

    log("EN.assertEnvelopeWrite", `Ownership confirmed for envelope "${envelopeName}"`);

    // Future housekeeping hook: missing device/recovery keys
    // log(`[housekeeping] Envelope ownership confirmed for "${envelopeName}"`);
}

export async function loadEnvelopePayloadToUI(envelope, uiCallback) {
    log("EN.loadEnvelopePayloadToUI", "called");

    if (!envelope.payload) {
        log("EN.loadEnvelopePayloadToUI", "Envelope has no payload");
        return;
    }

    try {
        // 2️⃣ Decrypt payload using _openEnvelope()
        const plaintext = await _openEnvelope(envelope);

        //trace("EN.loadEnvelopePayloadToUI", `plaintext: |${plaintext}|`);

        // 3️⃣ Populate plaintext area in UI
        if (uiCallback)
            uiCallback(plaintext);

        log("EN.loadEnvelopePayloadToUI", "Payload loaded into plaintext UI");
    } catch (err) {
        error("EN.loadEnvelopePayloadToUI", "Failed to decrypt envelope payload:", err.message);
    }
}

/**
 * Logs envelope structure and optionally validates key usability.
 * Non-throwing, meant for debugging/testing multi-device/recovery envelopes.
 */
export async function logEnvelopeStatus(envelope, devicePrivateKey = null) {
    log("EN.logEnvelopeStatus", "called");

    if (!envelope) {
        console.warn("Envelope is null/undefined");
        return;
    }

    log("EN.logEnvelopeStatus", "Envelope Status");
    log("EN.logEnvelopeStatus", "Version:", envelope.version);
    log("EN.logEnvelopeStatus", "Number of keys:", envelope.keys?.length || 0);

    if (!Array.isArray(envelope.keys)) {
        warn("Keys property is not an array");
        return;
    }

    for (const k of envelope.keys) {
        log("EN.logEnvelopeStatus", `KeyId: ${k.keyId || "missing"}`);
        log("EN.logEnvelopeStatus", "Role:", k.role);
        log("EN.logEnvelopeStatus", "DeviceId:", k.deviceId || "(none)");
        log("EN.logEnvelopeStatus", "RecoveryId:", k.recoveryId || "(none)");
        log("EN.logEnvelopeStatus", "WrappedKey exists:", !!k.wrappedKey);

        if (devicePrivateKey && k.role === "device" && k.wrappedKey) {
            try {
                const cek = await CR.unwrapCEKWithPrivateKey(k.wrappedKey, devicePrivateKey);
                log("EN.logEnvelopeStatus", "CEK unwrap success ✅", cek.byteLength, "bytes");
            } catch (e) {
                error("CEK unwrap failed ❌", e.message);
            }
        }

        console.groupEnd();
    }

    console.groupEnd();
}

export async function validateEnvelopeDecryption(envelope, devicePrivateKey) {
    log("EN.validateEnvelopeDecryption", "called");

    const entry = envelope.keys.find(k => k.role === "device" && k.keyId === G.deviceId);

    if (!entry) {
        warn("No CEK entry for this device");
        return false;
    }

    try {

        const cek = await CR.unwrapCEKWithPrivateKey(entry.wrappedKey, devicePrivateKey);

        await CR.decrypt(envelope.payload, cek);
        info("Envelope decrypt validation SUCCESS");
        return true;

    } catch (err) {
        error("Envelope decrypt validation FAILED", err);
        return false;
    }
}

/** INTERNAL FUNCTIONS **/
async function _createEnvelope(plainText, devicePublicKeyRecord) {
    log("EN._createEnvelope", "called");

    // 1️⃣ Generate the master Content Encryption Key (CEK)
    const cek = await CR.generateCEK();

    // 2️⃣ Encrypt the initial vault JSON (the "Starter" data)
    const payload = await CR.encrypt(plainText, cek);

    // 3️⃣ Wrap the CEK for this specific device immediately
    // Note: identity.publicKey is already the Base64/PEM data needed
    const wrappedKey = await SV.wrapContentKeyForDevice(cek, devicePublicKeyRecord.publicKey.data);

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

async function _openEnvelope(envelope) {
    log("EN._openEnvelope", "called");

    _validateEnvelope(envelope);

    let cek = null;

    // ✅ Use the recovery CEK if it's there, otherwise do the standard unwrap
    if (G.recoverySession && G.recoveryCEK) {
        cek = G.recoveryCEK;
    } else {
        const entry = await selectDecryptableKey(envelope);
        log("EN._openEnvelope", `Using keyId: ${entry.keyId}`);
        cek = await SV.unwrapContentKey(entry.wrappedKey, entry.keyId);
    }

    const decrypted = await CR.decrypt(envelope.payload, cek);

    return new TextDecoder().decode(decrypted);
}

function _keyMatchesOrIsSuperseded(entryKeyId, localIdentity) {
    if (!localIdentity?.fingerprint) return false;
    // Exact match (current key)
    if (entryKeyId === localIdentity.fingerprint) return true;
    // Superseded key (previous rotation)
    if (localIdentity.previousKeys?.some(k => k.fingerprint === entryKeyId)) return true;
    return false;
}

function _createStarterVaultJson() {
    return {
        "meta": {
            "version": "1.0",
            "lastModified": null,
            "type": "shared",
            "extensions": {
                "private_vaults": {}
            }
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

function _validateEnvelope(envelope) {
    log("EN._validateEnvelope", "called");

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

async function _writeEnvelopeWithLock(envelopeData) {
    log("EN._writeEnvelopeWithLock", "called");

    // 🛡️ If we are still "waiting for the 4s lock" from login, pause here.
    if (G.lockAcquisitionPromise) {
        log("EN._writeEnvelopeWithLock", "Write requested but lock still pending... pausing for sync.");
        await G.lockAcquisitionPromise;
        log("EN._writeEnvelopeWithLock", "Lock sync complete, proceeding with write.");
    }

    await assertEnvelopeWrite(C.ENVELOPE_NAME);

    try {

        // 1️⃣ Read envelope (includes fileId)
        const existing = await readEnvelopeFromDrive();

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

        await SV.writeLockToDrive(G.driveLockState.lock, G.driveLockState.fileId);

        // Update UI to reflect new lock generation
        updateLockStatusUI();

        log("EN._writeEnvelopeWithLock", `Envelope "${C.ENVELOPE_NAME}" written, generation=${newGeneration}`);
        return newEnvelopeContent;

    } catch (err) {
        error("_writeEnvelopeWithLock", `Failed to write envelope "${C.ENVELOPE_NAME}": ${err.message}`);
        throw err;
    }
}
