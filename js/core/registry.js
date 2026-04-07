import { C, G, LS, GD, log, trace, debug, info, warn, error } from '@/shared/exports.js';

function resetKeyRegistry() {
    log("RG.resetKeyRegistry", "called");

    // Fully mutable global registry
    G.keyRegistry.accounts = {};
    G.keyRegistry.flat = {
        activeDevices: [],
        deprecatedDevices: [],
        recoveryKeys: []
    };
    G.keyRegistry.loadedAt = new Date().toISOString();
}

function registerPublicKey(key) {

    if (!key || !key.fingerprint) {
        throw new Error("Cannot register invalid key");
    }
    trace("RG.registerPublicKey", "for fingerprint:", key.fingerprint);

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
    log("RG.validateKeyRegistry", "called");

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
    log("RG.resolveEffectiveActiveDevices", "called");

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

async function loadPublicKeyJsonsFromDrive() {

    log("RG.loadPublicKeyJsonsFromDrive", "called");

    const rawKeys = [];

    const pubKeysRoot = await GD.findOrCreateFolder(C.PUBKEY_FOLDER_NAME, C.ACCESS4_ROOT_ID);
    const accountFolders = await GD.listFolders(pubKeysRoot);

    for (const folder of accountFolders) {
        const jsons = await GD.readJsonFilesFromFolder(folder.id);
        rawKeys.push(...jsons);
    }

    const recoveryFolder = await GD.findDriveFileByNameInFolder("recovery", C.ACCESS4_ROOT_ID);

    if (recoveryFolder) {
        const recovery = await GD.readJsonByName(C.RECOVERY_KEY_PUBLIC_FILE, recoveryFolder.id);

        if (recovery)
            rawKeys.push(recovery.json);
    }

    // filtering step remains
    const superseded = new Set();

    for (const key of rawKeys)
        if (key.supersedes)
            superseded.add(key.supersedes);

    const publicKeyJsons = rawKeys.filter(k => k.state !== "revoked" && !superseded.has(k.keyId));

    log("RG.loadPublicKeyJsonsFromDrive", `Loaded ${publicKeyJsons.length} active public keys`);

    return publicKeyJsons;
}

function normalizePublicKey(raw) {

    if (!raw || typeof raw !== "object") {
        throw new Error("Invalid public key JSON");
    }

    if (!raw.keyId || !raw.fingerprint || !raw.publicKey) {
        throw new Error("Missing required public key fields (keyId, fingerprint, publicKey)");
    }
    trace("RG.normalizePublicKey", "fingerprint:", raw.fingerprint);

    return {

        // --- SYNC METADATA (CRITICAL FOR JANITOR) ---
        // We preserve these if they were already attached by the sync logic
        fileId: raw.fileId || null,
        syncedAt: raw.syncedAt || null,

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

/**
 * EXPORTED FUNCTIONS
 */
export async function buildKeyRegistryFromDrive() {
    log("RG.buildKeyRegistryFromDrive", "called");

    resetKeyRegistry(); // keep global registry mutable

    const publicKeyJsons = await loadPublicKeyJsonsFromDrive();

    for (const raw of publicKeyJsons) {
        const normalized = normalizePublicKey(raw);
        if (!normalized) continue; // skip invalid
        registerPublicKey(normalized);
    }

    G.keyRegistry.loadedAt = new Date().toISOString();

    // Validate structural integrity
    try {
        validateKeyRegistry(G.keyRegistry);
    } catch (err) {
        warn("RG.buildKeyRegistryFromDrive", "Key registry validation warning:", err.message);
    }

    // Resolve terminal active devices
    const activeDevices = resolveEffectiveActiveDevices(G.keyRegistry.flat);

    // Frozen snapshot for read-only use elsewhere (do NOT assign to G.keyRegistry)
    const snapshot = structuredClone(G.keyRegistry);
    snapshot.flat.activeDevices = Object.freeze(activeDevices.map(d => Object.freeze(d)));
    snapshot.flat.deprecatedDevices = Object.freeze(snapshot.flat.deprecatedDevices.map(d => Object.freeze(d)));
    snapshot.flat.recoveryKeys = Object.freeze(snapshot.flat.recoveryKeys.map(d => Object.freeze(d)));

    return snapshot; // assign to local var if needed, not G.keyRegistry
}

export function saveRegistryToCache() {
    try {
        // 1️⃣ Ensure we are saving the most recent resolved state
        const activeDevices = resolveEffectiveActiveDevices(G.keyRegistry.flat);

        const cacheData = {
            registry: G.keyRegistry,
            // 2️⃣ Save the snapshot so the UI can render instantly on reload
            snapshot: activeDevices,
            timestamp: new Date().getTime(),
            version: "1.0" // Good practice for future migrations
        };

        LS.set(C.REGISTRY_CACHE_KEY, JSON.stringify(cacheData));
        log("RG.saveRegistryToCache", `Cached ${activeDevices.length} active devices.`);
    } catch (err) {
        // Handle QuotaExceededError (rare for this small JSON, but safe)
        warn("RG.saveRegistryToCache", "Failed to cache registry:", err.message);
    }
}

/**
 * Loads the registry from local storage into G.keyRegistry.
 */
export function loadRegistryFromCache() {
    try {
        const raw = LS.get(C.REGISTRY_CACHE_KEY);
        if (!raw) {
            log("RG.loadRegistryFromCache", "No cache found, initializing empty registry");
            resetKeyRegistry(); // Ensure G.keyRegistry structure exists
            return false;
        }

        const cache = JSON.parse(raw);
        G.keyRegistry = cache.registry;

        // Re-resolve snapshots so UI-bound variables are ready
        G.activeDevicesSnapshot = cache.snapshot ||  resolveEffectiveActiveDevices(G.keyRegistry.flat);

        log("RG.loadRegistryFromCache", `Restored ${G.keyRegistry.flat.activeDevices.length} keys from cache`);
        return true;
    } catch (err) {
        warn("RG.loadRegistryFromCache", "Cache load failed:", err.message);
        resetKeyRegistry();
        return false;
    }
}

/**
 * Background Janitor Task: Syncs the Registry using metadata deltas.
 */
export async function syncRegistryDeltas(forceFullScan = false) {
    log("RG.syncRegistryDeltas", "Checking for key updates...");

    let updateFound = false;

    // If we are doing a full scan, we should reset our "Active" list
    // to ensure we don't keep local "ghost" devices that were deleted from Drive.
    if (forceFullScan) {
        G.keyRegistry.flat.activeDevices = [];
        G.keyRegistry.flat.recoveryKeys = [];
    }

    // 1️⃣ SYNC USER DEVICE KEYS (pub-keys/email/file.json)
    const pubKeysRoot = await GD.findOrCreateFolder(C.PUBKEY_FOLDER_NAME, C.ACCESS4_ROOT_ID);
    const accountFolders = await GD.listFolders(pubKeysRoot);

    for (const folder of accountFolders) {
        // We only ask for ID, Name, and ModifiedTime (Very small network footprint)
        const driveFiles = await GD.listJsonFiles(folder.id, "files(id, name, modifiedTime)");

        for (const file of driveFiles) {
            // Find if we already have this file in our flat list
            const existing = [
                ...G.keyRegistry.flat.activeDevices,
                ...G.keyRegistry.flat.deprecatedDevices
            ].find(k => k.fileId === file.id);

            const isModified = !existing || new Date(file.modifiedTime) > new Date(existing.syncedAt);

            if (forceFullScan || isModified) {
                log("RG.syncRegistryDeltas", `Authoritative fetch: ${file.name}`);
                const data = await GD.readJsonByFileId(file.id);
                const normalized = normalizePublicKey(data.json);

                // Attach sync metadata so we don't fetch it again next time
                normalized.fileId = file.id;
                normalized.syncedAt = file.modifiedTime;

                registerPublicKey(normalized);
                updateFound = true;
            }
        }
    }

    // 2️⃣ SYNC RECOVERY PUBLIC KEY (recovery/recovery.public.json)
    const recoveryFolder = await GD.findDriveFileByNameInFolder("recovery", C.ACCESS4_ROOT_ID);
    if (recoveryFolder) {
        // We look for the specific public file
        const recFile = await GD.findDriveFileByNameInFolder(C.RECOVERY_KEY_PUBLIC_FILE, recoveryFolder.id);

        if (recFile) {
            const existingRec = G.keyRegistry.flat.recoveryKeys.find(k => k.fileId === recFile.id);

            const isModifiedRec = !existingRec || new Date(recFile.modifiedTime) > new Date(existingRec.syncedAt);

            if (forceFullScan || isModifiedRec) {
                log("RG.syncRegistryDeltas", "Fetching updated Recovery Public Key");
                const dataRec = await GD.readJsonByFileId(recFile.id);
                const normalizedRec = normalizePublicKey(dataRec.json);

                normalizedRec.fileId = recFile.id;
                normalizedRec.syncedAt = recFile.modifiedTime;

                registerPublicKey(normalizedRec);
                updateFound = true;
            }
        }
    }

    // 3️⃣ FINALIZE
    // If we did a full scan, we MUST resolve the snapshot even if no "new" files were found,
    // because the "Full Scan" itself is the update.
    if (updateFound || forceFullScan) {
        saveRegistryToCache();
        G.activeDevicesSnapshot = resolveEffectiveActiveDevices(G.keyRegistry.flat);
        log("RG.syncRegistryDeltas", "Registry sync complete (Authoritative).");
    } else {
        log("RG.syncRegistryDeltas", "No updates found on Drive.");
    }
}



/*  //Referenced within ID.rotateDeviceIdentity() -
    //DO NOT DELETE but may need refinement in the current context when uncommented

    async function markPreviousDriveKeyDeprecated(oldFingerprint, newFingerprint) {
    log("GD.markPreviousDriveKeyDeprecated", "called");

    const folder = await findOrCreateUserFolder();
    const filenamePattern = `${G.userEmail}__`; // all device keys for this user
    const q = `'${folder}' in parents and name contains '${filenamePattern}'`;
    const res = await _driveFetch(_buildDriveUrl("files", { q, fields:"files(id,name)" }));

    if (!res.files.length) {
        log("GD.markPreviousDriveKeyDeprecated", "no drive files found to mark keys as deprecated");
        return; // nothing to patch
    }

    for (const file of res.files) {
        const fileData = await _driveFetch(_buildDriveUrl(`files/${file.id}`, { alt:"media" }));
        if (fileData.keyId !== oldFingerprint) continue; // not the old key

        // --- PATCH only mutable fields ---
        const patchData = {
            state:"deprecated",
            supersededBy: newFingerprint
        };

        await _driveFetch(_buildDriveUrl(`files/${file.id}`, { uploadType:"media" }), {
            method:"PATCH",
            headers: { "Content-Type":"application/json" },
            body: JSON.stringify(patchData)
        });

        log("GD.markPreviousDriveKeyDeprecated", `Marked keyId (${oldFingerprint}) as deprecated in file:${file.id}`);
    }
}*/