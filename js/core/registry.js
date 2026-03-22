import { C, G, E, GD, log, trace, debug, info, warn, error } from '@/shared/exports.js';

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

/**
 * EXPORTED FUNCTIONS
 */
export async function buildKeyRegistryFromDrive() {
    log("RG.buildKeyRegistryFromDrive", "called");

    resetKeyRegistry(); // keep global registry mutable

    // ─── Load key registry from pub-keys on Drive ───
    const publicKeyJsons = await loadPublicKeyJsonsFromDrive();

    for (const raw of publicKeyJsons) {
        const normalized = E.normalizePublicKey(raw);
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

    // 🔒 Frozen snapshot for read-only use elsewhere (do NOT assign to G.keyRegistry)
    const snapshot = structuredClone(G.keyRegistry);
    snapshot.flat.activeDevices = Object.freeze(activeDevices.map(d => Object.freeze(d)));
    snapshot.flat.deprecatedDevices = Object.freeze(snapshot.flat.deprecatedDevices.map(d => Object.freeze(d)));
    snapshot.flat.recoveryKeys = Object.freeze(snapshot.flat.recoveryKeys.map(d => Object.freeze(d)));

    return snapshot; // assign to local var if needed, not G.keyRegistry
}

/*async function markPreviousDriveKeyDeprecated(oldFingerprint, newFingerprint) {
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