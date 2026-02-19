"use strict";

import { C } from './constants.js';
import { G } from './global.js';

import * as ID from './identity.js';
import * as GD from './gdrive.js';
import * as UI from './ui.js';

import { log, trace, debug, info, warn, error } from './log.js';

export async function ensureEnvelope() {
    log("[ensureEnvelope] called");
    const envelopeName = "envelope.json";

    // ─── Fast path: skip lock re-acquire if already initialized ───
    if (G.driveLockState && G.driveLockState.mode) {
        log("[ensureEnvelope] Drive lock already initialized — skipping lock acquisition");
        log("[ensureEnvelope] G.driveLockState:", JSON.stringify(G.driveLockState));
    } else {
        const lockFile = await GD.readLockFromDrive(envelopeName);
        const { identity, self } = await getDriveLockSelf();
        const evalResult = evaluateEnvelopeLock(lockFile?.json, self);

        if (evalResult.status === "owned") {
            G.driveLockState = { envelopeName, fileId: lockFile?.fileId, lock: lockFile?.json, self, mode:"write" };
        } else if (evalResult.status === "locked") {
            log("[ensureEnvelope] Envelope locked by another device — entering read-only mode");
            G.driveLockState = { envelopeName, fileId: lockFile.fileId, lock: lockFile.json, self, mode:"read" };
        } else {
            await acquireDriveWriteLock(envelopeName);
        }
    }

    log("[ensureEnvelope] Drive mode:", G.driveLockState.mode);
    log("[ensureEnvelope] Drive self deviceId:", G.driveLockState.self.deviceId);

    // ─── Load key registry from pub-keys on Drive ───
    const rawPublicKeyJsons = await GD.loadPublicKeyJsonsFromDrive();
    G.keyRegistry = await buildKeyRegistryFromDrive(rawPublicKeyJsons);

    log("[ensureEnvelope] Active devices registry:", G.keyRegistry.flat.activeDevices.length);
    log("[ensureEnvelope] recoveryKeys registry:", G.keyRegistry.flat.recoveryKeys.length);

    // ─── Fast path: load existing envelope ───
    const existing = await GD.readEnvelopeFromDrive(envelopeName);
    if (existing?.json) {
        log("[ensureEnvelope] Envelope already exists");
        return existing.json;
    }

    // ─── Genesis envelope path ───
    log("[ensureEnvelope] Envelope missing — creating genesis envelope");
    const { identity } = await getDriveLockSelf();
    const selfKey = G.keyRegistry.flat.activeDevices.find(k => k.deviceId === identity.deviceId);
    if (!selfKey) throw new Error("Active device public key not found for envelope genesis");

    const envelope = await createEnvelope(JSON.stringify({ initialized: true }), selfKey);
    return await writeEnvelopeWithLock(envelopeName, envelope);
}

async function buildKeyRegistryFromDrive(rawPublicKeyJsons) {
    log("[buildKeyRegistryFromDrive] called");

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
        warn("[buildKeyRegistryFromDrive] Key registry validation warning:", e.message);
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
    trace("[normalizePublicKey] fingerprint:", raw.fingerprint);

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
    log("[resetKeyRegistry] called");
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
    trace("[registerPublicKey] for fingerprint:", key.fingerprint);

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
    log("[validateKeyRegistry] called");

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
    log("[resolveEffectiveActiveDevices] called");

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
    log("[getDriveLockSelf] called");
    const identity = await ID.loadIdentity();
    if (!identity) throw new Error("Identity not unlocked — cannot ensure envelope");
    const self = { account: G.userEmail, deviceId: identity.deviceId };
    return { identity, self };
}

function evaluateEnvelopeLock(lock, self) {
    //trace("[evaluateEnvelopeLock] called");

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
    log("[acquireDriveWriteLock] called");

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

    log("[acquireDriveWriteLock] writing lock to Drive...");
    const fileId = await GD.writeLockToDrive(C.ENVELOPE_NAME, lock, lockFile?.fileId);

    log("[acquireDriveWriteLock] lock written, fileId:", fileId);

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

    log("[acquireDriveWriteLock] completed");
    return G.driveLockState;
}

function createLockPayload(self, generation) {
    log("[createLockPayload] called");

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

    log("[startLockHeartbeat] args:", { readLockFromDrive, writeLockToDrive, onLost });

    let stopped = false;

    const tick = async () => {
        if (stopped) return;

        try {

            const lockFile = await readLockFromDrive(envelopeName);
            const diskLock = lockFile?.json;

            const evalResult = evaluateEnvelopeLock(diskLock, self);
            if (evalResult.status !== "owned") {
                stopped = true;
                onLost?.(evalResult);
                return;
            }

            // 🔑 MERGE: never allow generation to move backwards
            const mergedLock = {
                ...diskLock,
                generation: Math.max(
                    diskLock?.generation ?? 0,
                    G.driveLockState?.lock?.generation ?? 0
                )
            };

            const extended = extendLock(mergedLock, C.LOCK_TTL_MS);

            if (extended.generation < G.driveLockState.lock.generation) {
                throw new Error("Heartbeat attempted to regress generation");
            }

            await writeLockToDrive(
                envelopeName,
                extended,
                lockFile.fileId
            );

            G.driveLockState.lock = extended;   // keep local state authoritative
            //debug(`[startLockHeartbeat.tick] Heartbeat OK (gen=${extended.generation}, expires ${extended.expiresAt})`);
            UI.updateLockStatusUI();
        } catch (err) {
            error("[startLockHeartbeat.tick] err:", err);
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
    warn("[handleDriveLockLost] Drive lock lost:", JSON.stringify(info));

    if (G.driveLockState?.heartbeat) {
        G.driveLockState.heartbeat.stop();
    }

    G.driveLockState = null;

    UI.updateLockStatusUI();
}