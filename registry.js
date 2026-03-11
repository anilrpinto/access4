"use strict";

import { G } from './global.js';

import * as E from './envelope.js';
import { log, trace, debug, info, warn, error } from './log.js';

export async function buildKeyRegistryFromDrive(rawPublicKeyJsons) {
    log("RG.buildKeyRegistryFromDrive", "called");

    resetKeyRegistry(); // keep global registry mutable

    for (const raw of rawPublicKeyJsons) {
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
