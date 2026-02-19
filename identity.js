"use strict";

import { C } from './constants.js';
import { G } from './global.js';
import * as ID from './identity.js';

import * as GD from './gdrive.js';

import { log, trace, debug, info, warn, error } from './log.js';

//buildIdentityFromKeypair

/* ---------------------- DEVICE ---------------------- */
export function getDeviceId() {
    let id = localStorage.getItem(C.DEVICE_ID_KEY);
    if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem(C.DEVICE_ID_KEY, id);
        log("[getDeviceId] New device ID generated");
    }
    return id;
}

function identityKey() {
    return `access4.identity::${G.userEmail}::${getDeviceId()}`;
}

export function saveIdentity(id) {
    localStorage.setItem(identityKey(), JSON.stringify(id));
}

export async function loadIdentity() {
    log("[loadIdentity] called");
    log("[loadIdentity] G.sessionUnlocked:", !!G.sessionUnlocked);
    log("[loadIdentity] G.unlockedIdentity:", !!G.unlockedIdentity);

    if (G.sessionUnlocked && G.unlockedIdentity) {
        log("[loadIdentity] Returning G.unlockedIdentity from memory");
        return G.unlockedIdentity;
    }

    return loadIdentityFromStorage();
}

function loadIdentityFromStorage() {
    log("[loadIdentityFromStorage] called");

    const raw = localStorage.getItem(identityKey());
    log("[loadIdentityFromStorage] Identity in localStorage exists:", !!raw);

    if (!raw) return null;

    try {
        const id = JSON.parse(raw);
        //trace("[loadIdentityFromStorage] Identity loaded from localStorage:", JSON.stringify(id));
        if (G.sessionUnlocked && G.currentPrivateKey) {
            id._sessionPrivateKey = G.currentPrivateKey;
        }
        return id;
    } catch (e) {
        error("❌ Failed to parse identity:", e);
        return null;
    }
}

/* ---------------------- PUBLIC KEY ---------------------- */
export async function ensureDevicePublicKey() {
    log("[ensureDevicePublicKey] called");

    const folder = await GD.findOrCreateUserFolder();
    const id = await ID.loadIdentity();
    if (!id) throw new Error("Local identity missing");

    const deviceId = ID.getDeviceId();
    const filename = `${G.userEmail}__${deviceId}.json`;

    const q = `'${folder}' in parents and name='${filename}'`;
    const res = await GD.driveFetch(GD.buildDriveUrl("files", { q, fields:"files(id)" }));

    // Compute fingerprint (canonical keyId)
    const pubBytes = Uint8Array.from(atob(id.publicKey), c => c.charCodeAt(0));
    const hashBuffer = await crypto.subtle.digest("SHA-256", pubBytes);
    const fingerprint = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

    const pubData = {
        version:"1",
        account: G.userEmail,
        deviceId,
        keyId: fingerprint,
        fingerprint,
        state:"active",
        role:"device",
        supersedes: id.supersedes || null,
        created: new Date().toISOString(),
        algorithm: {
            type:"RSA",
            usage: ["wrapKey"],
            modulusLength: 2048,
            hash:"SHA-256"
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

    if (res.files.length > 0) {
        const fileId = res.files[0].id;

        // --- PATCH only the content fields (Drive forbids updating certain metadata) ---
        const contentOnly = {
            publicKey: pubData.publicKey,
            state: pubData.state,
            supersedes: pubData.supersedes
        };

        await GD.driveFetch(GD.buildDriveUrl(`files/${fileId}`, { uploadType:"media" }), {
            method:"PATCH",
            headers: { "Content-Type":"application/json" },
            body: JSON.stringify(contentOnly)
        });

        log("[ensureDevicePublicKey] Device public key UPDATED");
        return;
    }

    // File doesn't exist → create new
    await GD.driveMultipartUpload({
        metadata: { name: filename, parents: [folder] },
        content: JSON.stringify(pubData)
    });

    log("[ensureDevicePublicKey] Device public key UPLOADED");
}