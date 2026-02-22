"use strict";

import { C } from './constants.js';
import { G } from './global.js';

import * as ID from './identity.js';
import * as GD from './gdrive.js';
import * as UI from './ui.js';

import { log, trace, debug, info, warn, error } from './log.js';

export function initGIS() {

    log("[AU.initGIS] called");

    G.tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: C.CLIENT_ID,
        scope: C.SCOPES,
        callback: handleAuth
    });

    if (G.gisPrompt) {
        // Promts for accounts regardless (helpful in switching account)
        G.tokenClient.requestAccessToken({ prompt:"consent select_account" })
    } else {
        // Do not prompt for choosing other accounts if atleast one is signed in to Google already
        G.tokenClient.requestAccessToken({ prompt:"" });
    }

    UI.signinBtn.disabled = true;
}

async function handleAuth(resp) {
    log("[AU.handleAuth] called");

    if (resp.error) return;

    G.accessToken = resp.access_token;
    log(`[handleAuth] Access token acquired ${G.accessToken}`);

    await GD.fetchUserEmail();
    await GD.verifySharedRoot(C.ACCESS4_ROOT_ID);
    await GD.verifyWritable(C.ACCESS4_ROOT_ID);
    await ensureAuthorization();

    if (!isSessionAuthenticated())
        UI.promptUnlockPasword();

    G.biometricRegistered = !!localStorage.getItem(bioCredKey());

    onAuthReady(G.userEmail);
}

function isSessionAuthenticated() {
    return !!sessionStorage.getItem("sv_session_private_key");
}

async function onAuthReady(email) {
    log("[AU.onAuthReady] called");
    UI.showAuthorizedEmail(email);

    try {
        const id = await ID.loadIdentity();

        if (!id) {
            // New device → create identity
            setAuthMode("create");
            log("[AU.onAuthReady] New device detected, prompting password creation");
            return;
        }

        if (!id.passwordVerifier) {
            // Legacy identity → migration
            setAuthMode("unlock", { migration: true });
            log("[AU.onAuthReady] Identity missing password verifier — migration mode");
            return;
        }

        UI.showUnlockMessage("Checking for active session...", "info");
        // Attempt session restore first
        if (await attemptSessionRestore()) {
            log("[AU.onAuthReady] Found an active authenticated browser session — skipping password prompt");

            log("[AU.onAuthReady] G.driveLockState after session restore:" + (G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null));
            UI.showUnlockMessage("Authentication succeeded, proceeding to vault", "success");
            await ID.ensureDevicePublicKey();
            await UI.proceedAfterPasswordSuccess();
            return;
        }

        // Returning user → unlock
        setAuthMode("unlock");
        log("[AU.onAuthReady] Existing device detected, prompting unlock");

    } catch (e) {
        error("[AU.onAuthReady] Error loading identity:", e.message);
        UI.showUnlockMessage("Failed to load identity. Try again.");
        UI.signinBtn.disabled = false;
    }
}

function setAuthMode(mode, options = {}) {
    log("[AU.setAuthMode] called - mode: " + mode);
    G.authMode = mode;

    // reset fields
    UI.resetUnlockUi();

    UI.setupPasswordPrompt(mode, options);
}

async function attemptSessionRestore() {
    log("[AU.attemptSessionRestore] called");

    try {
        const stored = sessionStorage.getItem("sv_session_private_key");

        log("[AU.attemptSessionRestore] sessionStorage private key exists:", !!stored);
        if (!stored) {
            warn("[AU.attemptSessionRestore] No session private key found in sessionStorage");
            return false;
        }

        log("[AU.attemptSessionRestore] Restoring session private key...");

        const bytes = Uint8Array.from(atob(stored), c => c.charCodeAt(0));

        G.currentPrivateKey = await crypto.subtle.importKey(
            "pkcs8",
            bytes,
            { name:"RSA-OAEP", hash:"SHA-256" },
            false,
            ["decrypt", "unwrapKey"]
        );

        // Load identity from localStorage
        const id = await ID.loadIdentity(); // gets raw identity
        log("[AU.attemptSessionRestore] loadIdentity returned:", !!id);

        if (!id) {
            log("[AU.attemptSessionRestore] Identity not found in localStorage despite private key");
            return false;
        }

        // Attach session key
        id._sessionPrivateKey = G.currentPrivateKey;

        // Store as unlocked identity for ID.loadIdentity()
        G.unlockedIdentity = id;

        G.sessionUnlocked = true;
        log("[AU.attemptSessionRestore] Session restored from sessionStorage");

        log("[AU.attemptSessionRestore] Session restore check...");
        log("[AU.attemptSessionRestore] G.unlockedIdentity exists:", !!G.unlockedIdentity);
        log("[AU.attemptSessionRestore] fingerprint:", G.unlockedIdentity?.fingerprint);
        log("[AU.attemptSessionRestore] deviceId:", G.unlockedIdentity?.deviceId);
        log("[AU.attemptSessionRestore] G.currentPrivateKey exists:", !!G.currentPrivateKey);
        log("[AU.attemptSessionRestore] privateKey type:", G.currentPrivateKey?.type);
        log("[AU.attemptSessionRestore] privateKey algorithm:", JSON.stringify(G.currentPrivateKey?.algorithm));

        return true;

    } catch (err) {
        warn("[AU.attemptSessionRestore] Session restore failed, clearing");
        sessionStorage.removeItem("sv_session_private_key");
        return false;
    }
}

async function ensureAuthorization() {
    log("[AU.ensureAuthorization] called");

    const q = `'${C.ACCESS4_ROOT_ID}' in parents and name='${C.AUTH_FILE_NAME}'`;
    const res = await GD.driveFetch(GD.buildDriveUrl("files", { q, fields:"files(id)" }));

    if (!res.files.length) {
        log("[AU.ensureAuthorization] authorized.json not found, creating genesis authorization...");
        await createGenesisAuthorization();
        return;
    }
    const data = await GD.driveFetch(GD.buildDriveUrl(`files/${res.files[0].id}`, {
        alt:"media"
    }));
    if (!data.admins.includes(G.userEmail) && !data.members.includes(G.userEmail))
        throw new Error("Unauthorized user");
    log("[AU.ensureAuthorization] Authorized user verified");
}

async function createGenesisAuthorization() {
    log("[AU.createGenesisAuthorization] called");

    const file = await GD.driveFetch(GD.buildDriveUrl("files"), {
        method:"POST",
        headers: {
            "Content-Type":"application/json"
        },
        body: JSON.stringify({
            name: C.AUTH_FILE_NAME,
            parents: [C.ACCESS4_ROOT_ID]
        })
    });
    await GD.driveFetch(GD.buildDriveUrl(`files/${file.id}`, {
        uploadType:"media"
    }), {
        method:"PATCH",
        headers: {
            "Content-Type":"application/json"
        },
        body: JSON.stringify({
            admins: [G.userEmail],
            members: [G.userEmail],
            created: new Date().toISOString(),
            version: 1
        })
    });
    log(`[createGenesisAuthorization] Genesis authorization created for ${G.userEmail}`);
}

export function bioCredKey() {
    return `access4.bio.cred::${G.userEmail}::${ID.getDeviceId()}`;
}

export function bioPwdKey() {
    return `access4.bio.pwd::${G.userEmail}::${ID.getDeviceId()}`;
}
