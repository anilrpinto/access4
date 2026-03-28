"use strict";

import { C, G, clearGlobals, SV, log, trace, debug, info, warn, error,
    setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from '@/shared/exports.js';

import { rootUI } from '@/ui/loader.js';
import { loadLogin }  from '@/ui/login.js';
import { copyToClipboard } from '@/ui/uihelper.js';

export let logEl = rootUI.log;

function onLoad() {

    //setLogLevel(INFO);
    //onlyLogLevels(INFO, TRACE);
    log("APP.onLoad", `called for [v${C.APP_VERSION}]`);
    loadLogin();

    logEl.onClick(doCopyToClipboardClick);

    window.addEventListener('focus', () => {
        if (G.driveLockState && !G.driveLockState.heartbeat) {
            log("APP.focus", "Tab focused - Attempting to restart stalled heartbeat...");
            SV.tryAcquireEnvelopeWriteLock(); // This uses the new "Proactive" logic from earlier
        }
    });
}

function doCopyToClipboardClick() {
    copyToClipboard(logEl.innerText);
}

async function releaseDriveLock() {
    log("AP.releaseDriveLock", "called");

    if (!G.driveLockState) return;

    // 1️⃣ Stop the heartbeat first so it doesn't try to tick during the release
    G.driveLockState.heartbeat?.stop();

    const { fileId, envelopeName, lock } = G.driveLockState;

    if (fileId && lock) {
        try {
            const cleared = {
                ...lock,
                expiresAt: new Date(0).toISOString(), // Kill the TTL on the server
                generation: (lock.generation || 0) + 1 // Increment to fence out late heartbeats
            };

            // 2️⃣ MUST AWAIT this to ensure the server actually receives the "Unlock"
            await SV.writeLockToDrive(cleared, fileId);
            log("AP.releaseDriveLock", "Drive lock explicitly expired on server");
        } catch (err) {
            warn("AP.releaseDriveLock", "Failed to release on server (network?), proceeding with local wipe", err);
        }
    }

    // 3️⃣ Finally, wipe local state
    G.driveLockState = null;
}

window.onload = async () => {
    await onLoad();
    clearGlobals();
};

/**
 * EXPORTED FUNCTIONS
 */
export async function logout() {
    log("APP.logout", "Initiating logout...");

    // 1️⃣ Wait for the lock to be released properly
    await releaseDriveLock();

    // 2️⃣ Clear the rest of the app state
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");

    // 3️⃣ Redirect to login
    loadLogin();

    G.biometricIntent = false;
    log("APP.logout", "Logout complete.");
}
