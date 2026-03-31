"use strict";

import { C, G, clearGlobals, SV, log, trace, debug, info, warn, error,
    setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from '@/shared/exports.js';

import { rootUI } from '@/ui/loader.js';
import { loadLogin }  from '@/ui/login.js';
import { copyToClipboard } from '@/ui/uihelper.js';

export let logEl = rootUI.log;

const IdleManager = {
    timer: null,
    lastReset: 0,
    boundHandler: null,
    threshold: 5000,
    events: ['mousedown', 'mousemove', 'keydown', 'keypress', 'click', 'scroll', 'touchstart']
};

const resetTimer = (force = false) => {
    const now = Date.now();

    if (!force && (now - IdleManager.lastReset < IdleManager.threshold)) {
        return;
    }

    log("APP.resetTimer", "Refreshing idle timeout");
    IdleManager.lastReset = now;

    clearTimeout(IdleManager.timer);

    IdleManager.timer = setTimeout(async () => {
        logout("Auto logout");
    }, C.IDLE_TIMEOUT_MS);
};

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

function deactivateAutoLogout() {
    log("vaultUI.deactivateAutoLogout", "called");

    IdleManager.events.forEach(evt => {
        document.removeEventListener(evt, IdleManager.boundHandler);
    });

    clearTimeout(IdleManager.timer);
    IdleManager.callback = null;
    IdleManager.boundHandler = null;
    IdleManager.lastReset = 0;
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
export function activateAutoLogout() {
    log("APP.activateAutoLogout", "called");

    // 1. Create a clean wrapper that doesn't pass the Event object
    IdleManager.boundHandler = () => resetTimer(false);

    // Events that "wake up" the timer
    // Clean up old listeners to prevent memory leaks/duplicate triggers
    IdleManager.events.forEach(evt => {
        document.removeEventListener(evt, IdleManager.boundHandler);
        document.addEventListener(evt, IdleManager.boundHandler, { passive: true });
    });

    resetTimer(true);
}

export async function logout(reason = "User initiated") {
    log("APP.logout", "Initiating logout... reason:", reason);

    // 1️⃣ Wait for the lock to be released properly
    await releaseDriveLock();

    // 2️⃣ Clear the rest of the app state
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");

    deactivateAutoLogout();

    // 3️⃣ Redirect to login
    loadLogin();

    G.biometricIntent = false;
    log("APP.logout", "Logout complete.");
}
