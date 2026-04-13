"use strict";

import { C, G, clearGlobals, isValidSession, SV, log, trace, debug, info, warn, error, setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from '@/shared/exports.js';
import { rootUI } from '@/ui/loader.js';
import { loadLogin }  from '@/ui/login.js';
import { copyToClipboard } from '@/ui/uihelper.js';

export let logEl = rootUI.log;

const _idleManager = {
    timer: null,
    lastReset: 0,
    boundHandler: null,
    threshold: 5000,
    events: ['mousedown', 'mousemove', 'keydown', 'keypress', 'click', 'scroll', 'touchstart']
};

const _resetTimer = (force = false) => {
    const now = Date.now();

    if (!force && (now - _idleManager.lastReset < _idleManager.threshold)) {
        return;
    }

    log("APP._resetTimer", "Refreshing idle timeout");
    _idleManager.lastReset = now;

    clearTimeout(_idleManager.timer);

    _idleManager.timer = setTimeout(async () => {
        logout("Auto logout");
    }, C.IDLE_TIMEOUT_MS);
};

export function activateIdleChecker() {
    log("APP.activateIdleChecker", "called");

    // 1. Create a clean wrapper that doesn't pass the Event object
    _idleManager.boundHandler = () => _resetTimer(false);

    // Events that "wake up" the timer
    // Clean up old listeners to prevent memory leaks/duplicate triggers
    _idleManager.events.forEach(evt => {
        document.removeEventListener(evt, _idleManager.boundHandler);
        document.addEventListener(evt, _idleManager.boundHandler, { passive: true });
    });

    _resetTimer(true);
}

export async function logout(reason = "User initiated") {
    log("APP.logout", "Initiating logout... reason:", reason);

    // 2️⃣ Clear the rest of the app state
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");

    // 1️⃣ Wait for the lock to be released properly
    await _releaseDriveLock();

    _deactivateAutoLogout();

    // 3️⃣ Redirect to login
    loadLogin();

    G.biometricIntent = false;
    log("APP.logout", "Logout complete.");
}

/** INTERNAL FUNCTIONS **/
function _onLoad() {

    //setLogLevel(INFO);
    //onlyLogLevels(INFO, TRACE);
    log("APP._onLoad", `called for [v${C.APP_VERSION}]`);
    loadLogin();

    logEl.onClick(_doCopyToClipboardClick);

    window.addEventListener('focus', () => {
        if (G.driveLockState && !G.driveLockState.heartbeat) {
            log("APP.focus", "Tab focused - Attempting to restart stalled heartbeat...");

            if (!isValidSession) {
                warn("No valid session found, terminating lock status lost flow");
                return;
            }

            SV.tryAcquireEnvelopeWriteLock(); // This uses the new "Proactive" logic from earlier
        }
    });
}

function _deactivateAutoLogout() {
    log("vaultUI._deactivateAutoLogout", "called");

    _idleManager.events.forEach(evt => {
        document.removeEventListener(evt, _idleManager.boundHandler);
    });

    clearTimeout(_idleManager.timer);
    _idleManager.callback = null;
    _idleManager.boundHandler = null;
    _idleManager.lastReset = 0;
}

function _doCopyToClipboardClick() {
    copyToClipboard(logEl.innerText);
}

async function _releaseDriveLock() {
    log("AP._releaseDriveLock", "called");

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
            log("AP._releaseDriveLock", "Drive lock explicitly expired on server");
        } catch (err) {
            warn("AP._releaseDriveLock", "Failed to release on server (network?), proceeding with local wipe", err);
        }
    }

    // 3️⃣ Finally, wipe local state
    G.driveLockState = null;
}

window.onload = async () => {
    await _onLoad();
    clearGlobals();
};
