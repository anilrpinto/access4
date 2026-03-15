"use strict";

import { C, G, clearGlobals, E, log, trace, debug, info, warn, error,
    setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from './exports.js';

import { loadUI } from './ui/uihelper.js';

import { loadLogin, enterPreSignInMode }  from './ui/login.js';

function onLoad() {

    //setLogLevel(INFO);
    //onlyLogLevels(INFO, TRACE);
    log("APP.onLoad", `called for [v${C.APP_VERSION}]`);
    loadLogin();

    log("APP.onLoad", "sessionStorage sv_session_private_key exists:", !!sessionStorage.getItem("sv_session_private_key"));
    log("APP.onLoad", "G.unlockedIdentity:", !!G.unlockedIdentity);
    log("APP.onLoad", "G.currentPrivateKey:", !!G.currentPrivateKey);
}

async function releaseDriveLock() {
    log("AP.releaseDriveLock", "called");

    if (!G.driveLockState?.fileId) return;

    G.driveLockState.heartbeat?.stop();

    const cleared = {
        ...G.driveLockState.lock,
        expiresAt: new Date(0).toISOString()
    };

    await E.writeLockToDrive(
        G.driveLockState.envelopeName,
        cleared,
        G.driveLockState.fileId
    );

    log("AP.releaseDriveLock", "Drive lock released");
    G.driveLockState = null;
}

window.onload = async () => {
    await onLoad();

    clearGlobals();
    enterPreSignInMode();
};

/**
 * EXPORTED FUNCTIONS
 */
export function logout() {
    log("APP.logout", "Logging out...");

    releaseDriveLock();

    // 1️⃣ Release Drive lock if held
    E.handleDriveLockLost(); // stops heartbeat & clears local G.driveLockState

    // 2️⃣ Clear user-specific memory
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");
    enterPreSignInMode();

    G.biometricIntent = false;

    log("APP.logout", "completed");
}
