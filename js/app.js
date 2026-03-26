"use strict";

import { C, G, clearGlobals, SV, log, trace, debug, info, warn, error,
    setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from '@/shared/exports.js';

import { rootUI } from '@/ui/loader.js';
import { loadLogin }  from '@/ui/login.js';

export let logEl = rootUI.log;

function onLoad() {

    //setLogLevel(INFO);
    //onlyLogLevels(INFO, TRACE);
    log("APP.onLoad", `called for [v${C.APP_VERSION}]`);
    loadLogin();

    //log("APP.onLoad", "sessionStorage sv_session_private_key exists:", !!sessionStorage.getItem("sv_session_private_key"));
    //log("APP.onLoad", "G.unlockedIdentity:", !!G.unlockedIdentity);
    //log("APP.onLoad", "G.currentPrivateKey:", !!G.currentPrivateKey);
}

async function releaseDriveLock() {
    log("AP.releaseDriveLock", "called");

    if (!G.driveLockState?.fileId) return;

    G.driveLockState.heartbeat?.stop();

    const cleared = {
        ...G.driveLockState.lock,
        expiresAt: new Date(0).toISOString()
    };

    await SV.writeLockToDrive(
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
};

/**
 * EXPORTED FUNCTIONS
 */
export function logout() {
    log("APP.logout", "Logging out...");

    releaseDriveLock();

    // Release Drive lock if held
    SV.handleDriveLockLost(); // stops heartbeat & clears local G.driveLockState

    // Clear user-specific memory
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");
    loadLogin();

    G.biometricIntent = false;
    log("APP.logout", "completed");
}
