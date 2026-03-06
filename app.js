"use strict";

import { G, clearGlobals } from './global.js';

import * as GD from './gdrive.js';
import * as AU from './auth.js';
import * as E from './envelope.js';
import * as UI from './ui.js';

import { log, trace, debug, info, warn, error, setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from './log.js';

function onLoad() {

    //setLogLevel(INFO);
    //onlyLogLevels(INFO, TRACE);
    log("AP.onLoad", "called");
    UI.init();

    // Wire handlers
    UI.bindClick(UI.signinBtn, () => AU.initGIS());
    UI.bindClick(UI.logoutBtn, () => logout());

    log("AP.onLoad", "sessionStorage sv_session_private_key exists:", !!sessionStorage.getItem("sv_session_private_key"));
    log("AP.onLoad", "G.unlockedIdentity:", !!G.unlockedIdentity);
    log("AP.onLoad", "G.currentPrivateKey:", !!G.currentPrivateKey);
}

async function releaseDriveLock() {
    log("AP.releaseDriveLock", "called");

    if (!G.driveLockState?.fileId) return;

    G.driveLockState.heartbeat?.stop();

    const cleared = {
        ...G.driveLockState.lock,
        expiresAt: new Date(0).toISOString()
    };

    await GD.writeLockToDrive(
        G.driveLockState.envelopeName,
        cleared,
        G.driveLockState.fileId
    );

    log("AP.releaseDriveLock", "Drive lock released");
    G.driveLockState = null;
}

export function logout() {
    log("AP.logout", "Logging out...");

    releaseDriveLock();

    // 1️⃣ Release Drive lock if held
    E.handleDriveLockLost(); // stops heartbeat & clears local G.driveLockState

    // 2️⃣ Clear user-specific memory
    //G.accessToken = null;
    //G.userEmail = null;
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");
    UI.resetUnlockUi();

    G.biometricIntent = false;

    log("AP.logout", "completed");
}

window.onload = async () => {
    await onLoad();
    //await initGIS();

    // Clear any lingering G.driveLockState in memory
    //G.driveLockState = null;
    clearGlobals();
    UI.resetUnlockUi();

    // Optional: detect if a user was partially logged in
    // If you want logout to be final, skip restoring user session
    // Otherwise, you could try reacquiring the lock here
};
