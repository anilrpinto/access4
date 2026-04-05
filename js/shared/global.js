"use strict";

const _G = {
    tokenClient: null,
    accessToken: null,
    authorizedName: null,
    userEmail: null,
    userId: null,
    needsIdentitySetup: false,
    biometricIntent: false,

    auth: {
        admins: [],
        members: []
    },

    keyRegistry: {
        version: 1,
        loadedAt: null,

        accounts: {},

        flat: {
            activeDevices: [],
            deprecatedDevices: [],
            recoveryKeys: []
        }
    },

    driveLockState: null,
    unlockInProgress: false,
    authMode: null,

    unlockedIdentity: null,   // Holds decrypted identity for current session
    currentPrivateKey: null,
    sessionUnlocked: false,

    recoveryRequest: false,
    recoverySession: false,
    recoveryCEK: null,

    settings: {
        gisPrompt: false,
        minifyJson: false,
        clearBioDbOnLoad: false,
        clearLocalStorageOnLoad: false,
        clearLastAutoBackupKey: false,
        ignore24hCheck: false,
        preAuthMembers: {
            "avitapinto@gmail.com": { role: "member", readonly: false, forcePasswordChange: false, allowAttachments: true },
            "allisonpintosd@gmail.com": { role: "member", readonly: true, allowAttachments: false },
            "myemailinbox1234@gmail.com": { role: "member", readonly: true, allowAttachments: false, forcePasswordChange: true }
        }
    },
};

export let G = structuredClone(_G);

export function clearGlobals() {
    G = structuredClone(_G);
}

export function isValidSession() {
    return (G.sessionUnlocked && G.unlockedIdentity);
}

export function inWriteMode() {
    return G.driveLockState?.mode === "write";
}

export function inReadOnlyMode() {
    return G.driveLockState?.mode !== "write";
}

export function isRecoveryAuthorizedSession() {
    return (G.recoverySession === true && G.recoveryCEK);
}

export function isAuthorizedSession() {
    return G.currentPrivateKey || isRecoveryAuthorizedSession();
}

export function isActiveSession(id) {
    return G.sessionUnlocked === true && id._sessionPrivateKey === G.currentPrivateKey && G.unlockedIdentity === id;
}