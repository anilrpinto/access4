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
        clearLocalStorageOnLoad: true,
        clearLastAutoBackupKey: false,
        ignore24hBackupCheck: true,
        preAuthMembers: ["avitapinto@gmail.com", "allisonpintosd@gmail.com", "myemailinbox1234@gmail.com"]

    },
};

export let G = structuredClone(_G);

export function clearGlobals() {
    G = structuredClone(_G);
}

export function inReadOnlyMode() {
    return G.driveLockState?.mode !== "write";
}