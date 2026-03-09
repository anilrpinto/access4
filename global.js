"use strict";

const _G = {
    gisPrompt: false,
    tokenClient: null,
    accessToken: null,
    userEmail: null,
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
        minifyJson: false,
        clearBioDbOnLoad: false,
        clearLocalStorageOnLoad: false
    }
};

export let G = structuredClone(_G);

export function clearGlobals() {
    G = structuredClone(_G);
}