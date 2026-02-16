"use strict";

const _G = {
    tokenClient: null,
    accessToken: null,
    userEmail: null,
    needsIdentitySetup: false,
    unlockedPassword: null,
    biometricIntent: false,
    biometricRegistered: false,

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
    sessionUnlocked: false
};

export let G = structuredClone(_G);

export function clearGlobals() {
    G = structuredClone(_G);
}