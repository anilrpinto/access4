export const G = {
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
}