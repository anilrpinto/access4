"use strict";

import { C } from './constants.js';
import { G, clearGlobals } from './global.js';

import * as GD from './gdrive.js';
import * as AU from './auth.js';
import * as CR from './crypto.js';
import * as ID from './identity.js';
import * as E from './envelope.js';
import * as UI from './ui.js';

import { log, trace, debug, info, warn, error, setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from './log.js';

function onLoad() {

    //setLogLevel(INFO);
    //onlyLogLevels(INFO, TRACE);
    log("[AP.onLoad] called");
    UI.init();

    // Wire handlers
    UI.bindClick(UI.signinBtn, () => AU.initGIS());
    UI.bindClick(UI.logoutBtn, () => logout());
    //UI.bindClick(UI.unlockBtn, handleUnlockClick);

    log("[AP.onLoad] sessionStorage sv_session_private_key exists:", !!sessionStorage.getItem("sv_session_private_key"));
    log("[AP.onLoad] G.unlockedIdentity:", !!G.unlockedIdentity);
    log("[AP.onLoad] G.currentPrivateKey:", !!G.currentPrivateKey);
}

async function releaseDriveLock() {
    log("[AP.releaseDriveLock] called");

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

    log("[AP.releaseDriveLock] Drive lock released");
    G.driveLockState = null;
}

/*function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}*/

async function encryptPrivateKeyWithPassword(privateKey, password) {
    // 1️⃣ Export private key (raw)
    const rawPrivate = await crypto.subtle.exportKey("raw", privateKey);

    // 2️⃣ Derive AES key from password
    const kdf = {
        salt: crypto.getRandomValues(new Uint8Array(16)),
        iterations: 200_000,
        hash:"SHA-256"
    };

    const aesKey = await CR.deriveKey(password, kdf);

    // 3️⃣ Encrypt
    const encrypted = await encrypt(rawPrivate, aesKey);

    // 4️⃣ Package
    return {
        version: 1,
        kdf,
        cipher:"AES-256-GCM",
        encrypted
    };
}

/* ================= BIOMETRIC ================= */
async function biometricAuthenticateFromGesture() {
    if (!window.PublicKeyCredential) {
        log("⚠️ Biometric not supported on this browser");
        return;
    }

    const rawId = localStorage.getItem(AU.bioCredKey());
    const storedPwd = localStorage.getItem(AU.bioPwdKey());
    if (!rawId || !storedPwd) {
        log("⚠️ No biometric credential stored");
        return;
    }

    try {
        log("👆 Triggering biometric prompt...");
        await navigator.credentials.get({
            publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                allowCredentials: [{
                    type:"public-key",
                    id: Uint8Array.from(atob(rawId), c => c.charCodeAt(0))
                }],
                userVerification:"required"
            }
        });
        log("✅ Biometric authentication prompt completed successfully");
        log("🔓 Using stored password to unlock identity...");
        await unlockIdentityFlow(atob(storedPwd));
    } catch (e) {
        log("⚠️ Biometric prompt failed or canceled:" + e.message);
    }
}

/* ================= STEP 4.1: DEVICE PUBLIC KEY ================= */
async function hasRecoveryKey() {
    // TEMP: replace with Drive check later
    const marker = localStorage.getItem("recoveryKeyPresent");
    return !!marker;
}


/*function finalizeKeyRegistry(registry) {
    Object.freeze(registry.flat.activeDevices);
    Object.freeze(registry.flat.deprecatedDevices);
    Object.freeze(registry.flat.recoveryKeys);
    Object.freeze(registry.flat);
    Object.freeze(registry.accounts);
    Object.freeze(registry);
}*/



/* ================= LOGOUT ================= */
export function logout() {
    log("[AP.logout] Logging out...");

    releaseDriveLock();

    // 1️⃣ Release Drive lock if held
    E.handleDriveLockLost(); // stops heartbeat & clears local G.driveLockState

    // 2️⃣ Clear user-specific memory
    //G.accessToken = null;
    //G.userEmail = null;
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");
    UI.resetUnlockUi();

    // 4️⃣ Clear biometric data (optional)
    localStorage.removeItem(AU.bioCredKey());
    localStorage.removeItem(AU.bioPwdKey());
    G.biometricRegistered = false;
    G.biometricIntent = false;

    log("[AP.logout] completed");
}

/* ----------------- UI action handlers -------------------*/

async function handleCreateRecoveryClick() {
    log("[AP.handleCreateRecoveryClick] called - Starting recovery key creation");

    const pwd = passwordInput.value;
    const confirm = confirmPasswordInput.value;

    if (!pwd || pwd.length < 7) {
        throw new Error("Recovery password must be at least 7 characters.");
    }
    if (pwd !== confirm) {
        throw new Error("Recovery passwords do not match.");
    }

    unlockBtn.disabled = true;
    UI.showUnlockMessage("Creating recovery key…");

    // 1️⃣ Generate RSA keypair (same as device)
    const keypair = await crypto.subtle.generateKey(
        {
            name:"RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash:"SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
    log("[AP.handleCreateRecoveryClick] Recovery keypair generated");

    // 2️⃣ Export keys
    const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", keypair.privateKey);
    const publicKeySpki = await crypto.subtle.exportKey("spki", keypair.publicKey);
    log("[AP.handleCreateRecoveryClick] Recovery keys exported");

    // 3️⃣ Build recovery identity
    const recoveryIdentity = await buildIdentityFromKeypair(
        { privateKeyPkcs8, publicKeySpki },
        pwd,
        { type:"recovery", createdBy: ID.getDeviceId() }
    );
    log("[AP.handleCreateRecoveryClick] Private key encrypted with recovery password");

    // 4️⃣ Ensure recovery folder
    const recoveryFolderId = await GD.ensureRecoveryFolder();

    // 5️⃣ Write private recovery file
    await GD.driveCreateJsonFile({ name:"recovery.private.json", parents: [recoveryFolderId], json: recoveryIdentity });
    log("[AP.handleCreateRecoveryClick] recovery.private.json written");

    // 6️⃣ Write public recovery file (matching device key structure)
    const recoveryPublicJson = {
        type:"recovery",
        role:"recovery",
        keyId: recoveryIdentity.fingerprint,
        fingerprint: recoveryIdentity.fingerprint,
        created: recoveryIdentity.created,
        algorithm: {
            name:"RSA-OAEP",
            modulusLength: 2048,
            hash:"SHA-256",
            usage: ["encrypt"]
        },
        publicKey: {
            format:"spki",
            encoding:"base64",
            data: btoa(String.fromCharCode(...new Uint8Array(publicKeySpki)))
        }
    };

    await GD.driveCreateJsonFile({
        name:"recovery.public.json",
        parents: [recoveryFolderId],
        json: recoveryPublicJson
    });
    log("[AP.handleCreateRecoveryClick] recovery.public.json written");

    // 7️⃣ Add to envelope for CEK housekeeping
    await addRecoveryKeyToEnvelope({
        publicKey: publicKeySpki,
        keyId: recoveryIdentity.fingerprint
    });

    log("[AP.handleCreateRecoveryClick] Recovery key successfully established");
    UI.showUnlockMessage("Recovery key created!", "unlock-message success");
    unlockBtn.disabled = false;
}



/*function isEnvelopeReadOnly() {
    return !G.driveLockState || G.driveLockState.mode !== "write";
}*/


// Button to invoke it doens't exist in the latest ui, add to enable (for testing biometric behavior)
function handleResetBiometricClick() {
    localStorage.removeItem(AU.bioCredKey());
    localStorage.removeItem(AU.bioPwdKey());
    G.biometricRegistered = false;
    G.biometricIntent = false;
    log("⚠️ Biometric registration cleared for testing");
};

/* ---------- TEMPORARY ---------*/


/*-------- TEMPORARY ENDS -------*/

// IMPORTANT - DO NOT DELETE
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
