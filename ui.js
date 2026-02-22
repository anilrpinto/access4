"use strict";

import { C } from './constants.js';
import { G } from './global.js';
import { logout } from './app.js';

import * as GD from './gdrive.js';
import * as E from './envelope.js';
import * as CR from './crypto.js';
import * as ID from './identity.js';

import { log, trace, debug, info, warn, error } from './log.js';

export let signinBtn;
export let passwordSection;
export let confirmPasswordSection;
export let unlockBtn;

export let titleUnlocked;
export let plaintextInput;
export let saveBtn;

export let loginView;
export let unlockedView;
export let passwordInput;
export let confirmPasswordInput;

export let logoutBtn;

export let logEl;

let userEmailSpan;
let unlockMessage;
let idleTimer;
let idleCallback = null;

const idleEvents = ['mousedown', 'mousemove', 'keydown', 'keypress', 'click', 'scroll', 'touchstart'];

const resetTimer = () => {
    clearTimeout(idleTimer);

    if (!idleCallback) return;

    idleTimer = setTimeout(async () => {
        if (typeof idleCallback === 'function') {
            await idleCallback('idle.timeout');
        }
    }, C.IDLE_TIMEOUT_MS);
};

export function init() {

    // Cache DOM
    userEmailSpan = document.getElementById("userEmailSpan");
    signinBtn = document.getElementById("signinBtn");
    passwordSection = document.getElementById("passwordSection");
    confirmPasswordSection = document.getElementById("confirmPasswordSection");
    unlockBtn = document.getElementById("unlockBtn");
    unlockMessage = document.getElementById("unlockMessage");

    logoutBtn = document.getElementById("logoutBtn");

    loginView = document.getElementById("loginView");
    unlockedView = document.getElementById("unlockedView");
    passwordInput = document.getElementById("passwordInput");
    confirmPasswordInput = document.getElementById("confirmPasswordInput");
    logEl = document.getElementById("log");

    titleUnlocked = document.getElementById("titleUnlocked");
    plaintextInput = document.getElementById("plaintextInput");
    saveBtn = document.getElementById("saveBtn");

    // Initial UI state
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";
    unlockedView.style.display = "none";

    setupTitleGesture();
    initLoginUI();

    bindClick(saveBtn, handleSaveClick);
}

export function showUnlockMessage(msg, type = "error") {
    if (!unlockMessage) return;

    unlockMessage.textContent = msg;
    unlockMessage.className = `unlock-message ${type}`;
}

export function bindClick(el, callback, options = {}) {
    if (!el) {
        // Use your new logger!
        warn("[UI.bindClick] Attempted to bind click to a null element.");
        return;
    }

    el.addEventListener('click', (e) => {
        callback(e);
    }, options);
}

export function promptUnlockPasword() {
    logEl.textContent = "";
    signinBtn.disabled = true;
    logoutBtn.disabled = false;
    passwordSection.style.display = "block";
}

export function showAuthorizedEmail(email) {
    log("[UI.showAuthorizedEmail] email: ", email);
    userEmailSpan.textContent = email;
}

// attach gesture logic
function setupTitleGesture() {
    const t = document.getElementById("titleGesture");
    if (!t) return;

    let timer = null;

    t.addEventListener("pointerdown", () => {
        timer = setTimeout(armBiometric, 5000);
    });

    ["pointerup", "pointerleave", "pointercancel"].forEach(e =>
        t.addEventListener(e, () => clearTimeout(timer))
    );

    t.addEventListener("click", async () => {
        if (!G.biometricRegistered) return;
        await biometricAuthenticateFromGesture();
    });
}

function armBiometric() {
    G.biometricIntent = true;
    log("👆 Hidden biometric intent armed");

    if (G.unlockedPassword && !G.biometricRegistered) {
        log("🔐 Password already unlocked, enrolling biometric immediately...");
        ID.enrollBiometric(G.unlockedPassword).then(() => G.biometricRegistered = true);
    }
}

function initLoginUI() {
    // Always show login view
    loginView.style.display = "block";
    unlockedView.style.display = "none";

    // Hide password input sections until needed
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";

    signinBtn.disabled = false;

    // Reset any messages
    showUnlockMessage("");

    // Disable save button initially
    saveBtn.disabled = true;
}

export function resetUnlockUi() {

    // 3️⃣ Clear UI state
    unlockedView.style.display = "none";
    loginView.style.display = "block";

    // Clear password inputs
    passwordInput.value = "";
    confirmPasswordInput.value = "";

    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";

    // Reset button state
    unlockBtn.disabled = false;
    unlockBtn.textContent = "Unlock";

    // Clear messages
    showUnlockMessage("");

    idleEvents.forEach(evt => {
        document.removeEventListener(evt, resetTimer);
    });

    clearTimeout(idleTimer);
    idleCallback = null;

    log("[UI.resetUnlockUi] G.authMode:", G.authMode)

    if (G.authMode !== "create" && G.authMode !== "unlock") {
        showAuthorizedEmail(null);
        signinBtn.disabled = false;
    }
}

export function setupPasswordPrompt(mode, options = {}) {

    // ✅ Always enable unlockBtn when switching mode
    unlockBtn.disabled = false;

    passwordSection.style.display = "block";

    if (mode === "unlock") {
        confirmPasswordSection.style.display = "none";
        unlockBtn.textContent = "Unlock";
        unlockBtn.onclick = handleUnlockClick;

        showUnlockMessage(options.migration
            ? "Identity missing password verifier — enter your password to upgrade."
            :"");
    } else if (mode === "create") {
        confirmPasswordSection.style.display = "block";
        unlockBtn.textContent = "Create Password";
        unlockBtn.onclick = handleCreatePasswordClick;
    }

}

export function showVaultUI({ readOnly = false, onIdle = () => { warn('idle timeout fired') } } = {}) {

    log("[UI.showVaultUI] entered");

    // Hide login / password sections
    loginView.style.display = "none";
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";

    // Show main unlocked view
    unlockedView.style.display = "block";

    // Update UI for read-only mode
    if (readOnly) {
        warn("[UI.showVaultUI] Unlocked UI in read-only mode: disabling save button");
        saveBtn.disabled = true;
        saveBtn.title = "Read-only mode: cannot save";
        plaintextInput.readOnly = true;
        titleUnlocked.textContent = "Unlocked (Read-only)";
    } else {
        saveBtn.disabled = false;
        saveBtn.title = "";
        plaintextInput.readOnly = false;
        titleUnlocked.textContent = "Unlocked";
    }

    // Events that "wake up" the timer
    // Clean up old listeners to prevent memory leaks/duplicate triggers
    idleEvents.forEach(evt => {
        document.removeEventListener(evt, resetTimer);
        document.addEventListener(evt, resetTimer, { passive: true });
    });

    idleCallback = onIdle;
    resetTimer();
}

export function promptRecoverySetupUI() {
    log("[UI.promptRecoverySetupUI] called");

    return new Promise(resolve => {
        // reuse existing inputs
        resetUnlockUi();

        passwordSection.style.display = "block";
        confirmPasswordSection.style.display = "block";

        unlockBtn.textContent = "Create Recovery Password";
        unlockBtn.disabled = false;

        showUnlockMessage(
            "Create a recovery password. This allows account recovery if all devices are lost.",
            "unlock-message"
        );

        unlockBtn.onclick = async () => {
            try {
                await handleCreateRecoveryClick();
                resolve();
            } catch (e) {
                unlockBtn.disabled = false;
                showUnlockMessage(e.message || "Recovery setup failed", "unlock-message error");
            }
        };
    });
}

export function updateLockStatusUI() {
    if (!G.driveLockState) return;

    const { expiresAt } = G.driveLockState.lock;
    trace(`[updateLockStatusUI] You hold the envelope lock (expires ${expiresAt})`);
}

/* --------- Unlock flow --------- */

async function handleCreatePasswordClick()  {
    log("[UI.handleCreatePasswordClick] called");

    const pwd = passwordInput.value;
    const confirm = confirmPasswordInput.value;

    if (!pwd || pwd.length < 7) {
        showUnlockMessage("Password too weak");
        return;
    }

    if (pwd !== confirm) {
        showUnlockMessage("Passwords do not match");
        return;
    }

    try {
        await ID.createIdentity(pwd);
        await proceedAfterPasswordSuccess();
        log("[UI.handleCreatePasswordClick] New identity created and unlocked");
    } catch (e) {
        showUnlockMessage(e.message);
    }
}

async function handleUnlockClick() {

    log("[UI.handleUnlockClick] called");

    if (G.unlockInProgress) return;

    G.unlockInProgress  = true;
    const pwd = passwordInput.value;

    showUnlockMessage(""); // clear previous

    if (!pwd) {
        showUnlockMessage("Password cannot be empty");
        return;
    }

    try {
        await unlockIdentityFlow(pwd);
        await proceedAfterPasswordSuccess();
    } catch (e) {
        const def = Object.values(C.UNLOCK_ERROR_DEFS)
            .find(d => d.code === e.code);

        showUnlockMessage(def?.message || e.message || "Unlock failed");
        error("[UI.handleUnlockClick] Unlock failed:", (def?.message || e.message));
    }
}

async function unlockIdentityFlow(pwd) {

    log("[UI.unlockIdentityFlow] called");

    if (!pwd || pwd.length < 7) {
        const e = new Error(C.UNLOCK_ERROR_DEFS.WEAK_PASSWORD.message);
        e.code = C.UNLOCK_ERROR_DEFS.WEAK_PASSWORD.code;
        throw e;
    }

    log("🔓 [unlockIdentityFlow] Unlock attempt started for password:", (pwd ? "***" : "(empty)"));

    if (!G.accessToken) {
        const e = new Error(C.UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.message);
        e.code = C.UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.code;
        throw e;
    }

    let id = await ID.loadIdentity();
    log("[UI.unlockIdentityFlow] Identity loaded:", !!id);

    if (id && identityNeedsPasswordSetup(id)) {
        log("[UI.unlockIdentityFlow] Identity missing password verifier — attempting auto-migration");

        try {
            await ID.migrateIdentityWithVerifier(id, pwd);
            id = await ID.loadIdentity();
        } catch {
            const e = new Error(C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
            e.code = C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
            throw e;
        }
    }

    if (!id) {
        error("[UI.unlockIdentityFlow] No local identity found — cannot unlock");
        const e = new Error(C.UNLOCK_ERROR_DEFS.NO_IDENTITY.message);
        e.code = C.UNLOCK_ERROR_DEFS.NO_IDENTITY.code;
        throw e;
    }

    log("[UI.unlockIdentityFlow] Local identity found");

    // ─────────────────────────────
    // 🔐 AUTHORITATIVE PASSWORD CHECK
    // ─────────────────────────────
    let key;
    try {
        key = await CR.deriveKey(pwd, id.kdf);
        await ID.verifyPasswordVerifier(id.passwordVerifier, key);
        log("[UI.unlockIdentityFlow] Password verified");
    } catch {
        const e = new Error(C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
        e.code = C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
        throw e;
    }

    log("[UI.unlockIdentityFlow] Password verified:", (key ? "***" : "(failed)"));

    // ─────────────────────────────
    // 🔓 Attempt private key decrypt
    // ─────────────────────────────
    let decrypted = false;
    let decryptedPrivateKeyBytes = null;

    try {
        decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
        decrypted = true;
        log("[UI.unlockIdentityFlow] Identity successfully decrypted");
    } catch {
        error("[UI.unlockIdentityFlow] Private key decryption failed");
    }

    log("[UI.unlockIdentityFlow] Identity decrypted:", decrypted);

    // ─────────────────────────────
    // 🔁 Single rotation retry
    // ─────────────────────────────
    if (!decrypted) {
        log("[UI.unlockIdentityFlow] Attempting device key rotation");

        await rotateDeviceIdentity(pwd);
        id = await ID.loadIdentity();

        try {
            await CR.decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("[UI.unlockIdentityFlow] Decryption succeeded after rotation");
        } catch {
            warn("[UI.unlockIdentityFlow] Decryption still failing after rotation");
        }
    }

    // ─────────────────────────────
    // 🧨 Absolute Safari recovery
    // ─────────────────────────────
    if (!decrypted) {
        log("[UI.unlockIdentityFlow] Rotation failed (safari behavior?) — recreating identity");

        await createIdentity(pwd);
        id = await ID.loadIdentity();

        if (!id) {
            error("[UI.unlockIdentityFlow] Faied to load existing identity - ", C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            const e = new Error(C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }

        try {
            key = await CR.deriveKey(pwd, id.kdf);
            await decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("[UI.unlockIdentityFlow] Decryption succeeded after recreation");
        } catch {
            error("[UI.unlockIdentityFlow] post rotation decryption attempt failed - ", C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            const e = new Error(C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }
    }

    if (id.supersedes) {
        log("[UI.unlockIdentityFlow] Identity supersedes previous keyId:" + id.supersedes);
    }

    // ─────────────────────────────
    // Session unlocked
    // ─────────────────────────────
    G.unlockedPassword = pwd;

    await ID.cacheDecryptedPrivateKey(decryptedPrivateKeyBytes);

    // ✅ Attach decrypted key to identity and set global G.unlockedIdentity
    id._sessionPrivateKey = G.currentPrivateKey;
    G.unlockedIdentity = id;
    G.sessionUnlocked = true;


    log("[UI.unlockIdentityFlow] G.unlockedIdentity set in memory for session");

    if (G.biometricIntent && !G.biometricRegistered) {
        await enrollBiometric(pwd);
        G.biometricRegistered = true;
    }

    log("[UI.unlockIdentityFlow] Proceeding to device public key exchange");
    await ID.ensureDevicePublicKey();

    return id;
}

function identityNeedsPasswordSetup(id) {
    return id && !id.passwordVerifier;
}

export async function proceedAfterPasswordSuccess() {
    log("[UI.proceedAfterPasswordSuccess] called");
    log("[UI.proceedAfterPasswordSuccess] G.unlockedIdentity exists:", !!G.unlockedIdentity);
    log("[UI.proceedAfterPasswordSuccess] G.currentPrivateKey exists:", !!G.currentPrivateKey);
    log("[UI.proceedAfterPasswordSuccess] G.driveLockState:", G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null);

    await E.ensureEnvelope();      // 🔐 guarantees CEK + envelope
    await ensureRecoveryKey();   // 🔑 may block UI

    // ---- New housekeeping: wrap CEK for registry ----
    if (G.driveLockState?.self && G.driveLockState.envelopeName === C.ENVELOPE_NAME) {
        log("[UI.proceedAfterPasswordSuccess] Performing CEK housekeeping for all valid devices + recovery keys");
        await E.wrapCEKForRegistryKeys();  // helper handles load & write
    } else {
        warn("[UI.proceedAfterPasswordSuccess] Skipping CEK housekeeping — G.driveLockState not ready or not writable");
    }

    await E.loadEnvelopePayloadToUI();

    // Show unlocked UI in read-only mode if no write lock
    const readOnly = !G.driveLockState?.self || G.driveLockState.mode !== "write";
    if (readOnly) {
        warn("[UI.proceedAfterPasswordSuccess] Showing unlocked UI in read-only mode");
    }
    showVaultUI({ readOnly, onIdle: (type) => logout() });

    log("[UI.proceedAfterPasswordSuccess] Unlock successful!@");
}

async function ensureRecoveryKey() {
    log("[UI.ensureRecoveryKey] called");

    if (await GD.hasRecoveryKeyOnDrive()) {
        info("[UI.ensureRecoveryKey] Recovery key already present");
        return;
    }

    log("[UI.ensureRecoveryKey] No recovery key found — blocking for recovery setup");
    await promptRecoverySetupUI();   // ← UI + user input
}

async function handleSaveClick() {
    log("[UI.handleSaveClick] called");

    const text = plaintextInput.value;
    if (!text) {
        warn("[handleSaveClick] Nothing to encrypt");
        return;
    }

    try {
        await E.encryptAndPersistPlaintext(text);
        //plaintextInput.value = "";
    } catch (e) {
        error("[handleSaveClick] Encryption failed:", e.message);
    }
    alert("Saved!");
}
