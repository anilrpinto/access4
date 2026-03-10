"use strict";

import { C } from './constants.js';
import { G } from './global.js';
import { logout } from './app.js';

import * as AU from './auth.js';
import * as GD from './gdrive.js';
import * as E from './envelope.js';
import * as CR from './crypto.js';
import * as ID from './identity.js';
import * as BM from './biometrics.js';
import * as R from './recovery.js';
import * as U from './utils.js';
import { loadUI } from './uihelper.js';

import { log, trace, debug, info, warn, error } from './log.js';

export let logEl = document.getElementById('log');

const main = loadUI(['loginView', 'vaultView', 'vaultTitle']);

const login = loadUI(['signinBtn', 'userEmailSpan', 'authMsg', 'pwdSection', 'confirmPwdSection', 'pwdInput', 'confirmPwdInput',
    'unlockBtn', 'recoverBtn', 'recoveryLnk', 'statusMsg'], 'login_');

const vault = loadUI(['mainSection', 'data', 'recoveryRotationBtn', 'logoutBtn', 'saveBtn', 'statusMsg'], 'vault_', 'vaultBody');

const vaultRecoveryKey = loadUI(['mainSection', 'currentPwdSection', 'currentPwdInput', 'pwdInput',
    'confirmPwdInput', 'rotateBtn', 'cancelBtn', 'statusMsg'], 'vaultRecoveryKey_', 'vaultBody');

export let signinBtn = login.signinBtn;
export let logoutBtn = vault.logoutBtn;

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

export async function init() {

    signinBtn = login.signinBtn;
    logoutBtn = vault.logoutBtn;

    // Initial UI state
    login.pwdSection.setVisible(false);
    login.confirmPwdSection.setVisible(false);
    main.vaultView.setVisible(false);

    setupTitleGesture();
    initLoginUI();

    bindClick(login.recoveryLnk, doNeedRecoveryClick);
    bindClick(login.recoverBtn, doRecoverClick);
    bindClick(vault.saveBtn, doSaveClick);
    bindClick(logEl, copyLogsToClipboard);

    if (G.settings.clearBioDbOnLoad)
        await promptClearBiometricIndexedDB();

    if (G.settings.clearLocalStorageOnLoad)
        promptClearLocalStorage();

    await BM.debugBiometricDB();
    await updateBiometricIndicator();
}

export function showAuthMessage(msg, type = "error") {
    if (!login.authMsg) return;

    login.authMsg.textContent = msg;
    login.authMsg.className = `status-message ${type}`;
    login.signinBtn.setEnabled(true);
}

export function showUnlockMessage(msg, type = "error") {
    if (!login.statusMsg) return;

    login.statusMsg.textContent = msg;
    login.statusMsg.className = `status-message ${type}`;
}

export function showStatusMessage(msg, type = "error") {
    if (!vault.statusMsg) return;

    vault.statusMsg.textContent = msg;
    vault.statusMsg.className = `status-message ${type}`;
}

export function bindClick(el, callback, options = {}) {
    if (!el) {
        // Use your new logger!
        warn("UI.bindClick", "Attempted to bind click to a null element.");
        return;
    }

    el.addEventListener('click', (e) => {
        callback(e);
    }, options);
}

export function promptUnlockPasword() {
    logEl.textContent = "";

    login.signinBtn.setEnabled(false);
    vault.logoutBtn.setEnabled(true);
    login.pwdSection.setVisible(true);
}

export function showAuthorizedEmail(email) {
    log("UI.showAuthorizedEmail", "called - email:", email ? "axxx.gmail.com" : "empty");
    login.userEmailSpan.textContent = email;
}

// attach gesture logic
function setupTitleGesture() {
    log("UI.setupTitleGesture", "called");

    const el = document.getElementById("titleGesture");
    if (!el) return;

    let tapCount = 0;
    let tapTimer = null;

    el.addEventListener("pointerdown", async () => {
        if (!G.userEmail || G.sessionUnlocked) return;

        tapCount++;

        if (!tapTimer) {
            tapTimer = setTimeout(() => {
                tapCount = 0;
                tapTimer = null;
            }, 3000);
        }

        if (tapCount >= 5) {
            clearTimeout(tapTimer);
            tapCount = 0;
            tapTimer = null;

            await doHiddenGesture();
        }
    });
}

async function doHiddenGesture() {
    log("UI.doHiddenGesture", "called");

    if (!G.userEmail || G.sessionUnlocked) return;

    // ALWAYS activate intent first
    G.biometricIntent = true;
    await updateBiometricIndicator();

    const registered = await BM.isBiometricRegistered();

    if (registered) {
        await BM.attemptBiometricUnlock(async (password) => {
            await unlockIdentityFlow(password);
            await proceedAfterPasswordSuccess();
        });

        // After attempt, clear temporary intent
        G.biometricIntent = false;
        await updateBiometricIndicator();
    }
}

function initLoginUI() {
    log("UI.initLoginUI", "called");

    // Always show login view
    main.loginView.setVisible(true);
    main.vaultView.setVisible(false);

    // Hide password input sections until needed
    login.pwdSection.setVisible(false);
    login.confirmPwdSection.setVisible(false);

    signinBtn.setEnabled(true);

    // Reset any messages
    showUnlockMessage("");

    // Disable save button initially
    vault.saveBtn.setEnabled(false);
}

export function resetUnlockUi() {
    log("UI.resetUnlockUi", "called");

    // 3️⃣ Clear UI state
    main.vaultView.setVisible(false);
    main.loginView.setVisible(true);

    // Clear password inputs
    clearSensitiveFields();

    login.pwdSection.setVisible(false);
    login.confirmPwdSection.setVisible(false);

    // Reset button state
    login.unlockBtn.setText("Unlock");
    login.unlockBtn.setEnabled(true);

    updateBiometricIndicator();

    // Clear messages
    showUnlockMessage("");

    idleEvents.forEach(evt => {
        document.removeEventListener(evt, resetTimer);
    });

    clearTimeout(idleTimer);
    idleCallback = null;

    log("UI.resetUnlockUi", "G.authMode:", G.authMode)

    if (G.authMode !== "create" && G.authMode !== "unlock") {
        showAuthorizedEmail(null);
        signinBtn.setEnabled(true);
    }
}

export async function setupPasswordPrompt(mode, options = {}) {
    log("UI.setupPasswordPrompt", "called - mode:" + mode);

    login.authMsg.setVisible(false);

    clearSensitiveFields();
    showUnlockMessage("");

    // ✅ Always enable unlockBtn when switching mode
     login.unlockBtn.setEnabled(true);

    login.pwdSection.setVisible(true);

    if (mode === "unlock") {
        login.confirmPwdSection.setVisible(false);
        login.unlockBtn.setText("Unlock");
        login.unlockBtn.onClick(doUnlockClick);

        showUnlockMessage(options.migration ? "Identity missing password verifier — enter your password to upgrade." : "");
    } else if (mode === "create") {
        login.confirmPwdSection.setVisible(true);
        login.unlockBtn.setText("Create Password");
        login.unlockBtn.onClick(doCreatePasswordClick);
    } else if (mode === "recovery-request") {
        login.confirmPwdSection.setVisible(false);
        login.unlockBtn.setText("Recover");
        login.unlockBtn.onClick(doRecoverClick);
    }

    log("UI.setupPasswordPrompt", `G.recoveryRequest: ${G.recoveryRequest}, G.recoverySession: ${G.recoverySession}`);

    login.recoveryLnk.style.display = (G.recoveryRequest === true || G.recoverySession === true || !(await R.hasRecoveryKeyOnDrive())) ? "none" : "block";
}

function clearSensitiveFields() {
    login.pwdInput.clear();
    login.confirmPwdInput.clear();
}

export function showVaultUI({ readOnly = false, onIdle = () => { warn('idle timeout fired') } } = {}) {

    log("UI.showVaultUI", "called");

    // Hide login section
    main.loginView.setVisible(false);

    if (AU.isAdmin()) {
        vault.recoveryRotationBtn.setVisible(true);
        vault.recoveryRotationBtn.onClick(showRecoveryRotationUI);
    } else {
        warn("UI.showVaultUI", "Recovery option turned off for non-admin user");
        vault.recoveryRotationBtn.setVisible(false);
    }

    // Show main unlocked view
    main.vaultView.setVisible(true);

    // Update UI for read-only mode
    if (readOnly) {
        warn("UI.showVaultUI", "Unlocked UI in read-only mode: disabling save button");
        vault.saveBtn.setEnabled(false);
        vault.saveBtn.title = "Read-only mode: cannot save";
        vault.data.readOnly = true;
        main.vaultTitle.setText("Unlocked (Read-only)");
    } else {
        vault.saveBtn.setEnabled(true);
        vault.saveBtn.title = "";
        vault.data.readOnly = false;
        main.vaultTitle.setText("Unlocked");
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

export function updateLockStatusUI() {
    if (!G.driveLockState) return;

    const { expiresAt } = G.driveLockState.lock;
    //trace("updateLockStatusUI", `You hold the envelope lock (expires ${expiresAt})`);
    showStatusMessage(`Envelope lock expires at ${expiresAt}`, "success")
}

export function showRecoveryRotationStatusMessage(msg, type = "error") {
    if (!vaultRecoveryKey.statusMsg) return;

    vaultRecoveryKey.statusMsg.textContent = msg;
    vaultRecoveryKey.statusMsg.className = `status-message ${type}`;
}

function doCancelRecoveryRotationClick() {
    log("UI.doCancelRecoveryRotationClick", "called");
    vaultRecoveryKey.mainSection.setVisible(false);
    vault.mainSection.setVisible(true);
}

async function showRecoveryRotationUI() {
    log("UI.showRecoveryRotationUI", "called");

    const rotateMode = await R.hasRecoveryKeyOnDrive();

    vaultRecoveryKey.currentPwdSection.setVisible(rotateMode);
    vaultRecoveryKey.rotateBtn.setText(rotateMode ? "Rotate recovery" : "Create recovery");
    vaultRecoveryKey.mainSection.setVisible(true);
    vault.mainSection.setVisible(false);

    vaultRecoveryKey.rotateBtn.onClick((e) => doRotateRecoveryKeyClick(rotateMode));
    vaultRecoveryKey.cancelBtn.onClick((e) => doCancelRecoveryRotationClick());

    showRecoveryRotationStatusMessage("Create a recovery password. This allows account recovery if all devices are lost.", "status-message");
}

async function doRotateRecoveryKeyClick(rotateMode) {
    log("UI.doRotateRecoveryKeyClick", "called - Starting recovery key creation in rotateMode:", rotateMode);

    try {

        AU.requireAdmin();

        if (rotateMode) {
            const currPwd = vaultRecoveryKey.currentPwdInput.value;
            if (!currPwd || currPwd.length < C.PASSWORD_MIN_LEN || !(await R.verifyRecoveryPassword(currPwd))) {
                throw new Error("Incorrect current password");
            }
        }

        const pwd = vaultRecoveryKey.pwdInput.value;
        const confirm = vaultRecoveryKey.confirmPwdInput.value;

        if (!pwd || pwd.length < C.PASSWORD_MIN_LEN) {
            throw new Error("Recovery password must be at least 7 characters.");
        }
        if (pwd !== confirm) {
            throw new Error("Recovery passwords do not match.");
        }

        vaultRecoveryKey.currentPwdInput.clear();
        vaultRecoveryKey.pwdInput.clear();
        vaultRecoveryKey.confirmPwdInput.clear();

        vaultRecoveryKey.rotateBtn.setEnabled(false);
        showRecoveryRotationStatusMessage("Creating recovery key please wait...");

        const recoveryIdentity = await ID.createRecoveryIdentity(pwd);

        log("UI.doRotateRecoveryKeyClick", "Private key encrypted with recovery password");

        // 4️⃣ Ensure recovery folder
        const recoveryFolderId = await GD.ensureRecoveryFolder();

        // 5️⃣ Write private recovery file
        await GD.driveCreateJsonFile({ name:"recovery.private.json", parents: [recoveryFolderId], json: recoveryIdentity, overwrite: true });
        log("UI.doRotateRecoveryKeyClick", "recovery.private.json written");

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
                data: recoveryIdentity.publicKey
            }
        };

        await GD.driveCreateJsonFile({name:"recovery.public.json", parents: [recoveryFolderId], json: recoveryPublicJson, overwrite: true });
        log("UI.doRotateRecoveryKeyClick", "recovery.public.json written");

        // Refresh registry with newly uploaded recovery public key
        await E.buildKeyRegistryFromDrive(await GD.loadPublicKeyJsonsFromDrive());

        // 7️⃣ Add to envelope for CEK housekeeping
        await E.addRecoveryKeyToEnvelope({
            publicKey: recoveryIdentity.publicKey,
            keyId: recoveryIdentity.fingerprint
        });

        log("UI.doRotateRecoveryKeyClick", "Recovery key successfully established");
        //showRecoveryRotationStatusMessage("Recovery key created!", "status-message success");

        vaultRecoveryKey.rotateBtn.setEnabled(true);
        doCancelRecoveryRotationClick();
        showStatusMessage("Recovery key created!", "status-message success");

    } catch (err) {
        vaultRecoveryKey.rotateBtn.setEnabled(true);
        showRecoveryRotationStatusMessage(err.message || "Recovery setup failed", "status-message error");
    }
}

async function doCreatePasswordClick()  {
    log("UI.doCreatePasswordClick", "called");

    const pwd = login.pwdInput.value;
    const confirm = login.confirmPwdInput.value;

    if (!pwd || pwd.length < C.PASSWORD_MIN_LEN) {
        showUnlockMessage("Password too weak");
        return;
    }

    if (pwd !== confirm) {
        showUnlockMessage("Passwords do not match");
        return;
    }

    try {
         //SAFETY: Clear any existing local identity before creating new (could be recovery or normal flow)
        await ID.removeDeviceIdentity();
        await ID.createIdentity(pwd);
        await proceedAfterPasswordSuccess();
        log("UI.doCreatePasswordClick", "New identity created and unlocked");
    } catch (e) {
        showUnlockMessage(e.message);
    }
}

async function doUnlockClick() {

    log("UI.doUnlockClick", "called");

    const pwd = login.pwdInput.value;

    showUnlockMessage(""); // clear previous

    if (!pwd) {
        showUnlockMessage("Password cannot be empty");
        return;
    }

    try {
        await unlockIdentityFlow(pwd);
        await proceedAfterPasswordSuccess();
        G.unlockInProgress = false;
    } catch (e) {
        G.unlockInProgress = false;
        const def = Object.values(C.UNLOCK_ERROR_DEFS)
            .find(d => d.code === e.code);

        showUnlockMessage(def?.message || e.message || "Unlock failed");
        error("UI.doUnlockClick", "Unlock failed:", (def?.message || e.message));
    }
}

async function unlockIdentityFlow(pwd) {

    log("UI.unlockIdentityFlow", "called");

    if (!pwd || pwd.length < C.PASSWORD_MIN_LEN) {
        const e = new Error(C.UNLOCK_ERROR_DEFS.WEAK_PASSWORD.message);
        e.code = C.UNLOCK_ERROR_DEFS.WEAK_PASSWORD.code;
        throw e;
    }

    log("UI.unlockIdentityFlow", "Unlock attempt started for password:", (pwd ? "***" : "(empty)"));

    if (!G.accessToken) {
        const e = new Error(C.UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.message);
        e.code = C.UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.code;
        throw e;
    }

    let id = await ID.loadIdentity();

    if (!id) {
        error("UI.unlockIdentityFlow", "No local identity found — cannot unlock");
        const e = new Error(C.UNLOCK_ERROR_DEFS.NO_IDENTITY.message);
        e.code = C.UNLOCK_ERROR_DEFS.NO_IDENTITY.code;
        throw e;
    }
    //log("UI.unlockIdentityFlow", "Identity loaded:", !!id);
    log("UI.unlockIdentityFlow", "Local identity found");

    if (id && !id.passwordVerifier) {
        log("UI.unlockIdentityFlow", "Identity missing password verifier — attempting auto-migration");

        try {
            await ID.migrateIdentityWithVerifier(id, pwd);
            id = await ID.loadIdentity();
        } catch {
            const e = new Error(C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
            e.code = C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
            throw e;
        }
    }
    log("UI.unlockIdentityFlow", "password verifier found, skipped identity migration");

    // ─────────────────────────────
    // 🔐 AUTHORITATIVE PASSWORD CHECK
    // ─────────────────────────────
    let key;
    try {
        key = await CR.deriveKey(pwd, id.kdf);
        await ID.verifyPasswordVerifier(id.passwordVerifier, key);
    } catch {
        error("UI.unlockIdentityFlow", "passwordVerifier check failed for provided password");
        const e = new Error(C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
        e.code = C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
        throw e;
    }

    log("UI.unlockIdentityFlow", "Password verifier check succeeded");

    // ─────────────────────────────
    // 🔓 Attempt private key decrypt
    // ─────────────────────────────
    let decrypted = false;
    let decryptedPrivateKeyBytes = null;

    try {
        decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
        decrypted = true;
        log("UI.unlockIdentityFlow", "Identity private key successfully decrypted");
    } catch {
        warn("UI.unlockIdentityFlow", "Private key decryption failed, will attempt one time key rotation");
    }

    // ─────────────────────────────
    // 🔁 Single rotation retry
    // ─────────────────────────────
    if (!decrypted) {
        log("UI.unlockIdentityFlow", "Attempting device key rotation");

        await ID.rotateDeviceIdentity(pwd);
        id = await ID.loadIdentity();

        try {
            decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("UI.unlockIdentityFlow", "Decryption succeeded after rotation");
        } catch {
            warn("UI.unlockIdentityFlow", "Decryption still failing after rotation");
        }
    }

    // ─────────────────────────────
    // 🧨 Absolute Safari recovery
    // ─────────────────────────────
    if (!decrypted) {
        log("UI.unlockIdentityFlow", "Rotation failed (safari behavior?) — recreating identity");

        await ID.createIdentity(pwd);
        id = await ID.loadIdentity();

        if (!id) {
            error("UI.unlockIdentityFlow", "Faied to load existing identity - ", C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            const e = new Error(C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }

        try {
            key = await CR.deriveKey(pwd, id.kdf);
            decryptedPrivateKeyBytes = await decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("UI.unlockIdentityFlow", "Decryption succeeded after recreation");
        } catch {
            error("UI.unlockIdentityFlow", "post rotation decryption attempt failed - ", C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            const e = new Error(C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }
    }

    if (id.supersedes) {
        log("UI.unlockIdentityFlow", "Identity supersedes previous keyId:", id.supersedes);
    }

    // ─────────────────────────────
    // Session unlocked
    // ─────────────────────────────

    // 1️⃣ Cache current private key (imports + sets G.currentPrivateKey)
    await ID.cacheDecryptedPrivateKey(decryptedPrivateKeyBytes);

    // decrypt rotated identity keys
    await ID.decryptPreviousKeys(id, pwd);

    // 4️⃣ Attach decrypted key to identity + session globals
    id._sessionPrivateKey = G.currentPrivateKey;
    G.unlockedIdentity = id;
    G.sessionUnlocked = true;

    log("UI.unlockIdentityFlow", "G.unlockedIdentity set in memory for session");

    if (G.biometricIntent) {
        const registered = await BM.isBiometricRegistered();

        if (!registered) {
            try {
                log("UI.unlockIdentityFlow", "First-time biometric enrollment");
                await BM.enrollBiometric(pwd);
                log("UI.unlockIdentityFlow", "Biometric enrollment successful");
            } catch (err) {
                warn("UI.unlockIdentityFlow", "Biometric enrollment skipped or failed:", err);
            }
        } else {
            log("UI.unlockIdentityFlow", "Biometric already registered");
        }

        G.biometricIntent = false;
    }

    // 3️⃣ Immediately destroy password reference
    pwd = null;

    await updateBiometricIndicator();
    return id;
}

export async function proceedAfterPasswordSuccess() {
    log("UI.proceedAfterPasswordSuccess", "called");
    log("UI.proceedAfterPasswordSuccess", `G.unlockedIdentity exists: ${!!G.unlockedIdentity}, G.currentPrivateKey exists: ${!!G.currentPrivateKey}, fingerprint: ${G.unlockedIdentity?.fingerprint}`);
    log("UI.proceedAfterPasswordSuccess", "G.driveLockState:", G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null);

    log("UI.proceedAfterPasswordSuccess", "Proceeding to device public key exchange");
    await ID.ensureDevicePublicKey();

    // 1️⃣ Ensure envelope exists (read-only init only)
    await E.ensureEnvelope();      // 🔐 guarantees CEK + envelope

    log("UI.proceedAfterPasswordSuccess", `G.recoverySession: ${G.recoverySession}, G.recoveryCEK exists: ${!!G.recoveryCEK}`);

    // 2️⃣ Explicitly check authorization
    const auth = await E.checkEnvelopeAuthorization();

    if (!auth.authorized) {
        warn("UI.proceedAfterPasswordSuccess", "Device not authorized to decrypt envelope");
        setupPasswordPrompt("unlock");
        showUnlockMessage("This device is not authorized to access vault data. Retry after given access", "error");
        return;
    }

    // 3️⃣ Recovery key only after confirmed authorization
    // Recovery is now managed from Vault UI security menu
    //~await R.ensureRecoveryKey(async () => await promptRecoveryPasswordUI());

    // 4️⃣ Attempt write lock escalation (optional upgrade)
    if (G.driveLockState?.mode === "read") {
        log("UI.proceedAfterPasswordSuccess", "Attempting write lock escalation");
        await E.tryAcquireEnvelopeWriteLock({ onUpdate: updateLockStatusUI }); // must NOT throw if fails
    }

    // 5️⃣ Housekeeping only if we truly have write access
    if (G.driveLockState?.mode === "write" && G.driveLockState?.self) {
        log("UI.proceedAfterPasswordSuccess", "Performing CEK housekeepingfor all valid devices + recovery keys");
        await E.wrapCEKForRegistryKeys();
    } else {
        warn("UI.proceedAfterPasswordSuccess", "Skipping CEK housekeeping — G.driveLockState not ready or not writable");
        log("UI.proceedAfterPasswordSuccess", "Running in read-only mode");
    }

    if (G.recoverySession) {
        G.recoverySession = false;
        G.recoveryCEK = null;
    }

    // 6️⃣ Load vault payload
    await E.loadEnvelopePayloadToUI(text => vault.data.value = text);

    // 7️⃣ UI mode strictly derived from lock state
    const readOnly = G.driveLockState?.mode !== "write";

    if (readOnly) {
        warn("UI.proceedAfterPasswordSuccess", "Showing unlocked UI in read-only mode");
    }
    showVaultUI({ readOnly, onIdle: (type) => logout() });

    log("UI.proceedAfterPasswordSuccess", "IndexedDB dbs:", JSON.stringify(await indexedDB.databases()));

    U.dumpLocalStorageForDebug();
    log("UI.proceedAfterPasswordSuccess", "Unlock successful!@");
}

function doNeedRecoveryClick() {
    log("UI.doNeedRecoveryClick", "called");
    G.recoveryRequest = true;

    setupPasswordPrompt("recovery-request");
}

async function doRecoverClick() {
    log("UI.doRecoverClick", "called");

    showUnlockMessage("");

    const pwd = login.pwdInput.value;
    if (!pwd) {
        showUnlockMessage("Recovery password required");
        return;
    }

    try {
        await R.handleRecovery(pwd, onRecoveryCEKSuccess);
    } catch (err) {
        clearSensitiveFields();
        // Extract meaningful info from DOMException or normal Error
        const userMsg = err.message || `${err.name || 'RecoveryError'} — see console`;
        showUnlockMessage(`Recovery failed: ${userMsg}`);

        // Full error in console for debugging
        error("UI.doRecoverClick", "Recovery error:", err);
    }
    // 1. load recovery.private.json from Drive
    // 2. decrypt with password
    // 3. unwrap CEK
    // 4. generate new device identity
    // 5. wrap CEK, write envelope, unlock session
}

async function onRecoveryCEKSuccess() {
    log("UI.onRecoveryCEKSuccess", "called");

    setupPasswordPrompt("create");
}

async function doSaveClick() {
    log("UI.doSaveClick", "called");

    const text = vault.data.value;
    if (!text) {
        warn("UI.doSaveClick] Nothing to encrypt");
        return;
    }

    try {
        await E.encryptAndPersistPlaintext(text, { onUpdate: updateLockStatusUI });
        //vault.data.value = "";
    } catch (e) {
        error("UI.doSaveClick", "Encryption failed:", e.message);
    }
    alert("Saved!");
}

export async function updateBiometricIndicator() {
    log("UI.updateBiometricIndicator", "called");

    const el = document.getElementById("titleGesture");
    if (!el) return;

    el.classList.remove("bio-none","bio-armed");

    if (!window.PublicKeyCredential) {
        el.classList.add("bio-none");
        return;
    }

    if (!G.userEmail) {
        el.classList.add("bio-none");
        return;
    }

    if (G.biometricIntent) {
        el.classList.add("bio-armed");
    } else {
        el.classList.add("bio-none");
    }
}

async function copyLogsToClipboard() {
    if (!logEl) return;

    try {
        await navigator.clipboard.writeText(logEl.innerText);
        alert("Logs copied to clipboard");
    } catch (err) {
        error("UI.copyLogsToClipboard", "Failed to copy logs:", err);
    }
}

async function promptClearBiometricIndexedDB() {
    const confirmed = window.confirm("Are you sure you want to clear the biometric db? This cannot be undone.");

    if (!confirmed) {
        log("UI.promptClearBiometricIndexedDB] Deleting bio metric db canceled");
        return false;
    }

    await BM.clearBiometricIndexedDB();
    log("UI.promptClearBiometricIndexedDB", "db deleted successfully.");
    return true;
}

function promptClearLocalStorage() {
    const confirmed = window.confirm("Are you sure you want to clear all localStorage data for this app? This cannot be undone.");

    if (!confirmed) {
        log("UI.promptClearLocalStorage", "localStorage clear canceled");
        return false;
    }

    localStorage.clear();
    log("UI.promptClearLocalStorage", "localStorage cleared successfully.");
    return true;
}
