import { C, G, clearGlobals, AU, BM, CR, ID, R, RG, SV, EN, U, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { runAdminBackup } from '@/core/backup.js';
import { runVaultAccessHousekeeping } from '@/core/janitor.js';

import { rootUI, loginUI, vaultUI } from '@/ui/loader.js';
import { openRecoveryModal } from '@/ui/restore-backup.js';
import { loadUI, swapVisibility } from '@/ui/uihelper.js';
import { loadVault, refreshVaultView, stopVaultIdleCheck } from '@/ui/vault.js';

function init() {
    log("loginUI.init", "called");

    //swapVisibility(rootUI.vaultView, rootUI.loginView);

    rootUI.loginView.setVisible(true).setFlex();
    rootUI.vaultView.setVisible(false).setFlex();

    loginUI.title.setText(`Login [v${C.APP_VERSION}]`);

    loginUI.signinBtn.setVisible(true);
    //showAuthorizedName();
    handleSignOut();

    // Clear password inputs
    clearSensitiveFields();

    // Hide password input sections until needed
    loginUI.pwdSection.setVisible(false);
    loginUI.confirmPwdSection.setVisible(false);

    showUnlockMessage("");

    // Reset button state
    loginUI.unlockBtn.setText("Unlock");
    loginUI.unlockBtn.setEnabled(true);

    log("loginUI.init", "G.authMode:", G.authMode)

    //TODO: Figure out the purpose of this check - temporarily removed - 03/18/2026
    /*    if (G.authMode !== "create" && G.authMode !== "unlock") {
            showAuthorizedName();
            //loginUI.signinBtn.setEnabled(true);
        }*/
}

// attach gesture logic
function setupTitleGesture() {
    log("loginUI.setupTitleGesture", "called");

    let tapCount = 0;
    let tapTimer = null;

    loginUI.title.addEventListener("pointerdown", async () => {
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
    log("loginUI.doHiddenGesture", "called");

    if (!G.userEmail || G.sessionUnlocked) return;

    // ALWAYS activate intent first
    G.biometricIntent = true;
    await updateBiometricIndicator();

    const registered = await BM.isBiometricRegistered();

    if (registered) {
        await BM.attemptBiometricUnlock(async (pwd) => {
            await unlockIdentityFlow(pwd);
            await proceedAfterPasswordSuccess(pwd);
        });

        // After attempt, clear temporary intent
        G.biometricIntent = false;
        await updateBiometricIndicator();
    }
}

async function unlockIdentityFlow(pwd) {

    log("loginUI.unlockIdentityFlow", "called");


    log("loginUI.unlockIdentityFlow", "Unlock attempt started for password:", (pwd ? "***" : "(empty)"));

    if (!G.accessToken) {
        const e = new Error(C.UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.message);
        e.code = C.UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.code;
        throw e;
    }

    let id = await ID.loadIdentity();

    if (!id) {
        error("loginUI.unlockIdentityFlow", "No local identity found — cannot unlock");
        const e = new Error(C.UNLOCK_ERROR_DEFS.NO_IDENTITY.message);
        e.code = C.UNLOCK_ERROR_DEFS.NO_IDENTITY.code;
        throw e;
    }
    //log("loginUI.unlockIdentityFlow", "Identity loaded:", !!id);
    log("loginUI.unlockIdentityFlow", "Local identity found");

    if (id && !id.passwordVerifier) {
        log("loginUI.unlockIdentityFlow", "Identity missing password verifier — attempting auto-migration");

        try {
            await ID.migrateIdentityWithVerifier(id, pwd);
            id = await ID.loadIdentity();
        } catch {
            const e = new Error(C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
            e.code = C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
            throw e;
        }
    }
    log("loginUI.unlockIdentityFlow", "password verifier found, skipped identity migration");

    // ─────────────────────────────
    // 🔐 AUTHORITATIVE PASSWORD CHECK
    // ─────────────────────────────
    let key;
    try {
        key = await CR.deriveKey(pwd, id.kdf);
        await ID.verifyPasswordVerifier(id.passwordVerifier, key);
    } catch {
        error("loginUI.unlockIdentityFlow", "passwordVerifier check failed for provided password");
        const e = new Error(C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
        e.code = C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
        throw e;
    }

    log("loginUI.unlockIdentityFlow", "Password verifier check succeeded");

    // ─────────────────────────────
    // 🔓 Attempt private key decrypt
    // ─────────────────────────────
    let decrypted = false;
    let decryptedPrivateKeyBytes = null;

    try {
        decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
        decrypted = true;
        log("loginUI.unlockIdentityFlow", "Identity private key successfully decrypted");
    } catch {
        warn("loginUI.unlockIdentityFlow", "Private key decryption failed, will attempt one time key rotation");
    }

    // ─────────────────────────────
    // 🔁 Single rotation retry
    // ─────────────────────────────
    if (!decrypted) {
        log("loginUI.unlockIdentityFlow", "Attempting device key rotation");

        await ID.rotateDeviceIdentity(pwd);
        id = await ID.loadIdentity();

        try {
            decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("loginUI.unlockIdentityFlow", "Decryption succeeded after rotation");
        } catch {
            warn("loginUI.unlockIdentityFlow", "Decryption still failing after rotation");
        }
    }

    // ─────────────────────────────
    // 🧨 Absolute Safari recovery
    // ─────────────────────────────
    if (!decrypted) {
        log("loginUI.unlockIdentityFlow", "Rotation failed (safari behavior?) — recreating identity");

        await ID.createIdentity(pwd);
        id = await ID.loadIdentity();

        if (!id) {
            error("loginUI.unlockIdentityFlow", "Faied to load existing identity - ", C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            const e = new Error(C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }

        try {
            key = await CR.deriveKey(pwd, id.kdf);
            decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("loginUI.unlockIdentityFlow", "Decryption succeeded after recreation");
        } catch {
            error("loginUI.unlockIdentityFlow", "post rotation decryption attempt failed - ", C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            const e = new Error(C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }
    }

    if (id.supersedes) {
        log("loginUI.unlockIdentityFlow", "Identity supersedes previous keyId:", id.supersedes);
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

    log("loginUI.unlockIdentityFlow", "G.unlockedIdentity set in memory for session");

    if (G.biometricIntent) {
        const registered = await BM.isBiometricRegistered();

        if (!registered) {
            try {
                log("loginUI.unlockIdentityFlow", "First-time biometric enrollment");
                await BM.enrollBiometric(pwd);
                log("loginUI.unlockIdentityFlow", "Biometric enrollment successful");
            } catch (err) {
                warn("loginUI.unlockIdentityFlow", "Biometric enrollment skipped or failed:", err);
            }
        } else {
            log("loginUI.unlockIdentityFlow", "Biometric already registered");
        }

        G.biometricIntent = false;
    }

    await updateBiometricIndicator();
    return id;
}

function clearSensitiveFields() {
    loginUI.pwdInput.clear();
    loginUI.confirmPwdInput.clear();
}

async function onRecoveryCEKSuccess() {
    log("loginUI.onRecoveryCEKSuccess", "called");
    setupPasswordPrompt("create");
}

async function updateBiometricIndicator() {
    log("loginUI.updateBiometricIndicator", "called");

    loginUI.title.classList.remove("bio-none","bio-armed");

    if (!window.PublicKeyCredential) {
        loginUI.title.classList.add("bio-none");
        return;
    }

    if (!G.userEmail) {
        loginUI.title.classList.add("bio-none");
        return;
    }

    if (G.biometricIntent) {
        loginUI.title.classList.add("bio-armed");
    } else {
        loginUI.title.classList.add("bio-none");
    }
}

/*
 * Click handlers
 */
async function doUnlockClick() {

    log("loginUI.doUnlockClick", "called");

    try {
        const pwd = loginUI.pwdInput.value;
        showUnlockMessage(""); // clear previous

        if (!pwd) {
            showUnlockMessage("Password cannot be empty");
            return;
        }

        if (pwd.length < C.PASSWORD_MIN_LEN) {
            const e = new Error(C.UNLOCK_ERROR_DEFS.WEAK_PASSWORD.message);
            e.code = C.UNLOCK_ERROR_DEFS.WEAK_PASSWORD.code;
            throw e;
        }

        loginUI.pwdInput.clear();

        await unlockIdentityFlow(pwd);
        await proceedAfterPasswordSuccess(pwd);
        G.unlockInProgress = false;
    } catch (e) {
        G.unlockInProgress = false;
        const def = Object.values(C.UNLOCK_ERROR_DEFS)
            .find(d => d.code === e.code);

        showUnlockMessage(def?.message || e.message || "Unlock failed");
        error("loginUI.doUnlockClick", "Unlock failed:", (def?.message || e.message));
    }
}

function doNeedRecoveryClick() {
    log("loginUI.doNeedRecoveryClick", "called");
    G.recoveryRequest = true;

    setupPasswordPrompt("recovery-request");
}

async function doRecoverClick() {
    log("loginUI.doRecoverClick", "called");

    showUnlockMessage("");

    const pwd = loginUI.pwdInput.value;
    if (!pwd) {
        showUnlockMessage("Recovery password required");
        return;
    }

    try {
        await R.handleRecovery(pwd, onRecoveryCEKSuccess);
    } catch (err) {
        //alert(err);
        clearSensitiveFields();
        // Extract meaningful info from DOMException or normal Error
        const userMsg = err.message || `${err.name || 'RecoveryError'} — see console`;
        showUnlockMessage(`Recovery failed: ${userMsg}`);

        // Full error in console for debugging
        error("loginUI.doRecoverClick", "Recovery error:", err);
    }
    // 1. load recovery.private.json from Drive
    // 2. decrypt with password
    // 3. unwrap CEK
    // 4. generate new device identity
    // 5. wrap CEK, write envelope, unlock session
}

async function doCreatePasswordClick()  {
    log("loginUI.doCreatePasswordClick", "called");

    const pwd = loginUI.pwdInput.value;
    const confirm = loginUI.confirmPwdInput.value;

    if (!pwd || pwd.length < C.PASSWORD_MIN_LEN) {
        showUnlockMessage("Password too weak");
        return;
    }

    if (pwd !== confirm) {
        showUnlockMessage("Passwords do not match");
        return;
    }

    loginUI.pwdInput.clear();
    loginUI.confirmPwdInput.clear();

    try {
        //SAFETY: Clear any existing local identity before creating new (could be recovery or normal flow)
        await ID.removeDeviceIdentity();
        await ID.createIdentity(pwd);
        await proceedAfterPasswordSuccess(pwd);
        log("loginUI.doCreatePasswordClick", "New identity created and unlocked");
    } catch (e) {
        showUnlockMessage(e.message);
    }
}

/**
 * EXPORTED FUNCTIONS
 */
export async function loadLogin() {
    log("loginUI.loadLogin", "called");

    init();

    updateBiometricIndicator();
    stopVaultIdleCheck();
    setupTitleGesture();

    loginUI.signinBtn.onClick(() => AU.initGIS());
    loginUI.signoutLnk.onClick(() => handleSignOut());
    loginUI.recoveryLnk.onClick(doNeedRecoveryClick);
    loginUI.recoverBtn.onClick(doRecoverClick);

    loginUI.restoreBackupLnk.onClick(openRecoveryModal);

    await BM.debugBiometricDB();
    await updateBiometricIndicator();
}

export async function proceedAfterPasswordSuccess(pwd = null) {
    log("loginUI.proceedAfterPasswordSuccess", "called");
    log("loginUI.proceedAfterPasswordSuccess", `G.unlockedIdentity exists: ${!!G.unlockedIdentity}, G.currentPrivateKey exists: ${!!G.currentPrivateKey}, fingerprint: ${G.unlockedIdentity?.fingerprint}`);
    log("loginUI.proceedAfterPasswordSuccess", "G.driveLockState:", G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null);

    log("loginUI.proceedAfterPasswordSuccess", "Proceeding to device public key check on drive");

    RG.loadRegistryFromCache();

    // 1️⃣ Initialize the identity and device record first (Local/Fast)
    const deviceRecord = await SV.ensureDevicePublicKey();

    // 2️⃣ Initialize G.driveLockState (This happens inside ensureEnvelope)
    const envelope = await EN.ensureEnvelope(deviceRecord);

    log("loginUI.proceedAfterPasswordSuccess", `G.recoverySession: ${G.recoverySession}, G.recoveryCEK exists: ${!!G.recoveryCEK}`);

    // 2️⃣ Explicitly check authorization
    const auth = await EN.checkEnvelopeAuthorization(envelope);

    if (!auth.authorized) {
        warn("loginUI.proceedAfterPasswordSuccess", "Device not authorized to decrypt envelope");
        setupPasswordPrompt("unlock");
        showUnlockMessage("This device is not authorized to access vault yet. Ask for access", "error");
        return;
    }

    // 3️⃣ NOW start the background lock (Now that driveLockState exists!)
    G.lockAcquisitionPromise = SV.tryAcquireEnvelopeWriteLock();

    let vaultData;
    // 6️⃣ Load vault payload
    await EN.loadEnvelopePayloadToUI(envelope, async data => vaultData = await JSON.parse(data));
    await loadVault(pwd, vaultData, { readOnly: G.driveLockState?.mode !== "write" });

    // Immediately destroy password reference here as well if missed in vault
    pwd = null;

    // 5️⃣ AUTO-UPGRADE UI (When the 4s lock finishes)
    G.lockAcquisitionPromise.then((success) => {
        if (success && G.driveLockState?.mode === "write") {
            log("loginUI.proceedAfterPasswordSuccess", "Background lock acquired. Upgrading UI to WRITE mode.");
            refreshVaultView(false);
        }
    }).catch(err => {
        warn("loginUI.proceedAfterPasswordSuccess", "Background lock failed:", err.message);
    });

    //log("loginUI.proceedAfterPasswordSuccess", "IndexedDB dbs:", JSON.stringify(await indexedDB.databases()));
    //U.dumpLocalStorageForDebug();

    runVaultAccessHousekeeping(envelope);

    log("loginUI.proceedAfterPasswordSuccess", "Initial unlock successful! (Background tasks continuing)");
}

export async function setupPasswordPrompt(mode, options = {}) {
    log("loginUI.setupPasswordPrompt", "called - mode:", mode);

    loginUI.authMsg.setVisible(false);

    clearSensitiveFields();
    showUnlockMessage("");

    // ✅ Always enable unlockBtn when switching mode
    loginUI.unlockBtn.setEnabled(true);
    loginUI.pwdSection.setVisible(true);

    if (mode === "unlock") {
        loginUI.confirmPwdSection.setVisible(false);
        loginUI.unlockBtn.setText("Unlock");
        loginUI.unlockBtn.onClick(doUnlockClick);
        showUnlockMessage(options.migration ? "Identity missing password verifier — enter your password to upgrade." : "");
    } else if (mode === "create") {
        loginUI.confirmPwdSection.setVisible(true);
        loginUI.unlockBtn.setText("Create Password");
        loginUI.unlockBtn.onClick(doCreatePasswordClick);
    } else if (mode === "recovery-request") {
        loginUI.confirmPwdSection.setVisible(false);
        loginUI.unlockBtn.setText("Recover");
        loginUI.unlockBtn.onClick(doRecoverClick);
    }

    log("loginUI.setupPasswordPrompt", `G.recoveryRequest: ${G.recoveryRequest}, G.recoverySession: ${G.recoverySession}`);

    loginUI.recoveryLnk.style.display = (G.recoveryRequest === true || G.recoverySession === true || !(await R.hasRecoveryKeyOnDrive())) ? "none" : "block";
}

// On Sign In Success
export function handleSignInSuccessStatus() {

    log("loginUI.handleSignInSuccessStatus", `called - name: ${G.authorizedName ? G.authorizedName?.slice(-2) : G.userEmail?.slice(-10)}`);

    const name = G.authorizedName ? G.authorizedName : G.userEmail;

    if (name) {
        // 1. Add the layout class
        loginUI.signinStatus.classList.add('signed-in');

        loginUI.welcomeSpan.setText("Hi,");
        loginUI.welcomeSpan.classList.remove('not-signed-in');
        loginUI.authorizedNameSpan.setText(name);
        loginUI.signoutLnk.setVisible(true);

        // temp code - REMOVE
        doDevelopmentCleanup();
    } else {
        handleSignOut();
    }
}

// On Sign Out
export function handleSignOut() {
    log("loginUI.handleSignOut", "called");

    clearGlobals();

    // 1. Remove the layout class (returns to center)
    loginUI.signinStatus.classList.remove('signed-in');

    // 2. Reset the UI
    loginUI.welcomeSpan.setText("Not signed in");
    loginUI.welcomeSpan.classList.add('not-signed-in');
    loginUI.authorizedNameSpan.setText("");
    loginUI.signoutLnk.setVisible(false);

    loginUI.signinBtn.setVisible(true);
    loginUI.pwdSection.setVisible(false);
}

export function showUnlockMessage(msg, type = "error") {
    if (!loginUI.statusMsg) return;

    loginUI.statusMsg.textContent = msg;
    loginUI.statusMsg.className = `status-message ${type}`;
}

export function showAuthMessage(msg, type = "error") {
    if (!loginUI.authMsg) return;

    loginUI.authMsg.textContent = msg;
    loginUI.authMsg.className = `status-message ${type}`;
}


/*
 * TEMPORARY DEVELOPMENT CODE - REMOVE
 */
function doDevelopmentCleanup() {
    if (G.settings.clearBioDbOnLoad)
        promptClearBiometricIndexedDB();

    if (G.settings.clearLocalStorageOnLoad)
        promptClearLocalStorage();

    if (G.settings.clearLastAutoBackupKey)
        promptClearLastAutoBackupKey();
}

async function promptClearBiometricIndexedDB() {
    const confirmed = window.confirm("Are you sure you want to clear the biometric db? This cannot be undone.");

    if (!confirmed) {
        log("loginUI.promptClearBiometricIndexedDB] Deleting bio metric db canceled");
        return false;
    }

    await BM.clearBiometricIndexedDB();
    log("loginUI.promptClearBiometricIndexedDB", "db deleted successfully.");
    return true;
}

async function promptClearLocalStorage() {
    const confirmed = window.confirm("Are you sure you want to clear all localStorage data for this app? This cannot be undone.");

    if (!confirmed) {
        log("loginUI.promptClearLocalStorage", "localStorage clear canceled");
        return false;
    }

    localStorage.clear();
    log("loginUI.promptClearLocalStorage", "localStorage cleared successfully.");
    return true;
}

async function promptClearLastAutoBackupKey() {
    const confirmed = window.confirm("Are you sure you want to clear SILENT BACKUP data for this app? This cannot be undone.");

    if (!confirmed) {
        log("loginUI.promptClearLastAutoBackupKey", "Silent Backup key clear canceled");
        return false;
    }

    localStorage.removeItem(C.LAST_AUTO_BACKUP_KEY);
    log("loginUI.promptClearLastAutoBackupKey", "Silent Backup key cleared successfully.");
    return true;
}
