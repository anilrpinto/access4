import { C, G, LS, inReadOnlyMode, inWriteMode, clearGlobals, AU, BM, CR, ID, R, RG, SV, EN, log, trace, debug, info, warn, error } from '@/shared/exports.js';
import { runVaultAccessHousekeeping } from '@/core/janitor.js';
import { rootUI, loginUI } from '@/ui/loader.js';
import { openRecoveryModal } from '@/ui/restore-backup.js';

export async function loadLogin() {
    log("loginUI.loadLogin", "called");

    _init();

    _updateBiometricIndicator();
    _setupTitleGesture();

    loginUI.signinBtn.onClick(() => AU.initGIS());
    loginUI.signoutLnk.onClick(() => handleSignOut());
    loginUI.recoveryLnk.onClick(_doNeedRecoveryClick);
    loginUI.recoverBtn.onClick(_doRecoverClick);
    loginUI.restoreBackupLnk.onClick(openRecoveryModal);

    await BM.debugBiometricDB();
    await _updateBiometricIndicator();
}

export async function proceedAfterPasswordSuccess(pwd = null) {
    log("loginUI.proceedAfterPasswordSuccess", "called");
    //log("loginUI.proceedAfterPasswordSuccess", `G.unlockedIdentity exists: ${!!G.unlockedIdentity}, G.currentPrivateKey exists: ${!!G.currentPrivateKey}, fingerprint: ${G.unlockedIdentity?.fingerprint}`);
    //log("loginUI.proceedAfterPasswordSuccess", "G.driveLockState:", G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null);

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

    // Load the vault logic ONLY after we know the user is authorized
    const { loadVault, refreshVault } = await import('@/ui/vault.js');

    await loadVault(pwd, vaultData, { readOnly: inReadOnlyMode() });

    // Immediately destroy password reference here as well if missed in vault
    pwd = null;

    // AUTO-UPGRADE UI (When the 4s lock finishes)
    G.lockAcquisitionPromise.then((success) => {
        if (success && inWriteMode()) {
            log("loginUI.proceedAfterPasswordSuccess", "Background lock acquired. Upgrading UI to WRITE mode.");
            refreshVault(false);
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

    _clearSensitiveFields();
    showUnlockMessage("");

    // ✅ Always enable unlockBtn when switching mode
    loginUI.unlockBtn.setEnabled(true);
    loginUI.pwdSection.setVisible(true);

    if (mode === "unlock") {
        loginUI.confirmPwdSection.setVisible(false);
        loginUI.unlockBtn.setText("Unlock");
        loginUI.unlockBtn.onClick(_doUnlockClick);
        showUnlockMessage(options.migration ? "Identity missing password verifier — enter your password to upgrade." : "");
    } else if (mode === "create") {
        loginUI.confirmPwdSection.setVisible(true);
        loginUI.unlockBtn.setText("Create Password");
        loginUI.unlockBtn.onClick(_doCreatePasswordClick);
    } else if (mode === "recovery-request") {
        loginUI.confirmPwdSection.setVisible(false);
        loginUI.unlockBtn.setText("Recover");
        loginUI.unlockBtn.onClick(_doRecoverClick);
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
        _doDevelopmentCleanup();
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
    loginUI.authorizedNameSpan.clear();
    loginUI.signoutLnk.setVisible(false);

    loginUI.signinBtn.setVisible(true);
    loginUI.pwdSection.setVisible(false);
}

export function showUnlockMessage(msg, type = "error") {
    if (!loginUI.statusMsg) return;

    loginUI.statusMsg.setText(msg);
    loginUI.statusMsg.className = `status-message ${type}`;
}

export function showAuthMessage(msg, type = "error") {
    if (!loginUI.authMsg) return;

    loginUI.authMsg.setText(msg);
    loginUI.authMsg.className = `status-message ${type}`;
}

/** INTERNAL FUNCTIONS **/
function _init() {
    log("loginUI._init", "called");

    document.documentElement.classList.remove('vault-active');
    document.body.classList.remove('vault-active');

    //swapVisibility(rootUI.vaultView, rootUI.loginView);

    rootUI.loginView.setVisible(true).setFlex();
    rootUI.vaultView.setVisible(false).setFlex();

    loginUI.title.setText(`Login [v${C.APP_VERSION}]`);

    loginUI.signinBtn.setVisible(true);
    handleSignOut();

    // Clear password inputs
    _clearSensitiveFields();

    // Hide password input sections until needed
    loginUI.pwdSection.setVisible(false);
    loginUI.confirmPwdSection.setVisible(false);

    showUnlockMessage("");

    // Reset button state
    loginUI.unlockBtn.setText("Unlock");
    loginUI.unlockBtn.setEnabled(true);

    log("loginUI._init", "G.authMode:", G.authMode)
}

function _setupTitleGesture() {
    log("loginUI._setupTitleGesture", "called");

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

            await _doHiddenGesture();
        }
    });
}

async function _doHiddenGesture() {
    log("loginUI._doHiddenGesture", "called");

    if (!G.userEmail || G.sessionUnlocked) return;

    // ALWAYS activate intent first
    G.biometricIntent = true;
    await _updateBiometricIndicator();

    const registered = await BM.isBiometricRegistered();

    if (registered) {
        await BM.attemptBiometricUnlock(async (pwd) => {
            await _unlockIdentityFlow(pwd);
            await proceedAfterPasswordSuccess(pwd);
        });

        // After attempt, clear temporary intent
        G.biometricIntent = false;
        await _updateBiometricIndicator();
    }
}

async function _unlockIdentityFlow(pwd) {
    log("loginUI._unlockIdentityFlow", "called - Unlock attempt started for password:", (pwd ? "***" : "(empty)"));

    if (!G.accessToken) {
        const e = new Error(C.UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.message);
        e.code = C.UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.code;
        throw e;
    }

    let id = await ID.loadIdentity();

    if (!id) {
        error("loginUI._unlockIdentityFlow", "No local identity found — cannot unlock");
        const e = new Error(C.UNLOCK_ERROR_DEFS.NO_IDENTITY.message);
        e.code = C.UNLOCK_ERROR_DEFS.NO_IDENTITY.code;
        throw e;
    }
    //log("loginUI._unlockIdentityFlow", "Identity loaded:", !!id);
    log("loginUI._unlockIdentityFlow", "Local identity found");

    if (id && !id.passwordVerifier) {
        log("loginUI._unlockIdentityFlow", "Identity missing password verifier — attempting auto-migration");

        try {
            await ID.migrateIdentityWithVerifier(id, pwd);
            id = await ID.loadIdentity();
        } catch {
            const e = new Error(C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
            e.code = C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
            throw e;
        }
    }
    log("loginUI._unlockIdentityFlow", "password verifier found, skipped identity migration");

    // ─────────────────────────────
    // 🔐 AUTHORITATIVE PASSWORD CHECK
    // ─────────────────────────────
    let key;
    try {
        key = await CR.deriveKey(pwd, id.kdf);
        await ID.verifyPasswordVerifier(id.passwordVerifier, key);
    } catch {
        error("loginUI._unlockIdentityFlow", "passwordVerifier check failed for provided password");
        const e = new Error(C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
        e.code = C.UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
        throw e;
    }

    log("loginUI._unlockIdentityFlow", "Password verifier check succeeded");

    // ─────────────────────────────
    // 🔓 Attempt private key decrypt
    // ─────────────────────────────
    let decrypted = false;
    let decryptedPrivateKeyBytes = null;

    try {
        decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
        decrypted = true;
        log("loginUI._unlockIdentityFlow", "Identity private key successfully decrypted");
    } catch {
        warn("loginUI._unlockIdentityFlow", "Private key decryption failed, will attempt one time key rotation");
    }

    // ─────────────────────────────
    // 🔁 Single rotation retry
    // ─────────────────────────────
    if (!decrypted) {
        log("loginUI._unlockIdentityFlow", "Attempting device key rotation");

        await ID.rotateDeviceIdentity(pwd);
        id = await ID.loadIdentity();

        try {
            decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("loginUI._unlockIdentityFlow", "Decryption succeeded after rotation");
        } catch {
            warn("loginUI._unlockIdentityFlow", "Decryption still failing after rotation");
        }
    }

    // ─────────────────────────────
    // 🧨 Absolute Safari recovery
    // ─────────────────────────────
    if (!decrypted) {
        log("loginUI._unlockIdentityFlow", "Rotation failed (safari behavior?) — recreating identity");

        await ID.createIdentity(pwd);
        id = await ID.loadIdentity();

        if (!id) {
            error("loginUI._unlockIdentityFlow", "Faied to load existing identity - ", C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            const e = new Error(C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }

        try {
            key = await CR.deriveKey(pwd, id.kdf);
            decryptedPrivateKeyBytes = await CR.decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("loginUI._unlockIdentityFlow", "Decryption succeeded after recreation");
        } catch {
            error("loginUI._unlockIdentityFlow", "post rotation decryption attempt failed - ", C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            const e = new Error(C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = C.UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }
    }

    if (id.supersedes) {
        log("loginUI._unlockIdentityFlow", "Identity supersedes previous keyId:", id.supersedes);
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

    log("loginUI._unlockIdentityFlow", "G.unlockedIdentity set in memory for session");

    if (G.biometricIntent) {
        const registered = await BM.isBiometricRegistered();

        if (!registered) {
            try {
                log("loginUI._unlockIdentityFlow", "First-time biometric enrollment");
                await BM.enrollBiometric(pwd);
                log("loginUI._unlockIdentityFlow", "Biometric enrollment successful");
            } catch (err) {
                warn("loginUI._unlockIdentityFlow", "Biometric enrollment skipped or failed:", err);
            }
        } else {
            log("loginUI._unlockIdentityFlow", "Biometric already registered");
        }

        G.biometricIntent = false;
    }

    await _updateBiometricIndicator();
    return id;
}

function _clearSensitiveFields() {
    loginUI.pwdInput.clear();
    loginUI.confirmPwdInput.clear();
}

async function _onRecoveryCEKSuccess() {
    log("loginUI._onRecoveryCEKSuccess", "called");
    setupPasswordPrompt("create");
}

async function _updateBiometricIndicator() {
    log("loginUI._updateBiometricIndicator", "called");

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

async function _doUnlockClick() {
    log("loginUI._doUnlockClick", "called");

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

        await _unlockIdentityFlow(pwd);
        await proceedAfterPasswordSuccess(pwd);
        G.unlockInProgress = false;
    } catch (e) {
        G.unlockInProgress = false;
        const def = Object.values(C.UNLOCK_ERROR_DEFS)
            .find(d => d.code === e.code);

        showUnlockMessage(def?.message || e.message || "Unlock failed");
        error("loginUI._doUnlockClick", "Unlock failed:", (def?.message || e.message));
    }
}

function _doNeedRecoveryClick() {
    log("loginUI._doNeedRecoveryClick", "called");

    G.recoveryRequest = true;
    setupPasswordPrompt("recovery-request");
}

async function _doRecoverClick() {
    log("loginUI._doRecoverClick", "called");

    showUnlockMessage("");

    const pwd = loginUI.pwdInput.value;
    if (!pwd) {
        showUnlockMessage("Recovery password required");
        return;
    }

    try {
        await R.handleRecovery(pwd, _onRecoveryCEKSuccess);
    } catch (err) {
        //alert(err);
        _clearSensitiveFields();
        // Extract meaningful info from DOMException or normal Error
        const userMsg = err.message || `${err.name || 'RecoveryError'} — see console`;
        showUnlockMessage(`Recovery failed: ${userMsg}`);

        // Full error in console for debugging
        error("loginUI._doRecoverClick", "Recovery error:", err);
    }
    // 1. load recovery.private.json from Drive
    // 2. decrypt with password
    // 3. unwrap CEK
    // 4. generate new device identity
    // 5. wrap CEK, write envelope, unlock session
}

async function _doCreatePasswordClick()  {
    log("loginUI._doCreatePasswordClick", "called");

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
        log("loginUI._doCreatePasswordClick", "New identity created and unlocked");
    } catch (e) {
        showUnlockMessage(e.message);
    }
}

/*
 * TEMPORARY DEVELOPMENT CODE - REMOVE
 */
function _doDevelopmentCleanup() {
    if (G.settings.clearBioDbOnLoad)
        _promptClearBiometricIndexedDB();

    if (G.settings.clearLocalStorageOnLoad)
        _promptClearLocalStorage();

    if (G.settings.clearLastAutoBackupKey)
        _promptClearLastAutoBackupKey();
}

async function _promptClearBiometricIndexedDB() {
    const confirmed = window.confirm("Are you sure you want to clear the biometric db? This cannot be undone.");

    if (!confirmed) {
        log("loginUI._promptClearBiometricIndexedDB] Deleting bio metric db canceled");
        return false;
    }

    await BM.clearBiometricIndexedDB();
    log("loginUI._promptClearBiometricIndexedDB", "db deleted successfully.");
    return true;
}

async function _promptClearLocalStorage() {
    const confirmed = window.confirm("Are you sure you want to clear all localStorage data for this app? This cannot be undone.");

    if (!confirmed) {
        log("loginUI._promptClearLocalStorage", "localStorage clear canceled");
        return false;
    }

    LS.clear();
    log("loginUI._promptClearLocalStorage", "localStorage cleared successfully.");
    return true;
}

async function _promptClearLastAutoBackupKey() {
    const confirmed = window.confirm("Are you sure you want to clear SILENT BACKUP data for this app? This cannot be undone.");

    if (!confirmed) {
        log("loginUI._promptClearLastAutoBackupKey", "Silent Backup key clear canceled");
        return false;
    }

    LS.remove(C.LAST_AUTO_BACKUP_KEY);
    log("loginUI._promptClearLastAutoBackupKey", "Silent Backup key cleared successfully.");
    return true;
}
