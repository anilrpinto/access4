import { C, G, LS, ID, GD, CR, log, trace, debug, info, warn, error, isTraceEnabled } from '@/shared/exports.js';
import { loginUI } from '@/ui/loader.js';
import { handleSignInSuccessStatus, showAuthMessage, setupPasswordPrompt, proceedAfterPasswordSuccess, showUnlockMessage } from '@/ui/login.js';

export function initGIS() {

    log("AU.initGIS", `called for [v${C.APP_VERSION}]`);

    G.tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: C.CLIENT_ID,
        scope: C.SCOPES,
        callback: _handleAuth
    });

    if (G.settings.gisPrompt) {
        // Promts for accounts regardless (helpful in switching account)
        G.tokenClient.requestAccessToken({ prompt:"consent select_account" })
    } else {
        // Do not prompt for choosing other accounts if atleast one is signed in to Google already
        G.tokenClient.requestAccessToken({ prompt:"" });
    }
}

export function isGenesisUser() {
    const user = G.auth?.members?.[G.userEmail];
    return user?.role === "genesis";
}

export function isAdmin() {
    const user = G.auth?.members?.[G.userEmail];
    const role = user?.role;
    // Usually, Genesis has all Admin powers + more
    return role === "admin" || role === "genesis";
}

export function isMember() {
    return !!G.auth?.members?.[G.userEmail];
}

export function canWrite() {
    const user = G.auth?.members?.[G.userEmail];
    // If the user isn't in the list, or 'readonly' is explicitly true, return false.
    // If 'readonly' is missing, we assume they are NOT allowed to write (Safe Default).
    return user?.role === "genesis" || user?.readonly === false;
}

export function attachmentsAllowed() {
    const user = G.auth?.members?.[G.userEmail];
    return user?.role === "genesis" || user?.allowAttachments === true;
}

export function needsPasswordChange() {
    const user = G.auth?.members?.[G.userEmail];
    return user?.forcePasswordChange === true;
}

export function requireAdmin() {
    if (!isAdmin())
        throw new Error("Administrator privileges required");
}

/** INTERNAL FUNCTIONS **/
async function _handleAuth(resp) {
    log("AU._handleAuth", "called");

    try {
        //log("AU._handleAuth", "resp: " + JSON.stringify(resp));

        if (resp.error) {
            loginUI.signinBtn.setVisible(true);
            return;
        }

        loginUI.signinBtn.setVisible(false);

        G.accessToken = resp.access_token;
        trace("AU._handleAuth", `Acquired access token [${G.accessToken?.slice(0, 20)}...]`);

        await GD.fetchUserEmail();
        await handleSignInSuccessStatus();

        await GD.verifySharedRoot(C.ACCESS4_ROOT_ID);
        await GD.verifyWritable(C.ACCESS4_ROOT_ID);
        await _ensureAuthorization();

        _onAuthReady(G.userEmail);
    } catch (err) {
        error("AU._handleAuth", "Error after signin: " + err);
        showAuthMessage(`Initial authorization failed. ${err}`);
        loginUI.signinBtn.setVisible(true);
        //alert("Error after signin: " + err);
    }
}

async function _onAuthReady(email) {
    log("AU._onAuthReady", "called");

    try {
        const id = await ID.loadIdentity();

        if (!id) {
            // New device → create identity
            _setAuthMode("create");
            log("AU._onAuthReady", "New device detected, prompting password creation");
            return;
        }

        if (!id.passwordVerifier) {
            // Legacy identity → migration
            _setAuthMode("unlock", { migration: true });
            log("AU._onAuthReady", "Identity missing password verifier — migration mode");
            return;
        }

        showUnlockMessage("Checking for active session...", "info");

        // Attempt session restore first
        if (await _attemptSessionRestore()) {
            info("AU._onAuthReady", "Found an active authenticated browser session — skipping password prompt");

            log("AU._onAuthReady", "G.driveLockState after session restore:" + (G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null));
            showUnlockMessage("Authentication succeeded, proceeding to vault", "success");

            await proceedAfterPasswordSuccess();
            return;
        } else
            log("AU._onAuthReady", "No active pre-authenticated browser session found, proceeding in 'unlock' mode");

        // Returning user → unlock
        _setAuthMode("unlock");

    } catch (e) {
        error("AU._onAuthReady", "Error loading identity:", e.message);
        showUnlockMessage("Failed to load identity. Try again.");
        loginUI.signinBtn.setEnabled(true);
    }
}

function _setAuthMode(mode, options = {}) {
    log("AU._setAuthMode", "called - mode: " + mode);
    G.authMode = mode;

    setupPasswordPrompt(mode, options);
}

async function _attemptSessionRestore() {
    log("AU._attemptSessionRestore", "called");

    try {
        const storedSessionKeyB64 = sessionStorage.getItem("sv_session_private_key");

        if (!storedSessionKeyB64) {
            warn("AU._attemptSessionRestore", "No session private key found in memory (sessionStorage)");
            return false;
        }

        log("AU._attemptSessionRestore", "Restoring session private key...");

        G.currentPrivateKey = await CR.importRSAPrivateKeyFromB64(storedSessionKeyB64, ["decrypt", "unwrapKey"]);

        // Load identity from localStorage
        const id = await ID.loadIdentity();
        log("AU._attemptSessionRestore", "loadIdentity returned:", !!id);

        if (!id) {
            log("AU._attemptSessionRestore", "Identity not found in localStorage despite private key");
            return false;
        }

        // Attach session key and update Global State
        id._sessionPrivateKey = G.currentPrivateKey;
        G.unlockedIdentity = id;
        G.sessionUnlocked = true;

        log("AU._attemptSessionRestore", "Session restored successfully.");

        log("AU._attemptSessionRestore", `G.unlockedIdentity exists: ${!!G.unlockedIdentity}, fingerprint: ${G.unlockedIdentity?.fingerprint},
            deviceId: ${G.unlockedIdentity?.deviceId}, G.currentPrivateKey exists: ${!!G.currentPrivateKey}`);
        trace("AU._attemptSessionRestore", `Fingerprint: ${id.fingerprint}`);

        return true;

    } catch (err) {
        error("AU._attemptSessionRestore", "Session restore failed, clearing storage:", err.message);
        sessionStorage.removeItem("sv_session_private_key");
        return false;
    }
}

async function _ensureAuthorization() {
    log("AU._ensureAuthorization", `called - verifying against ${C.AUTH_FILE_NAME}`);

    // 1️⃣ Try to get the ID from cache first
    let fileId = LS.get(C.AUTH_FILE_ID_CACHE);
    let existing;

    if (fileId) {
        // FAST PATH: Direct ID lookup (No search/cold start)
        existing = await GD.readJsonByFileId(fileId).catch(() => null);
    }

    // 2️⃣ Fallback to Name search only if ID is missing or dead
    if (!existing) {
        warn("AU._ensureAuthorization", "Cache miss or file moved. Falling back to Name search...");
        existing = await GD.readJsonByName(C.AUTH_FILE_NAME);

        if (existing?.fileId) {
            LS.set(C.AUTH_FILE_ID_CACHE, existing.fileId);
        }
    }

    let data;
    if (existing) {
        data = existing.json;
    } else {
        log("AU._ensureAuthorization", "Creating genesis authorization...");

        const preAuth = G.settings.preAuthMembers || {};

        data = {
            version: 1,
            created: new Date().toISOString(),
            members: {
                [G.userEmail]: { role: "genesis", readonly: false, allowAttachments: true, forcePasswordChange: false },
                ...preAuth
            }
        };

        const fileId = await GD.upsertJsonFile({ name: C.AUTH_FILE_NAME, parentId: C.ACCESS4_ROOT_ID, json: data });

        if (fileId) LS.set(C.AUTH_FILE_ID_CACHE, fileId);

        log("AU._ensureAuthorization", `Genesis authorization created for ${G.userEmail}`);
    }

    G.auth = data;

    if (isTraceEnabled())
        trace("AU._ensureAuthorization", `G.auth: ${JSON.stringify(G.auth)}`);

    if (!isMember())
        throw new Error("Unauthorized user");

    log("AU._ensureAuthorization", "Signed in user is authorized to proceed, admin:", isAdmin());
}
