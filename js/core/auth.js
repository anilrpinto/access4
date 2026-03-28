import { C, G, ID, GD, CR, log, trace, debug, info, warn, error, isTraceEnabled } from '@/shared/exports.js';

import { loginUI } from '@/ui/loader.js';

import { handleSignInSuccessStatus, showAuthMessage, setupPasswordPrompt,
        proceedAfterPasswordSuccess, showUnlockMessage } from '@/ui/login.js';

async function handleAuth(resp) {
    log("AU.handleAuth", "called");

    try {
        //log("AU.handleAuth", "resp: " + JSON.stringify(resp));

        if (resp.error) {
            loginUI.signinBtn.setVisible(true);
            return;
        }

        loginUI.signinBtn.setVisible(false);

        G.accessToken = resp.access_token;
        trace("AU.handleAuth", `Acquired access token [${G.accessToken?.slice(0, 20)}...]`);

        await GD.fetchUserEmail();
        await handleSignInSuccessStatus();

        await GD.verifySharedRoot(C.ACCESS4_ROOT_ID);
        await GD.verifyWritable(C.ACCESS4_ROOT_ID);
        await ensureAuthorization();

        onAuthReady(G.userEmail);
    } catch (err) {
        error("AU.handleAuth", "Error after signin: " + err);
        showAuthMessage(err);
        loginUI.signinBtn.setVisible(true);
        //alert("Error after signin: " + err);
    }
}

async function onAuthReady(email) {
    log("AU.onAuthReady", "called");

    try {
        const id = await ID.loadIdentity();

        if (!id) {
            // New device → create identity
            setAuthMode("create");
            log("AU.onAuthReady", "New device detected, prompting password creation");
            return;
        }

        if (!id.passwordVerifier) {
            // Legacy identity → migration
            setAuthMode("unlock", { migration: true });
            log("AU.onAuthReady", "Identity missing password verifier — migration mode");
            return;
        }

        showUnlockMessage("Checking for active session...", "info");

        // Attempt session restore first
        if (await attemptSessionRestore()) {
            info("AU.onAuthReady", "Found an active authenticated browser session — skipping password prompt");

            log("AU.onAuthReady", "G.driveLockState after session restore:" + (G.driveLockState ? { mode: G.driveLockState.mode, self: G.driveLockState.self } : null));
            showUnlockMessage("Authentication succeeded, proceeding to vault", "success");

            await proceedAfterPasswordSuccess();
            return;
        } else
            log("AU.onAuthReady", "No active pre-authenticated browser session found, proceeding in 'unlock' mode");

        // Returning user → unlock
        setAuthMode("unlock");

    } catch (e) {
        error("AU.onAuthReady", "Error loading identity:", e.message);
        showUnlockMessage("Failed to load identity. Try again.");
        loginUI.signinBtn.setEnabled(true);
    }
}

function setAuthMode(mode, options = {}) {
    log("AU.setAuthMode", "called - mode: " + mode);
    G.authMode = mode;

    setupPasswordPrompt(mode, options);
}

async function attemptSessionRestore() {
    log("AU.attemptSessionRestore", "called");

    try {
        const storedSessionKeyB64 = sessionStorage.getItem("sv_session_private_key");

        if (!storedSessionKeyB64) {
            warn("AU.attemptSessionRestore", "No session private key found in memory (sessionStorage)");
            return false;
        }

        log("AU.attemptSessionRestore", "Restoring session private key...");

        G.currentPrivateKey = await CR.importRSAPrivateKeyFromB64(storedSessionKeyB64, ["decrypt", "unwrapKey"]);

        // Load identity from localStorage
        const id = await ID.loadIdentity();
        log("AU.attemptSessionRestore", "loadIdentity returned:", !!id);

        if (!id) {
            log("AU.attemptSessionRestore", "Identity not found in localStorage despite private key");
            return false;
        }

        // Attach session key and update Global State
        id._sessionPrivateKey = G.currentPrivateKey;
        G.unlockedIdentity = id;
        G.sessionUnlocked = true;

        log("AU.attemptSessionRestore", "Session restored successfully.");

        log("AU.attemptSessionRestore", `G.unlockedIdentity exists: ${!!G.unlockedIdentity}, fingerprint: ${G.unlockedIdentity?.fingerprint},
            deviceId: ${G.unlockedIdentity?.deviceId}, G.currentPrivateKey exists: ${!!G.currentPrivateKey}`);
        trace("AU.attemptSessionRestore", `Fingerprint: ${id.fingerprint}`);

        return true;

    } catch (err) {
        error("AU.attemptSessionRestore", "Session restore failed, clearing storage:", err.message);
        sessionStorage.removeItem("sv_session_private_key");
        return false;
    }
}

async function ensureAuthorization() {
    log("AU.ensureAuthorization", `called - verifying against ${C.AUTH_FILE_NAME}`);

    const existing = await GD.readJsonByName(C.AUTH_FILE_NAME);

    let data;

    if (existing)
        data = existing.json;
    else {
        log("AU.ensureAuthorization", `${C.AUTH_FILE_NAME} not found, creating genesis authorization...`);

        data = { admins: [G.userEmail], members: [G.userEmail, ...G.settings.preAuthMembers], created: new Date().toISOString(), version: 1 };
        await GD.upsertJsonFile({ name: C.AUTH_FILE_NAME, parentId: C.ACCESS4_ROOT_ID, json: data });

        log("AU.ensureAuthorization", `Genesis authorization created for ${G.userEmail}`);
    }

    // Cache authorization structure for use in the app
    G.auth = {
        admins: data.admins || [],
        members: data.members || []
    };

    if (isTraceEnabled())
        trace("AU.ensureAuthorization", `G.auth: ${JSON.stringify(G.auth)}`);

    if (!G.auth.admins.includes(G.userEmail) && !G.auth.members.includes(G.userEmail))
        throw new Error("Unauthorized user");

    log("AU.ensureAuthorization", "Signed in user is authorized to proceed, admin:", isAdmin());
}

/**
 * EXPORTED FUNCTIONS
 */
export function initGIS() {

    log("AU.initGIS", `called for [v${C.APP_VERSION}]`);

    G.tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: C.CLIENT_ID,
        scope: C.SCOPES,
        callback: handleAuth
    });

    if (G.settings.gisPrompt) {
        // Promts for accounts regardless (helpful in switching account)
        G.tokenClient.requestAccessToken({ prompt:"consent select_account" })
    } else {
        // Do not prompt for choosing other accounts if atleast one is signed in to Google already
        G.tokenClient.requestAccessToken({ prompt:"" });
    }
}

export function isAdmin() {
    return G.auth?.admins?.includes(G.userEmail);
}

export function isMember() {
    return G.auth?.members?.includes(G.userEmail);
}

export function requireAdmin() {
    if (!isAdmin())
        throw new Error("Administrator privileges required");
}