"use strict";

/* ================= CONFIG ================= */
const CLIENT_ID = "738922366916-ppn1c24mp9qamr6pdmjqss3cqjmvqljv.apps.googleusercontent.com";
const SCOPES = "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email";
const ACCESS4_ROOT_ID = "1zQPiXTCDlPjzgD1YZiVKsRB2s4INUS_g";
const AUTH_FILE_NAME = "authorized.json";
const PUBKEY_FOLDER_NAME = "pub-keys";

const DEVICE_ID_KEY = "access4.device.id";

const HEARTBEAT_INTERVAL = 10_000; // 10 seconds
const LOCK_TTL_MS = 30_000;        // must be > heartbeat

/* ================= STATE ================= */
let tokenClient;
let accessToken = null;
let userEmail = null;
let needsIdentitySetup = false;
let unlockedPassword = null;
let biometricIntent = false;
let biometricRegistered = false;

let keyRegistry = {
    version: 1,
    loadedAt: null,

    accounts: {},

    flat: {
        activeDevices: [],
        deprecatedDevices: [],
        recoveryKeys: []
    }
};

let driveLockState = null;
let unlockInProgress = false;
let authMode;

let unlockedIdentity = null;   // Holds decrypted identity for current session
let currentPrivateKey = null;
let sessionUnlocked = false;

/* ================= DOM ================= */
let userEmailSpan;
let signinBtn;
let passwordSection;
let confirmPasswordSection;
let unlockBtn;

let titleUnlocked;
let plaintextInput;
let saveBtn;

let loginView;
let unlockedView;
let passwordInput;
let confirmPasswordInput;

let logoutBtn;

let logEl;
let idleTimer;

const UNLOCK_ERROR_DEFS = {
    WEAK_PASSWORD: {
        code: "WEAK_PASSWORD",
        message: "Password must be at least 7 characters long."
    },
    NO_ACCESS_TOKEN: {
        code: "NO_ACCESS_TOKEN",
        message: "Authentication not ready. Please sign in again."
    },
    INCORRECT_PASSWORD: {
        code: "INCORRECT_PASSWORD",
        message: "Incorrect password. Please try again."
    },
    SAFARI_RECOVERY: {
        code: "SAFARI_RECOVERY",
        message: "Browser recovery required. Identity was recreated."
    },
    PASSWORD_SETUP_REQUIRED: {
        code: "PASSWORD_SETUP_REQUIRED",
        message: "Detected need for a password set up."
    },
    NO_IDENTITY: {
        code: "NO_IDENTITY",
        message: "No identity found on this device. Please create one first."
    },
    UNKNOWN: {
        code: "UNKNOWN_ERROR",
        message: "An unexpected error occurred."
    }
};


/* ================= LOG ================= */
function log(msg) {
    console.log(msg);
    logEl.textContent += msg + "\n";
}

/* ================= BOOT + AUTHENTICATION FLOW ================= */

function onLoad() {

    // Cache DOM
    userEmailSpan = document.getElementById("userEmailSpan");
    signinBtn = document.getElementById("signinBtn");
    passwordSection = document.getElementById("passwordSection");
    confirmPasswordSection = document.getElementById("confirmPasswordSection");
    unlockBtn = document.getElementById("unlockBtn");
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

    // Wire handlers
    signinBtn.onclick = handleSignInClick;
    unlockBtn.onclick = handleUnlockClick;
    logoutBtn.onclick = handleLogoutClick;

    saveBtn.onclick = handleSaveClick;

    log("📌 onLoad start");
    log("🧠 sessionStorage sv_session_private_key exists:" + !!sessionStorage.getItem("sv_session_private_key"));
    log("🧩 in-memory unlockedIdentity:" + !!unlockedIdentity);
    log("🧩 in-memory currentPrivateKey:" + !!currentPrivateKey);


    setupTitleGesture();

    initLoginUI();

    ["mousemove", "keydown", "click"].forEach(e =>
    document.addEventListener(e, resetIdleTimer)
    );

    log("UI ready");
}

/* --------- GOOGLE SIGN-IN start --------- */
function handleSignInClick() {
    signinBtn.disabled = true;
    logEl.textContent = "";
    passwordSection.style.display = "block";

    tokenClient.requestAccessToken({ prompt: "consent select_account" });
}

function initGIS() {
    tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: CLIENT_ID,
        scope: SCOPES,
        callback: handleAuth
    });
    tokenClient.requestAccessToken({
        prompt: ""
    });
}

/* --------- GOOGLE SIGN-IN end --------- */

async function handleAuth(resp) {
    if (resp.error) return;

    accessToken = resp.access_token;
    log("✓ Access token acquired");

    await fetchUserEmail();
    await verifySharedRoot();
    await verifyWritable(ACCESS4_ROOT_ID);
    await ensureAuthorization();

    signinBtn.disabled = true;
    logoutBtn.disabled = false;
    passwordSection.style.display = "block";

    biometricRegistered = !!localStorage.getItem(bioCredKey());

    onAuthReady(userEmail);
}

async function onAuthReady(email) {
    userEmailSpan.textContent = email;

    try {
        const id = await loadIdentity();

        if (!id) {
            // New device → create identity
            setAuthMode("create");
            log("🆔 New device detected, prompting password creation");
            return;
        }

        if (!id.passwordVerifier) {
            // Legacy identity → migration
            setAuthMode("unlock", { migration: true });
            log("🧭 Identity missing password verifier — migration mode");
            return;
        }

        // Attempt session restore first
        if (await attemptSessionRestore()) {
            log("🔓 Session restore successful — skipping password");

            log("🧩 driveLockState after session restore:" + (driveLockState ? { mode: driveLockState.mode, self: driveLockState.self } : null));
            await ensureDevicePublicKey();
            await proceedAfterPasswordSuccess();
            return;
        }

        // Returning user → unlock
        setAuthMode("unlock");
        log("📁 Existing device detected, prompting unlock");


    } catch (e) {
        log("❌ Error loading identity: " + e.message);
        unlockMessage.textContent = "Failed to load identity. Try again.";
    }
}

/* ---------------------- Load identity ---------------------- */
async function loadIdentity() {

    log("📌 loadIdentity called");
    log("📌 sessionUnlocked:" + !!sessionUnlocked);
    log("📌 unlockedIdentity:" + !!unlockedIdentity);

    if (sessionUnlocked && unlockedIdentity) {
        log("✅ Returning unlockedIdentity from memory");
        return unlockedIdentity;
    }

    return loadIdentityFromStorage();
}

/* ---------------------- Load from localStorage only ---------------------- */
function loadIdentityFromStorage() {
    const raw = localStorage.getItem(identityKey());
    log("📦 Identity in localStorage exists:" + !!raw);
    if (!raw) return null;

    try {
        const id = JSON.parse(raw);
        log("✅ Identity loaded from localStorage");
        if (sessionUnlocked && currentPrivateKey) {
            id._sessionPrivateKey = currentPrivateKey;
        }
        return id;
    } catch (e) {
        log("❌ Failed to parse identity:" + e);
        return null;
    }
}

function setAuthMode(mode, options = {}) {
    authMode = mode;

    // reset fields
    resetUnlockUi();

    // ✅ Always enable unlockBtn when switching mode
    unlockBtn.disabled = false;

    passwordSection.style.display = "block";

    if (mode === "unlock") {
        confirmPasswordSection.style.display = "none";
        unlockBtn.textContent = "Unlock";
        unlockBtn.onclick = handleUnlockClick;

        showUnlockMessage(options.migration
            ? "Identity missing password verifier — enter your password to upgrade."
            : "");
    }

    if (mode === "create") {
        confirmPasswordSection.style.display = "block";
        unlockBtn.textContent = "Create Password";
        unlockBtn.onclick = handleCreatePasswordClick;
    }
}

async function attemptSessionRestore() {
    log("📌 attemptSessionRestore start");

    try {
        const stored = sessionStorage.getItem("sv_session_private_key");

        log("🧠 sessionStorage private key exists: " + !!stored);
        if (!stored) {
            log("⚠️ No session private key found in sessionStorage");
            return false;
        }

        log("🧠 Restoring session private key...");

        const bytes = Uint8Array.from(atob(stored), c => c.charCodeAt(0));

        currentPrivateKey = await crypto.subtle.importKey(
            "pkcs8",
            bytes,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt", "unwrapKey"]
        );

        // Load identity from localStorage
        const id = await loadIdentity(); // gets raw identity
        log("📦 loadIdentity returned:", !!id);
        if (!id) {
            log("⚠️ Identity not found in localStorage despite private key");
            return false;
        }

        // ✅ Attach session key
        id._sessionPrivateKey = currentPrivateKey;

        // ✅ Store as unlocked identity for loadIdentity()
        unlockedIdentity = id;

        sessionUnlocked = true;
        log("🧠 Session restored from sessionStorage");

        log("♻ Session restore check:");
        log("   unlockedIdentity exists:" + !!unlockedIdentity);
        log("   fingerprint:" + unlockedIdentity?.fingerprint);
        log("   deviceId:" + unlockedIdentity?.deviceId);
        log("   currentPrivateKey exists:" + !!currentPrivateKey);
        log("   privateKey type:" + currentPrivateKey?.type);
        log("   privateKey algorithm:" + JSON.stringify(currentPrivateKey?.algorithm));

        return true;

    } catch (err) {
        log("⚠️ Session restore failed, clearing");
        sessionStorage.removeItem("sv_session_private_key");
        return false;
    }
}

async function ensureDevicePublicKey() {
    const folder = await findOrCreateUserFolder();
    const id = await loadIdentity();
    if (!id) throw new Error("Local identity missing");

    const deviceId = getDeviceId();
    const filename = `${userEmail}__${deviceId}.json`;

    const q = `'${folder}' in parents and name='${filename}'`;
    const res = await driveFetch(buildDriveUrl("files", { q, fields: "files(id)" }));

    // Compute fingerprint (canonical keyId)
    const pubBytes = Uint8Array.from(atob(id.publicKey), c => c.charCodeAt(0));
    const hashBuffer = await crypto.subtle.digest("SHA-256", pubBytes);
    const fingerprint = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

    const pubData = {
        version: "1",
        account: userEmail,
        deviceId,
        keyId: fingerprint,
        fingerprint,
        state: "active",
        role: "device",
        supersedes: id.supersedes || null,
        created: new Date().toISOString(),
        algorithm: {
            type: "RSA",
            usage: ["wrapKey"],
            modulusLength: 2048,
            hash: "SHA-256"
        },
        publicKey: {
            format: "spki",
            encoding: "base64",
            data: id.publicKey
        },
        deviceName: `${navigator.platform} - ${navigator.userAgent}`.substring(0, 64),
        browser: navigator.userAgentData?.brands?.map(b => b.brand).join(",") || navigator.userAgent,
        os: navigator.platform
    };

    if (res.files.length > 0) {
        const fileId = res.files[0].id;

        // --- PATCH only the content fields (Drive forbids updating certain metadata) ---
        const contentOnly = {
            publicKey: pubData.publicKey,
            state: pubData.state,
            supersedes: pubData.supersedes
        };

        await driveFetch(buildDriveUrl(`files/${fileId}`, { uploadType: "media" }), {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(contentOnly)
        });

        log("🔁 Device public key updated");
        return;
    }

    // File doesn't exist → create new
    await driveMultipartUpload({
        metadata: { name: filename, parents: [folder] },
        content: JSON.stringify(pubData)
    });

    log("🆕 Device public key uploaded");
}

async function findOrCreateUserFolder() {
    const rootQ = `'${ACCESS4_ROOT_ID}' in parents and name='${PUBKEY_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder'`;
    const rootRes = await driveFetch(buildDriveUrl("files", {
        q: rootQ,
        fields: "files(id)"
    }));
    const root = rootRes.files.length ? rootRes.files[0].id :
    (await driveFetch(buildDriveUrl("files"), {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            name: PUBKEY_FOLDER_NAME,
            mimeType: "application/vnd.google-apps.folder",
            parents: [ACCESS4_ROOT_ID]
        })
    })).id;

    const userQ = `'${root}' in parents and name='${userEmail}' and mimeType='application/vnd.google-apps.folder'`;
    const userRes = await driveFetch(buildDriveUrl("files", {
        q: userQ,
        fields: "files(id)"
    }));
    if (userRes.files.length) return userRes.files[0].id;

    const folder = await driveFetch(buildDriveUrl("files"), {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            name: userEmail,
            mimeType: "application/vnd.google-apps.folder",
            parents: [root]
        })
    });

    return folder.id;
}

function getDeviceId() {
    let id = localStorage.getItem(DEVICE_ID_KEY);
    if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem(DEVICE_ID_KEY, id);
        log("🆔 New device ID generated");
    }
    return id;
}

async function proceedAfterPasswordSuccess() {
    log("[proceedAfterPasswordSuccess] start");
    log("🧠 unlockedIdentity exists: " + !!unlockedIdentity);
    log("🧠 currentPrivateKey exists: " + !!currentPrivateKey);
    log("🧩 driveLockState:", driveLockState ? { mode: driveLockState.mode, self: driveLockState.self } : null);

    await ensureEnvelope();      // 🔐 guarantees CEK + envelope
    await ensureRecoveryKey();   // 🔑 may block UI

    // ---- New housekeeping: wrap CEK for registry ----
    if (driveLockState?.self && driveLockState.envelopeName === "envelope.json") {
        log("🧹 Performing CEK housekeeping for all valid devices + recovery keys");
        await wrapCEKForRegistryKeys();  // helper handles load & write
    } else {
        log("⚠️ Skipping CEK housekeeping — driveLockState not ready or not writable");
    }

    await loadEnvelopePayloadToUI();

    // Show unlocked UI in read-only mode if no write lock
    const readOnly = !driveLockState?.self || driveLockState.mode !== "write";
    if (readOnly) {
        log("⚠️ Showing unlocked UI in read-only mode");
    }
    showVaultUI({ readOnly });

    log("🔑 Unlock successful!");
}

async function ensureEnvelope() {
    const envelopeName = "envelope.json";

    // ─── Fast path: skip lock re-acquire if already initialized ───
    if (driveLockState && driveLockState.mode) {
        log("[ensureEnvelope] Drive lock already initialized — skipping lock acquisition");
    } else {
        const lockFile = await readLockFromDrive(envelopeName);
        const { identity, self } = await getDriveLockSelf();
        const evalResult = evaluateEnvelopeLock(lockFile?.json, self);

        if (evalResult.status === "owned") {
            driveLockState = { envelopeName, fileId: lockFile?.fileId, lock: lockFile?.json, self, mode: "write" };
        } else if (evalResult.status === "locked") {
            log("🔒 Envelope locked by another device — entering read-only mode");
            driveLockState = { envelopeName, fileId: lockFile.fileId, lock: lockFile.json, self, mode: "read" };
        } else {
            await acquireDriveWriteLock(envelopeName);
        }
    }

    log("🔐 [ensureEnvelope] Drive mode:" + driveLockState.mode);
    log("🖥 [ensureEnvelope] Drive self deviceId:" + driveLockState.self.deviceId);

    // ─── Load key registry from pub-keys on Drive ───
    const rawPublicKeyJsons = await loadPublicKeyJsonsFromDrive();
    keyRegistry = await buildKeyRegistryFromDrive(rawPublicKeyJsons);

    log("[ensureEnvelope] Active devices registry:" + keyRegistry.flat.activeDevices.length);
    log("[ensureEnvelope] recoveryKeys registry:" + keyRegistry.flat.recoveryKeys.length);

    // ─── Fast path: load existing envelope ───
    const existing = await readEnvelopeFromDrive(envelopeName);
    if (existing?.json) {
        log("📦 Envelope already exists");
        return existing.json;
    }

    // ─── Genesis envelope path ───
    log("📦 Envelope missing — creating genesis envelope");
    const { identity } = await getDriveLockSelf();
    const selfKey = keyRegistry.flat.activeDevices.find(k => k.deviceId === identity.deviceId);
    if (!selfKey) throw new Error("Active device public key not found for envelope genesis");

    const envelope = await createEnvelope(JSON.stringify({ initialized: true }), selfKey);
    return await writeEnvelopeWithLock(envelopeName, envelope);
}

async function getDriveLockSelf() {
    const identity = await loadIdentity();
    if (!identity) throw new Error("Identity not unlocked — cannot ensure envelope");
    const self = { account: userEmail, deviceId: identity.deviceId };
    return { identity, self };
}

function evaluateEnvelopeLock(lock, self) {
    if (!lock) return { status: "free" };

    const now = Date.now();
    const expired = Date.parse(lock.expiresAt) <= now;

    if (expired) return { status: "free", reason: "expired" };

    if (lock.owner.account === self.account && lock.owner.deviceId === self.deviceId) {
        return { status: "owned", lock };
    }

    return { status: "locked", lock };
}

async function acquireDriveWriteLock(envelopeName) {
    log("🔐 acquireDriveWriteLock: start");

    const identity = await loadIdentity();
    const self = { account: userEmail, deviceId: identity.deviceId };

    const lockFile = await readLockFromDrive(envelopeName).catch(() => null);
    const evalResult = evaluateEnvelopeLock(lockFile?.json, self);

    if (evalResult.status === "locked") {
        throw new Error("Failed to acquire lock: locked-by-other");
    }

    const envelope = await readEnvelopeFromDrive(envelopeName).catch(() => null);
    const generation = envelope?.generation ?? 0;

    const lock = createLockPayload(self, envelopeName, generation);

    log("🔐 writing lock to Drive...");
    const fileId = await writeLockToDrive(envelopeName, lock, lockFile?.fileId);

    log("🔐 lock written, fileId: " + fileId);

    // ✅ Initialize driveLockState safely
    driveLockState = {
        envelopeName,
        fileId: fileId || null,
        lock,
        self,
        mode: "write",
        heartbeat: startLockHeartbeat({
            envelopeName,
            self,
            readLockFromDrive,
            writeLockToDrive,
            onLost: info => handleDriveLockLost(info)
        })
    };

    updateLockStatusUI();

    log("✅ acquireDriveWriteLock completed");
    return driveLockState;
}

async function loadPublicKeyJsonsFromDrive() {
    const publicKeyJsons = [];

    // 1️⃣ Locate pub-keys folder
    const pubKeysFolders = await driveList({
        q: `'${ACCESS4_ROOT_ID}' in parents and name='pub-keys' and mimeType='application/vnd.google-apps.folder'`,
        pageSize: 1
    });

    if (pubKeysFolders.length === 0) {
        log("[loadPublicKeyJsonsFromDrive] pub-keys folder not found");
        return publicKeyJsons;
    }

    const pubKeysRootId = pubKeysFolders[0].id;

    // 2️⃣ Enumerate email subfolders
    const accountFolders = await driveList({
        q: `'${pubKeysRootId}' in parents and mimeType='application/vnd.google-apps.folder'`,
        pageSize: 100
    });

    for (const accountFolder of accountFolders) {
        // 3️⃣ Enumerate device key files
        const deviceKeyFiles = await driveList({
            q: `'${accountFolder.id}' in parents and mimeType='application/json'`,
            pageSize: 100
        });

        for (const file of deviceKeyFiles) {
            try {
                const json = await driveReadJsonFile(file.id);
                publicKeyJsons.push(json);
            } catch (err) {
                log(`[loadPublicKeyJsonsFromDrive] Failed to read ${file.name}: ${err.message}`);
            }
        }
    }

    // 4️⃣ Load recovery public key (optional)
    const recoveryFolders = await driveList({
        q: `'${ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`,
        pageSize: 1
    });

    if (recoveryFolders.length > 0) {
        const recoveryFolderId = recoveryFolders[0].id;

        const recoveryPublicFiles = await driveList({
            q: `'${recoveryFolderId}' in parents and name='recovery.public.json'`,
            pageSize: 1
        });

        if (recoveryPublicFiles.length > 0) {
            try {
                const recoveryJson = await driveReadJsonFile(recoveryPublicFiles[0].id);
                publicKeyJsons.push(recoveryJson);
            } catch (err) {
                log("[loadPublicKeyJsonsFromDrive] Failed to read recovery.public.json");
            }
        }
    }

    log(`[loadPublicKeyJsonsFromDrive] Loaded ${publicKeyJsons.length} public keys`);
    return publicKeyJsons;
}

async function buildKeyRegistryFromDrive(rawPublicKeyJsons) {
    resetKeyRegistry();

    for (const raw of rawPublicKeyJsons) {
        const normalized = normalizePublicKey(raw);
        if (!normalized) continue; // skip invalid
        registerPublicKey(normalized);
    }

    keyRegistry.loadedAt = new Date().toISOString();

    // Validate structural integrity
    try {
        validateKeyRegistry(keyRegistry);
    } catch (e) {
        log("⚠️ Key registry validation warning:" + e.message);
    }

    // Resolve terminal active devices
    const activeDevices = resolveEffectiveActiveDevices(keyRegistry.flat);

    // 🔒 Freeze resolved device lists
    keyRegistry.flat.activeDevices = Object.freeze(
        activeDevices.map(d => Object.freeze(d))
    );

    keyRegistry.flat.deprecatedDevices = Object.freeze(
        keyRegistry.flat.deprecatedDevices.map(d => Object.freeze(d))
    );

    // 🔒 Freeze flat view
    Object.freeze(keyRegistry.flat);

    // 🔒 Freeze entire registry
    Object.freeze(keyRegistry);

    return keyRegistry;
}

function resetKeyRegistry() {
    keyRegistry.accounts = {};
    keyRegistry.flat.activeDevices = [];
    keyRegistry.flat.deprecatedDevices = [];
    keyRegistry.flat.recoveryKeys = [];
    keyRegistry.loadedAt = new Date().toISOString();
}

function normalizePublicKey(raw) {
    if (!raw || typeof raw !== "object") {
        throw new Error("Invalid public key JSON");
    }

    //log("[normalizePublicKey] raw: " + JSON.stringify(raw));

    if (!raw.keyId || !raw.fingerprint || !raw.publicKey) {
        throw new Error("Missing required public key fields");
    }

    return {
        version: Number(raw.version) || 1,

        account: raw.account || null,
        role: raw.role,

        keyId: raw.keyId,
        fingerprint: raw.fingerprint,
        state: raw.state || "active",

        deviceId: raw.role === "device" ? raw.deviceId : null,
        supersedes: raw.supersedes || null,
        created: raw.created || null,

        algorithm: {
            type: raw.algorithm?.type,
            usage: raw.algorithm?.usage || [],
            modulusLength: raw.algorithm?.modulusLength,
            hash: raw.algorithm?.hash
        },

        publicKey: {
            format: raw.publicKey.format,
            encoding: raw.publicKey.encoding,
            data: raw.publicKey.data
        },

        meta: {
            deviceName: raw.deviceName || null,
            browser: raw.browser || null,
            os: raw.os || null
        }
    };
}

function registerPublicKey(key) {
    if (!key || !key.fingerprint) {
        throw new Error("Cannot register invalid key");
    }

    // --- account bucket ---
    if (!keyRegistry.accounts[key.account]) {
        keyRegistry.accounts[key.account] = {
            devices: {},
            recovery: {}
        };
    }

    const accountBucket = keyRegistry.accounts[key.account];

    // --- role routing ---
    if (key.role === "device") {
        accountBucket.devices[key.fingerprint] = key;

        if (key.state === "active") {
            keyRegistry.flat.activeDevices.push(key);
        } else if (key.state === "deprecated") {
            keyRegistry.flat.deprecatedDevices.push(key);
        }
    }

    if (key.role === "recovery") {
        accountBucket.recovery[key.fingerprint] = key;
        keyRegistry.flat.recoveryKeys.push(key);
    }
}

function validateKeyRegistry(registry) {
    if (!registry.loadedAt) {
        throw new Error("Registry missing loadedAt timestamp");
    }

    const seen = new Set();

    for (const key of [
        ...registry.flat.activeDevices,
        ...registry.flat.deprecatedDevices,
        ...registry.flat.recoveryKeys
    ]) {
        if (!key.fingerprint) {
            throw new Error("Registry contains key without fingerprint");
        }

        if (seen.has(key.fingerprint)) {
            throw new Error("Duplicate fingerprint in registry: " + key.fingerprint);
        }

        seen.add(key.fingerprint);
    }
}

function resolveEffectiveActiveDevices(flat) {
    const superseded = buildSupersedenceIndex([
        ...flat.activeDevices,
        ...flat.deprecatedDevices
    ]);

    return flat.activeDevices.filter(key => {
        // Must be active
        if (key.state !== "active") return false;

        // Must NOT be superseded by another key
        if (superseded.has(key.fingerprint)) return false;

        return true;
    });
}

async function readEnvelopeFromDrive(envelopeName) {
    const file = await findDriveFileByName(envelopeName);
    if (!file) return null;

    const json = await driveReadJsonFile(file.id);

    return {
        fileId: file.id,
        json
    };
}

function createLockPayload(self, envelopeName, generation) {
    const now = Date.now();
    return {
        version: 1,
        envelope: envelopeName,
        owner: {
            account: self.account,
            deviceId: self.deviceId
        },
        mode: "write",
        generation,
        acquiredAt: new Date(now).toISOString(),
        expiresAt: new Date(now + LOCK_TTL_MS).toISOString()
    };
}

async function writeLockToDrive(envelopeName, lockJson, existingFileId = null) {
    const lockName = `${envelopeName}.lock`;

    if (existingFileId) {
        // ✅ Content-only update
        await drivePatchJsonFile(existingFileId, lockJson);
        return existingFileId;
    }

    // ✅ New file creation
    return await driveCreateJsonFile({
        name: lockName,
        parents: [ACCESS4_ROOT_ID],
        json: lockJson
    });
}

async function createEnvelope(plainText, devicePublicKeyRecord) {

    if (!isKeyUsableForEncryption(devicePublicKeyRecord)) {
        throw new Error("Cannot encrypt for non-active key");
    }

    const cek = await generateContentKey();
    const payload = await encryptPayload(plainText, cek);

    const wrappedKey = await wrapContentKeyForDevice(cek, devicePublicKeyRecord.publicKey.data);

    return {
        version: "1.0",
        cipher: {
            payload: "AES-256-GCM",
            keyWrap: "RSA-OAEP-SHA256"
        },
        payload,
        keys: [{
            role: "device",
            account: devicePublicKeyRecord.account,
            deviceId: devicePublicKeyRecord.deviceId,
            keyId: devicePublicKeyRecord.fingerprint,
            keyVersion: devicePublicKeyRecord.version,
            wrappedKey
        }],
        created: new Date().toISOString()
    };
}

async function generateContentKey() {
    return crypto.subtle.generateKey({
        name: "AES-GCM",
        length: 256
    },
        true,
        ["encrypt", "decrypt"]
    );
}

/* --- Encrypt Payload with CEK --- */
async function encryptPayload(plainText, cek) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);

    const ciphertext = await crypto.subtle.encrypt({
        name: "AES-GCM",
        iv
    },
        cek,
        encoded
    );

    return {
        iv: btoa(String.fromCharCode(...iv)),
        data: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
    };
}

async function writeEnvelopeWithLock(envelopeName, envelopeData) {

    log("➡️ Entered writeEnvelopeWithLock()");

    await assertEnvelopeWrite(envelopeName);

    try {
        // 1️⃣ Find envelope file (metadata only)
        const envelopeFile = await findDriveFileByName(envelopeName);

        let currentEnvelope = null;

        if (envelopeFile) {
            try {
                currentEnvelope = await driveReadJsonFile(envelopeFile.id);
            } catch {
                log("⚠️ Failed to parse existing envelope — will overwrite");
            }
        }

        // 2️⃣ Increment generation
        const currentGen = currentEnvelope?.generation ?? 0;
        const newGeneration = currentGen + 1;

        // 3️⃣ Build new envelope
        const newEnvelopeContent = {
            ...envelopeData,
            generation: newGeneration,
            lastModifiedBy: driveLockState.self.deviceId,
            lastModifiedAt: new Date().toISOString()
        };

        // 4️⃣ Write envelope (content-only)
        if (envelopeFile?.id) {
            await drivePatchJsonFile(envelopeFile.id, newEnvelopeContent);
        } else {
            await driveCreateJsonFile({
                name: envelopeName,
                parents: [ACCESS4_ROOT_ID],
                json: newEnvelopeContent
            });
        }

        // 5️⃣ IMPORTANT: update lock generation to match
        driveLockState.lock.generation = newGeneration;

        await writeLockToDrive(
            envelopeName,
            driveLockState.lock,
            driveLockState.fileId
        );

        // Update UI to reflect new lock generation
        updateLockStatusUI();

        log(`✅ Envelope "${envelopeName}" written, generation=${newGeneration}`);
        return newEnvelopeContent;

    } catch (err) {
        log(`❌ Failed to write envelope "${envelopeName}": ${err.message}`);
        throw err;
    }
}

async function ensureRecoveryKey() {
    if (await hasRecoveryKeyOnDrive()) {
        log("🛟 Recovery key already present");
        return;
    }

    log("🛟 No recovery key found — blocking for recovery setup");
    await promptRecoverySetupUI();   // ← UI + user input
}

async function hasRecoveryKeyOnDrive() {
    try {
        const folders = await driveList({
            q: `'${ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`,
            pageSize: 1
        });

        log("[hasRecoveryKeyOnDrive] recovery folders found: " + folders.length);

        if (!folders.length) return false;

        const recoveryFolderId = folders[0].id;

        const files = await driveList({
            q: `'${recoveryFolderId}' in parents and name='recovery.public.json'`,
            pageSize: 1
        });

        return files.length === 1;

    } catch (e) {
        log("❌ Recovery key check failed: " + e.message);
        throw e; // mandatory block
    }
}

function promptRecoverySetupUI() {
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

async function wrapCEKForRegistryKeys(forceWrite = false) {

    log("[wrapCEKForRegistryKeys] start");
    log("🧠 [wrapCEKForRegistryKeys] unlockedIdentity:" + !!unlockedIdentity);
    log("🧠 [wrapCEKForRegistryKeys] currentPrivateKey:" + !!currentPrivateKey);

    const envelopeName = "envelope.json";

    const envelopeFile = await readEnvelopeFromDrive(envelopeName);
    if (!envelopeFile || !envelopeFile.json) {
        throw new Error("Envelope missing — cannot wrap CEK for registry");
    }

    const envelope = envelopeFile.json;

    log("📦 [wrapCEKForRegistryKeys] envelope keys count:" + envelope?.keys?.length ?? 0);

    if (!envelope.keys || !envelope.payload) {
        throw new Error("Invalid envelope structure for CEK housekeeping");
    }

    const activeDevices = keyRegistry.flat.activeDevices;
    const recoveryKeys = keyRegistry.flat.recoveryKeys;

    log("🔍 [wrapCEKForRegistryKeys] Selecting device key entry...");
    log("📧 [wrapCEKForRegistryKeys] userEmail:" + userEmail);
    log("🖥 [wrapCEKForRegistryKeys] self.deviceId:" + driveLockState?.self?.deviceId);

    // Unwrap CEK using any current device key
    const currentDeviceKeyEntry = envelope.keys.find(k =>
    k.account === userEmail &&
    k.deviceId === driveLockState.self.deviceId) || envelope.keys[0]; // Added temporary comment to debug refresh errors

    if (!currentDeviceKeyEntry) {
        throw new Error("No device key available to unwrap CEK");
    }

    log("✅ [wrapCEKForRegistryKeys] Selected keyId for unwrap:" + currentDeviceKeyEntry.keyId);
    log("📦 [wrapCEKForRegistryKeys] Selected deviceId:" + currentDeviceKeyEntry.deviceId);


    log("🔓 [wrapCEKForRegistryKeys] Attempting CEK unwrap");
    log("🔐 [wrapCEKForRegistryKeys] unwrap keyId:" + currentDeviceKeyEntry.keyId);
    log("🧠 [wrapCEKForRegistryKeys] unlockedIdentity fingerprint:" + unlockedIdentity?.fingerprint);
    log("🧠 [wrapCEKForRegistryKeys] currentPrivateKey exists:" + !!currentPrivateKey);

    const cek = await unwrapContentKey(currentDeviceKeyEntry.wrappedKey, currentDeviceKeyEntry.keyId);
    let updated = false;

    // Wrap CEK for each active device not already present
    for (const device of activeDevices) {
        const existing = envelope.keys.find(k => k.keyId === device.fingerprint);
        if (!existing) {
            const wrappedKey = await wrapContentKeyForDevice(cek, device.publicKey.data);
            envelope.keys.push({
                role: "device",
                account: device.account,
                deviceId: device.deviceId,
                keyId: device.fingerprint,
                wrappedKey
            });
            log(`🔁 CEK wrapped for device ${device.deviceId}`);
            updated = true;
        } else if (forceWrite) {
            // Re-wrap CEK even if key exists
            existing.wrappedKey = await wrapContentKeyForDevice(cek, device.publicKey.data);
            log(`♻ CEK re-wrapped for device ${device.deviceId} (forceWrite)`);
            updated = true;
        }
    }

    // Wrap CEK for recovery keys not already present
    for (const recovery of recoveryKeys) {
        const existing = envelope.keys.find(k => k.keyId === recovery.fingerprint);
        if (!existing) {
            const wrappedKey = await wrapContentKeyForDevice(cek, recovery.publicKey.data);
            envelope.keys.push({
                role: "recovery",
                keyId: recovery.fingerprint,
                wrappedKey
            });
            log(`🔁 CEK wrapped for recovery key ${recovery.fingerprint}`);
            updated = true;
        } else if (forceWrite) {
            existing.wrappedKey = await wrapContentKeyForDevice(cek, recovery.publicKey.data);
            log(`♻ CEK re-wrapped for recovery key ${recovery.fingerprint} (forceWrite)`);
            updated = true;
        }
    }

    // Write back if updated OR forceWrite
    if (updated || forceWrite) {
        log("💾 Envelope updated with wrapped keys — writing to Drive");
        await writeEnvelopeSafely(envelopeName, envelope);
    } else {
        log("✅ Envelope up to date — skipping write");
    }

    return envelope;
}

/* ---Unwrap CEK Using Local Private Key (rotation-safe) --- */
async function unwrapContentKey(wrappedKeyBase64, keyId) {
    const id = await loadIdentity();
    if (!id) throw new Error("Local identity missing");

    // Helper to unwrap with a given CryptoKey
    async function unwrapWithKey(privateKey) {
        const wrappedBytes = Uint8Array.from(atob(wrappedKeyBase64), c => c.charCodeAt(0));
        return crypto.subtle.unwrapKey(
            "raw",
            wrappedBytes,
            privateKey,
            { name: "RSA-OAEP" },
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // 1️⃣ Try current in-memory private key if keyId matches
    if (currentPrivateKey && keyId === id.fingerprint) {
        console.log(`[unwrapContentKey] Using currentPrivateKey for keyId ${keyId}`);
        return unwrapWithKey(currentPrivateKey);
    }

    // 2️⃣ Try previous keys
    if (id.previousKeys?.length) {
        const prev = id.previousKeys.find(k => k.fingerprint === keyId);
        if (prev) {
            if (!unlockedPassword) throw new Error("Identity not unlocked for previous key");
            console.log(`[unwrapContentKey] Using previous key for keyId ${keyId}`);
            const derivedKey = await deriveKey(unlockedPassword, prev.kdf);
            const privateKeyPkcs8 = await decrypt(prev.encryptedPrivateKey, derivedKey);
            const privateKey = await crypto.subtle.importKey(
                "pkcs8",
                privateKeyPkcs8,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["unwrapKey"]
            );
            return unwrapWithKey(privateKey);
        }
    }

    // 3️⃣ Fallback: use currentPrivateKey even if fingerprint mismatch
    if (currentPrivateKey) {
        console.log(`[unwrapContentKey] Fallback: using currentPrivateKey despite fingerprint mismatch for keyId ${keyId}`);
        return unwrapWithKey(currentPrivateKey);
    }

    // 4️⃣ Nothing found
    console.error(`[unwrapContentKey] No private key available for keyId ${keyId}`);
    throw new Error("No private key available for keyId: " + keyId);
}

async function deriveKey(pwd, kdf) {
    const mat = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(pwd),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey({
        name: "PBKDF2",
        salt: Uint8Array.from(atob(kdf.salt), c => c.charCodeAt(0)),
        iterations: kdf.iterations,
        hash: "SHA-256"
    },
        mat, {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function decrypt(enc, key) {
    return crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: Uint8Array.from(atob(enc.iv), c => c.charCodeAt(0))
    },
        key,
        Uint8Array.from(atob(enc.data), c => c.charCodeAt(0))
    );
}

/* --- Wrap CEK for a Device Public Key --- */
async function wrapContentKeyForDevice(cek, devicePublicKeyBase64) {
    const pubKeyBytes = Uint8Array.from(atob(devicePublicKeyBase64), c => c.charCodeAt(0));

    const publicKey = await crypto.subtle.importKey(
        "spki",
        pubKeyBytes, {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        false,
        ["wrapKey"]
    );

    const wrapped = await crypto.subtle.wrapKey(
        "raw",
        cek,
        publicKey, {
            name: "RSA-OAEP"
        }
    );

    return btoa(String.fromCharCode(...new Uint8Array(wrapped)));
}

async function writeEnvelopeSafely(envelopeName, envelopeData, maxRetries = 3, retryDelayMs = 1000) {
    let attempt = 0;

    while (attempt < maxRetries) {
        attempt++;

        // Ensure we hold the lock
        if (!driveLockState || driveLockState.envelopeName !== envelopeName) {
            log(`🔒 Attempting to acquire lock for "${envelopeName}" (attempt ${attempt})`);
            try {
                await acquireDriveWriteLock(envelopeName);
            } catch (err) {
                log(`⚠️ Lock acquisition failed: ${err.message}`);
                await new Promise(r => setTimeout(r, retryDelayMs));
                continue;
            }
        }

        await assertEnvelopeWrite(envelopeName);

        try {
            const result = await writeEnvelopeWithLock(envelopeName, envelopeData);
            return result;
        } catch (err) {
            log(`⚠️ Write attempt failed: ${err.message}`);
            // If lock was lost mid-write, retry
            await new Promise(r => setTimeout(r, retryDelayMs));
        }
    }

    throw new Error(`Failed to write envelope "${envelopeName}" after ${maxRetries} attempts`);
}

async function loadEnvelopePayloadToUI(envelopeName = "envelope.json") {
    log(`📥 Loading envelope payload from Drive: ${envelopeName}`);

    // 1️⃣ Read envelope file
    const envelopeFile = await readEnvelopeFromDrive(envelopeName);
    if (!envelopeFile) {
        log("⚠️ Envelope file not found");
        return;
    }

    const envelope = envelopeFile.json;

    if (!envelope.payload) {
        log("⚠️ Envelope has no payload");
        return;
    }

    try {
        // 2️⃣ Decrypt payload using openEnvelope()
        const plaintext = await openEnvelope(envelope);

        log(`plaintext: |${plaintext}|`);

        // 3️⃣ Populate plaintext area in UI
        plaintextInput.value = plaintext;

        log("✅ Payload loaded into plaintext UI");
    } catch (err) {
        log("❌ Failed to decrypt envelope payload: " + err.message);
    }
}

async function openEnvelope(envelope) {

    log("[openEnvelope]");

    validateEnvelope(envelope);

    const entry = await selectDecryptableKey(envelope);

    log(`entry.keyId: ${entry.keyId}`);

    const cek = await unwrapContentKey(
        entry.wrappedKey,
        entry.keyId
    );

    const iv = Uint8Array.from(atob(envelope.payload.iv), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob(envelope.payload.data), c => c.charCodeAt(0));

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cek,
        data
    );

    return new TextDecoder().decode(decrypted);
}

function validateEnvelope(envelope) {
    if (!envelope.version) {
        throw new Error("Envelope missing version");
    }

    if (!Array.isArray(envelope.keys) || envelope.keys.length === 0) {
        throw new Error("Envelope has no key entries");
    }

    let hasUsableKey = false;

    for (const k of envelope.keys) {
        // wrapped CEK is always required
        if (!k.wrappedKey) {
            throw new Error("Key entry missing wrappedKey");
        }

        // keyId is REQUIRED for rotation safety (all key types)
        if (!k.keyId) {
            throw new Error("Key entry missing keyId (rotation unsafe)");
        }

        // Type-aware validation
        if (k.role === "device") {
            if (!k.deviceId) {
                throw new Error("Device key entry missing deviceId");
            }
            hasUsableKey = true;
        } else if (k.role === "recovery") {
            // recovery entries intentionally do NOT have deviceId
            // optional: validate recoveryId / method if you want
            hasUsableKey = true;
        } else {
            throw new Error(`Unknown key entry role: ${k.role || "missing"}`);
        }
    }

    if (!hasUsableKey) {
        throw new Error("Envelope contains no usable key entries");
    }
}

async function selectDecryptableKey(envelope) {

    const id = await loadIdentity();
    if (!id) throw new Error("Local identity missing");

    if (!Array.isArray(envelope.keys)) {
        throw new Error("Envelope missing keys array");
    }

    // 1️⃣ Prefer current device key (rotation-aware)
    const deviceEntry = envelope.keys.find(k => {
        if (k.role !== "device") return false;
        if (!k.deviceId) return false;
        if (k.deviceId !== id.deviceId) return false;

        // Allow current or superseded key
        return keyMatchesOrIsSuperseded(k.keyId, id);
    });

    if (deviceEntry) {
        if (deviceEntry.keyId !== id.fingerprint) {
            log("🔁 Envelope encrypted with previous device key — rotation detected");
        }
        return deviceEntry;
    }

    // 2️⃣ Optional fallback: recovery key (NO deviceId expected)
    const recoveryEntry = envelope.keys.find(k => k.role === "recovery");

    if (recoveryEntry) {
        log("🛟 Falling back to recovery key for decryption");
        return recoveryEntry;
    }

    throw new Error("No decryptable key found for this device or recovery");
}

function keyMatchesOrIsSuperseded(entryKeyId, localIdentity) {
    if (!localIdentity?.fingerprint) return false;
    // Exact match (current key)
    if (entryKeyId === localIdentity.fingerprint) return true;
    // Superseded key (previous rotation)
    if (localIdentity.previousKeys?.some(k => k.fingerprint === entryKeyId)) return true;
    return false;
}

/* --------- Unlock flow --------- */
async function handleUnlockClick() {

    if (unlockInProgress) return;

    unlockInProgress  = true;
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
        const def = Object.values(UNLOCK_ERROR_DEFS)
            .find(d => d.code === e.code);

        showUnlockMessage(def?.message || e.message || "Unlock failed");
        log("❌ Unlock failed: " + (def?.message || e.message));
    }
}

async function unlockIdentityFlow(pwd) {
    if (!pwd || pwd.length < 7) {
        const e = new Error(UNLOCK_ERROR_DEFS.WEAK_PASSWORD.message);
        e.code = UNLOCK_ERROR_DEFS.WEAK_PASSWORD.code;
        throw e;
    }

    log("🔓 [unlockIdentityFlow] Unlock attempt started for password:" + pwd ? "***" : "(empty)");

    if (!accessToken) {
        const e = new Error(UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.message);
        e.code = UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.code;
        throw e;
    }

    let id = await loadIdentity();
    log("📁 [unlockIdentityFlow] Identity loaded:" + !!id);

    if (id && identityNeedsPasswordSetup(id)) {
        log("🧭 Identity missing password verifier — attempting auto-migration");

        try {
            await migrateIdentityWithVerifier(id, pwd);
            id = await loadIdentity();
        } catch {
            const e = new Error(UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
            e.code = UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
            throw e;
        }
    }

    if (!id) {
        log("❌ No local identity found — cannot unlock");
        const e = new Error(UNLOCK_ERROR_DEFS.NO_IDENTITY.message);
        e.code = UNLOCK_ERROR_DEFS.NO_IDENTITY.code;
        throw e;
    }

    log("📁 Local identity found");

    // ─────────────────────────────
    // 🔐 AUTHORITATIVE PASSWORD CHECK
    // ─────────────────────────────
    let key;
    try {
        key = await deriveKey(pwd, id.kdf);
        await verifyPasswordVerifier(id.passwordVerifier, key);
        log("🔐 Password verified");
    } catch {
        const e = new Error(UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.message);
        e.code = UNLOCK_ERROR_DEFS.INCORRECT_PASSWORD.code;
        throw e;
    }

    log("🔐 [unlockIdentityFlow] Password verified:", key ? "***" : "(failed)");

    // ─────────────────────────────
    // 🔓 Attempt private key decrypt
    // ─────────────────────────────
    let decrypted = false;
    let decryptedPrivateKeyBytes = null;

    try {
        decryptedPrivateKeyBytes = await decrypt(id.encryptedPrivateKey, key);
        decrypted = true;
        log("✅ Identity successfully decrypted");
    } catch {
        log("⚠️ Private key decryption failed");
    }

    log("✅ [unlockIdentityFlow] Identity decrypted:", decrypted);

    // ─────────────────────────────
    // 🔁 Single rotation retry
    // ─────────────────────────────
    if (!decrypted) {
        log("🔁 Attempting device key rotation");

        await rotateDeviceIdentity(pwd);
        id = await loadIdentity();

        try {
            await decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("✅ Decryption succeeded after rotation");
        } catch {
            log("⚠️ Decryption still failing after rotation");
        }
    }

    // ─────────────────────────────
    // 🧨 Absolute Safari recovery
    // ─────────────────────────────
    if (!decrypted) {
        log("🧨 Rotation failed — recreating identity");

        await createIdentity(pwd);
        id = await loadIdentity();

        if (!id) {
            const e = new Error(UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }

        try {
            key = await deriveKey(pwd, id.kdf);
            await decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("✅ Decryption succeeded after recreation");
        } catch {
            const e = new Error(UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
            e.code = UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
            throw e;
        }
    }

    if (id.supersedes) {
        log("ℹ️ Identity supersedes previous keyId: " + id.supersedes);
    }

    // ─────────────────────────────
    // Session unlocked
    // ─────────────────────────────
    unlockedPassword = pwd;

    await cacheDecryptedPrivateKey(decryptedPrivateKeyBytes);

    // ✅ Attach decrypted key to identity and set global unlockedIdentity
    id._sessionPrivateKey = currentPrivateKey;
    unlockedIdentity = id;
    sessionUnlocked = true;


    log("🧠 unlockedIdentity set in memory for session");

    if (biometricIntent && !biometricRegistered) {
        await enrollBiometric(pwd);
        biometricRegistered = true;
    }

    log("🔑 Proceeding to device public key exchange");
    await ensureDevicePublicKey();

    return id;
}

async function cacheDecryptedPrivateKey(decryptedPrivateKeyBytes) {
    try {
        if (!decryptedPrivateKeyBytes) throw new Error("No decrypted key available");

        const base64 = arrayBufferToBase64(decryptedPrivateKeyBytes);
        sessionStorage.setItem("sv_session_private_key", base64);

        // Keep in-memory reference for session restore
        currentPrivateKey = await crypto.subtle.importKey(
            "pkcs8",
            decryptedPrivateKeyBytes,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt", "unwrapKey"]
        );

        sessionUnlocked = true;
        log("🧠 Session private key cached");

    } catch (e) {
        log("⚠️ Session caching failed (non-fatal): " + e.message);
    }
}

/* ---------------------- Session storage helpers ---------------------- */
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000; // 32k chunks
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function handleCreatePasswordClick()  {
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
        await createIdentity(pwd);
        await proceedAfterPasswordSuccess();
        log("✅ New identity created and unlocked");
    } catch (e) {
        showUnlockMessage(e.message);
    }
}

/* --------------- CREATE IDENTITY start ----------------- */
async function createIdentity(pwd) {
    log("🔐 Generating new device identity key pair");

    const keypair = await generateDeviceKeypair();
    const identity = await buildIdentityFromKeypair(keypair, pwd);

    saveIdentity(identity);

    log("✅ New identity created and stored locally");

    if (biometricIntent && !biometricRegistered) {
        log("👆 Biometric enrollment intent detected, enrolling now...");
        await enrollBiometric(pwd);
        biometricRegistered = true;
    }
}

async function rotateDeviceIdentity(pwd) {
    log("🔁 Rotating device identity key");

    const oldIdentity = await loadIdentity();
    if (!oldIdentity) {
        throw new Error("Cannot rotate — no existing identity");
    }

    const keypair = await generateDeviceKeypair();

    const newIdentity = await buildIdentityFromKeypair(
        keypair,
        pwd, {
            supersedes: oldIdentity.fingerprint,
            previousKeys: [
                ...(oldIdentity.previousKeys || []),
                {
                    fingerprint: oldIdentity.fingerprint,
                    created: oldIdentity.created,
                    encryptedPrivateKey: oldIdentity.encryptedPrivateKey, // <-- Store encrypted private key
                    kdf: oldIdentity.kdf // <-- Include kdf so unwrapContentKey can derive correctly
                }
            ]
        }
    );

    saveIdentity(newIdentity);

    log("✅ Device identity rotated");
    log("↪ Supersedes keyId: " + oldIdentity.fingerprint);

    // --- Drive updates (best effort) ---
    try {
        await markPreviousDriveKeyDeprecated(oldIdentity.fingerprint); // updates old key JSON
        await ensureDevicePublicKey();        // uploads NEW active key
        log("☁️ Drive key lifecycle updated");
    } catch (e) {
        log("⚠️ Drive update failed (local rotation preserved): " + e.message);
    }
}

async function markPreviousDriveKeyDeprecated(oldFingerprint) {
    const folder = await findOrCreateUserFolder();
    const filenamePattern = `${userEmail}__`; // all device keys for this user
    const q = `'${folder}' in parents and name contains '${filenamePattern}'`;
    const res = await driveFetch(buildDriveUrl("files", { q, fields: "files(id,name)" }));

    if (!res.files.length) return; // nothing to patch

    for (const file of res.files) {
        const fileData = await driveFetch(buildDriveUrl(`files/${file.id}`, { alt: "media" }));
        if (fileData.keyId !== oldFingerprint) continue; // not the old key

        // --- PATCH only mutable fields ---
        const patchData = {
            state: "deprecated",
            supersededBy: (await loadIdentity()).fingerprint
        };

        await driveFetch(buildDriveUrl(`files/${file.id}`, { uploadType: "media" }), {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(patchData)
        });

        log(`☑️ Previous device key (${oldFingerprint}) marked deprecated on Drive`);
    }
}

async function computeFingerprintFromPublicKey(base64Spki) {
    const pubBytes = Uint8Array.from(atob(base64Spki), c => c.charCodeAt(0));
    const hash = await crypto.subtle.digest("SHA-256", pubBytes);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

function identityNeedsPasswordSetup(id) {
    return id && !id.passwordVerifier;
}

/* --------------- CREATE IDENTITY end ----------------- */

/* ================= USER ================= */
async function fetchUserEmail() {
    const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });
    const data = await res.json();
    userEmail = data.email;
    userEmailSpan.textContent = userEmail;
    log("Signed in as xxx@gmail.com"); //+ userEmail);
}

/* ================= DRIVE HELPERS ================= */
function buildDriveUrl(path, params = {}) {
    params.supportsAllDrives = true;
    // Commented as only needed for LIST calls not GET
    //params.includeItemsFromAllDrives = true;
    return `https://www.googleapis.com/drive/v3/${path}?` +
    Object.entries(params).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
}

function buildDriveListUrl(params = {}) {
    return buildDriveUrl("files", {
        ...params,
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
    });
}

async function driveList(params) {
    const res = await driveFetch(buildDriveListUrl(params));
    return res.files || [];
}

function buildDriveUploadUrl(path, params = {}) {
    const qs = new URLSearchParams({
        supportsAllDrives: "true",
        includeItemsFromAllDrives: "true",
        ...params
    });
    return `https://www.googleapis.com/upload/drive/v3/${path}?${qs}`;
}

async function driveFetch(url, options = {}) {
    options.headers ||= {};
    options.headers.Authorization = `Bearer ${accessToken}`;
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`Drive fetch failed: ${res.status} ${res.statusText}`);
    return res.json();
}

async function driveMultipartUpload({ metadata, content, contentType = "application/json" }) {
    const boundary = "-------access4-" + crypto.randomUUID();

    const body =
    `--${boundary}\r\n` +
    `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
    JSON.stringify(metadata) + "\r\n" +
    `--${boundary}\r\n` +
    `Content-Type: ${contentType}\r\n\r\n` +
    content + "\r\n" +
    `--${boundary}--`;

    const res = await fetch(
        "https://www.googleapis.com/upload/drive/v3/files" +
        "?uploadType=multipart&supportsAllDrives=true", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": `multipart/related; boundary=${boundary}`
            },
            body
        }
    );

    if (!res.ok) {
        const text = await res.text();
        throw new Error(`Multipart upload failed ${res.status}: ${text}`);
    }

    const json = await res.json();
    return json;
}

// IMPORTANT:
// Drive has separate endpoints for metadata vs file content.
// NEVER send JSON content to drive/v3/files.
// Use upload/drive/v3/files for media writes.

async function driveApiGet(path, params = {}) {
    return driveFetch(
        buildDriveUrl(path, params),
        { method: "GET" }
    );
}

async function driveFindFileByNameInFolder(name, folderId) {
    const q = [
        `name='${name.replace(/'/g, "\\'")}'`,
        `'${folderId}' in parents`,
        `trashed=false`
    ].join(" and ");

    const res = await driveApiGet("files", { q, fields: "files(id,name,modifiedTime)" });

    return res.files?.[0] || null;
}

async function driveFetchRaw(url, options = {}) {
    options.headers ||= {};
    options.headers.Authorization = `Bearer ${accessToken}`;

    const res = await fetch(url, options);
    if (!res.ok) {
        const text = await res.text();
        throw new Error(text);
    }
    return res;
}

async function driveReadJsonFile(fileId) {
    const res = await driveFetchRaw(
        buildDriveUrl(`files/${fileId}`, { alt: "media" })
    );
    return await res.json();
}

async function drivePatchJsonFile(fileId, json) {
    await driveFetchRaw(
        buildDriveUploadUrl(`files/${fileId}`, { uploadType: "media" }),
        {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(json)
        }
    );
}

async function driveCreateJsonFile({ name, parents, json }) {
    const data = await driveMultipartUpload({
        metadata: {
            name,
            parents,
            mimeType: "application/json"
        },
        content: JSON.stringify(json),
        contentType: "application/json"
    });

    return data.id;
}

async function findDriveFileByName(name) {
    return driveFindFileByNameInFolder(name, ACCESS4_ROOT_ID);
}

async function verifyWritable(folderId) {
    log("? Verifying Drive write access (probe)");
    await fetch(buildDriveUrl("files", {
        q: `'${folderId}' in parents`,
        pageSize: 1
    }), {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });
    log("? Drive access verified (read scope OK)");
}

async function verifySharedRoot() {
    await driveFetch(buildDriveUrl(`files/${ACCESS4_ROOT_ID}`, {
        fields: "id"
    }));
}

/* ================= AUTH ================= */
async function ensureAuthorization() {
    const q = `'${ACCESS4_ROOT_ID}' in parents and name='${AUTH_FILE_NAME}'`;
    const res = await driveFetch(buildDriveUrl("files", {
        q,
        fields: "files(id)"
    }));
    if (!res.files.length) {
        log("? authorized.json not found, creating genesis authorization...");
        await createGenesisAuthorization();
        return;
    }
    const data = await driveFetch(buildDriveUrl(`files/${res.files[0].id}`, {
        alt: "media"
    }));
    if (!data.admins.includes(userEmail) && !data.members.includes(userEmail))
    throw new Error("Unauthorized user");
    log("? Authorized user verified");
}

async function createGenesisAuthorization() {
    const file = await driveFetch(buildDriveUrl("files"), {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            name: AUTH_FILE_NAME,
            parents: [ACCESS4_ROOT_ID]
        })
    });
    await driveFetch(buildDriveUrl(`files/${file.id}`, {
        uploadType: "media"
    }), {
        method: "PATCH",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            admins: [userEmail],
            members: [userEmail],
            created: new Date().toISOString(),
            version: 1
        })
    });
    log(`? Genesis authorization created for ${userEmail}`);
}

/* ================= IDENTITY (4.1) ================= */
function identityKey() {
    return `access4.identity::${userEmail}::${getDeviceId()}`;
}

function saveIdentity(id) {
    localStorage.setItem(identityKey(), JSON.stringify(id));
}

/* ================= CRYPTO ================= */
async function createPasswordVerifier(key) {
    const data = new TextEncoder().encode("identity-ok");
    return encrypt(data, key);
}

async function verifyPasswordVerifier(verifier, key) {
    const buf = await decrypt(verifier, key);
    const text = new TextDecoder().decode(buf);
    if (text !== "identity-ok") {
        throw new Error("INVALID_PASSWORD");
    }
}

async function encrypt(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({
        name: "AES-GCM",
        iv
    }, key, data);
    return {
        iv: btoa(String.fromCharCode(...iv)),
        data: btoa(String.fromCharCode(...new Uint8Array(enc)))
    };
}

async function generateDeviceKeypair() {
    const pair = await crypto.subtle.generateKey({
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    },
        true,
        ["encrypt", "decrypt"]
    );

    const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
    const publicKeySpki = await crypto.subtle.exportKey("spki", pair.publicKey);

    return {
        privateKeyPkcs8,
        publicKeySpki
    };
}

async function buildIdentityFromKeypair({privateKeyPkcs8, publicKeySpki}, pwd, opts = {}) {
    const pubB64 = btoa(String.fromCharCode(...new Uint8Array(publicKeySpki)));
    const fingerprint = await computeFingerprintFromPublicKey(pubB64);

    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const kdf = {
        salt: btoa(String.fromCharCode(...saltBytes)),
        iterations: 100000
    };

    const key = await deriveKey(pwd, kdf);
    const passwordVerifier = await createPasswordVerifier(key);
    const encryptedPrivateKey = await encrypt(privateKeyPkcs8, key);

    return {
        passwordVerifier,
        encryptedPrivateKey,
        publicKey: pubB64,
        fingerprint,
        kdf,
        deviceId: getDeviceId(),
        email: userEmail,
        created: new Date().toISOString(),
        ...opts
    };
}

async function encryptPrivateKeyWithPassword(privateKey, password) {
    // 1️⃣ Export private key (raw)
    const rawPrivate = await crypto.subtle.exportKey("raw", privateKey);

    // 2️⃣ Derive AES key from password
    const kdf = {
        salt: crypto.getRandomValues(new Uint8Array(16)),
        iterations: 200_000,
        hash: "SHA-256"
    };

    const aesKey = await deriveKey(password, kdf);

    // 3️⃣ Encrypt
    const encrypted = await encrypt(rawPrivate, aesKey);

    // 4️⃣ Package
    return {
        version: 1,
        kdf,
        cipher: "AES-256-GCM",
        encrypted
    };
}


async function migrateIdentityWithVerifier(id, pwd) {
    log("🛠️ Migrating identity to add password verifier");

    const key = await deriveKey(pwd, id.kdf);

    // Prove password correctness by decrypting private key
    await decrypt(id.encryptedPrivateKey, key);

    // Create and attach verifier
    id.passwordVerifier = await createPasswordVerifier(key);

    saveIdentity(id);

    log("✅ Identity auto-migrated with password verifier");
}


/* ================= BIOMETRIC ================= */
function bioCredKey() {
    return `access4.bio.cred::${userEmail}::${getDeviceId()}`;
}

function bioPwdKey() {
    return `access4.bio.pwd::${userEmail}::${getDeviceId()}`;
}

async function enrollBiometric(pwd) {
    if (!window.PublicKeyCredential) return;
    const cred = await navigator.credentials.create({
        publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: {
                name: "Access4"
            },
            user: {
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: userEmail,
                displayName: userEmail
            },
            pubKeyCredParams: [{
                type: "public-key",
                alg: -7
            }],
            authenticatorSelection: {
                userVerification: "required"
            },
            timeout: 60000
        }
    });
    localStorage.setItem(bioCredKey(), btoa(String.fromCharCode(...new Uint8Array(cred.rawId))));
    localStorage.setItem(bioPwdKey(), btoa(pwd));
    log("🧬 Hidden biometric shortcut enrolled");
}

async function biometricAuthenticateFromGesture() {
    if (!window.PublicKeyCredential) {
        log("⚠️ Biometric not supported on this browser");
        return;
    }

    const rawId = localStorage.getItem(bioCredKey());
    const storedPwd = localStorage.getItem(bioPwdKey());
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
                    type: "public-key",
                    id: Uint8Array.from(atob(rawId), c => c.charCodeAt(0))
                }],
                userVerification: "required"
            }
        });
        log("✅ Biometric authentication prompt completed successfully");
        log("🔓 Using stored password to unlock identity...");
        await unlockIdentityFlow(atob(storedPwd));
    } catch (e) {
        log("⚠️ Biometric prompt failed or canceled: " + e.message);
    }
}

/* ================= HIDDEN GESTURE ================= */
function armBiometric() {
    biometricIntent = true;
    log("👆 Hidden biometric intent armed");

    if (unlockedPassword && !biometricRegistered) {
        log("🔐 Password already unlocked, enrolling biometric immediately...");
        enrollBiometric(unlockedPassword).then(() => biometricRegistered = true);
    }
}

// attach gesture logic
function setupTitleGesture() {
    const t = document.getElementById("titleGesture");
    if (!t) return; // defensive, avoids silent crash

    let timer = null;

    t.addEventListener("pointerdown", () => {
        timer = setTimeout(armBiometric, 5000);
    });

    ["pointerup", "pointerleave", "pointercancel"].forEach(e =>
    t.addEventListener(e, () => clearTimeout(timer))
    );

    t.addEventListener("click", async () => {
        if (!biometricRegistered) return;
        await biometricAuthenticateFromGesture();
    });
}

/* ================= STEP 4.1: DEVICE PUBLIC KEY ================= */
async function hasRecoveryKey() {
    // TEMP: replace with Drive check later
    const marker = localStorage.getItem("recoveryKeyPresent");
    return !!marker;
}





/* ================= RECOVERY KEY ================= */


async function ensureRecoveryFolder() {
    const q = `'${ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`;
    const res = await driveFetch(buildDriveUrl("files", {
        q,
        fields: "files(id)"
    }));

    if (res.files.length) {
        return res.files[0].id;
    }

    const folder = await driveFetch(buildDriveUrl("files"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            name: "recovery",
            mimeType: "application/vnd.google-apps.folder",
            parents: [ACCESS4_ROOT_ID]
        })
    });

    return folder.id;
}

/* ================= ENVELOPE WRITE ASSERTION + HOUSEKEEPING HELPER ================= */
async function assertEnvelopeWrite(envelopeName) {

    if (!driveLockState) {
        throw new Error(`Cannot write: no drive lock state for "${envelopeName}"`);
    }

    if (driveLockState.envelopeName !== envelopeName) {
        throw new Error(`Cannot write: lock does not match envelope "${envelopeName}"`);
    }

    if (driveLockState.mode !== "write") {
        throw new Error(`Read-only session — write not permitted for envelope "${envelopeName}"`);
    }

    log(`[assertEnvelopeWrite] Ownership confirmed for envelope "${envelopeName}"`);

    // Future housekeeping hook: missing device/recovery keys
    // console.log(`[housekeeping] Envelope ownership confirmed for "${envelopeName}"`);
}

function isKeyUsableForEncryption(pubKeyRecord) {
    return pubKeyRecord.state === "active";
}

function isKeyUsableForDecryption(pubKeyRecord) {
    return pubKeyRecord.state === "active" ||
    pubKeyRecord.state === "deprecated";
}

/* ------------------- Public key Registry building steps ---------------- */

function buildSupersedenceIndex(keys) {
    const superseded = new Set();

    for (const key of keys) {
        if (key.supersedes) {
            superseded.add(key.supersedes);
        }
    }

    return superseded;
}

function finalizeKeyRegistry(registry) {
    Object.freeze(registry.flat.activeDevices);
    Object.freeze(registry.flat.deprecatedDevices);
    Object.freeze(registry.flat.recoveryKeys);
    Object.freeze(registry.flat);
    Object.freeze(registry.accounts);
    Object.freeze(registry);
}

/* ------------------- Envelope check+acquire lock helpers ---------------- */

function extendLock(lock, ttlMs) {
    return {
        ...lock,
        expiresAt: new Date(Date.now() + ttlMs).toISOString()
    };
}

function startLockHeartbeat({envelopeName, self, readLockFromDrive, writeLockToDrive, onLost}) {
    let stopped = false;

    const tick = async () => {
        if (stopped) return;

        try {
            const lockFile = await readLockFromDrive(envelopeName);
            const diskLock = lockFile?.json;

            const evalResult = evaluateEnvelopeLock(diskLock, self);
            if (evalResult.status !== "owned") {
                stopped = true;
                onLost?.(evalResult);
                return;
            }

            // 🔑 MERGE: never allow generation to move backwards
            const mergedLock = {
                ...diskLock,
                generation: Math.max(
                    diskLock?.generation ?? 0,
                    driveLockState?.lock?.generation ?? 0
                )
            };

            const extended = extendLock(mergedLock, LOCK_TTL_MS);

            if (extended.generation < driveLockState.lock.generation) {
                throw new Error("Heartbeat attempted to regress generation");
            }

            await writeLockToDrive(
                envelopeName,
                extended,
                lockFile.fileId
            );

            driveLockState.lock = extended;   // keep local state authoritative
            //log(`💓 Heartbeat OK (gen=${extended.generation}, expires ${extended.expiresAt})`);
            updateLockStatusUI();
        } catch (err) {
            stopped = true;
            onLost?.({ reason: "heartbeat-failed", error: err });
        }
    };

    const timer = setInterval(tick, HEARTBEAT_INTERVAL);

    return {
        stop() {
            stopped = true;
            clearInterval(timer);
        }
    };
}

function handleDriveLockLost(info) {
    log("❌ Drive lock lost: " + JSON.stringify(info));

    if (driveLockState?.heartbeat) {
        driveLockState.heartbeat.stop();
    }

    driveLockState = null;

    updateLockStatusUI();
}

async function releaseDriveLock() {
    if (!driveLockState?.fileId) return;

    driveLockState.heartbeat?.stop();

    const cleared = {
        ...driveLockState.lock,
        expiresAt: new Date(0).toISOString()
    };

    await writeLockToDrive(
        driveLockState.envelopeName,
        cleared,
        driveLockState.fileId
    );

    log("🔓 Drive lock released");
    driveLockState = null;
}

async function addRecoveryKeyToEnvelope({ publicKey, keyId }) {
    const envelopeName = "envelope.json";

    log("🛟 Adding recovery key to envelope...");

    // 1️⃣ Load existing envelope from Drive
    const envelopeFile = await readEnvelopeFromDrive(envelopeName);
    if (!envelopeFile) {
        throw new Error("Envelope missing — cannot add recovery key");
    }

    await assertEnvelopeWrite(envelopeName);

    const envelope = envelopeFile.json;

    // 2️⃣ Check if recovery key already exists
    if (envelope.keys?.some(k => k.role === "recovery" && k.keyId === keyId)) {
        log("🛟 Recovery key already present in envelope");
    } else {
        // 3️⃣ Unwrap CEK using the first active device key
        log("🔑 Unwrapping CEK with active device key...");
        const cek = await unwrapContentKey(
            envelope.keys[0].wrappedKey,
            envelope.keys[0].keyId
        );
        log("✅ CEK unwrapped");

        // 4️⃣ Wrap CEK for the new recovery key
        log("🔒 Wrapping CEK for recovery key...");
        let wrappedKey;
        try {
            wrappedKey = await wrapContentKeyForDevice(cek, publicKey);
            log("✅ CEK wrapped for recovery key");
        } catch (err) {
            console.error("❌ Error wrapping CEK:", err);
            throw err;
        }

        // 5️⃣ Add recovery key to envelope
        envelope.keys.push({
            role: "recovery",
            keyId,
            wrappedKey
        });

        log("[DEBUG] Added recovery key to envelope.keys: " + envelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));
    }

    // ---- Housekeeping CEK wrap for all devices & recovery keys (force write) ----
    if (driveLockState?.self && driveLockState.envelopeName === envelopeName) {
        log("🧹 Performing CEK housekeeping with force write");
        const updatedEnvelope = await wrapCEKForRegistryKeys(true); // <- forceWrite = true

        log("[DEBUG] Updated envelope after wrapCEKForRegistryKeys: " + updatedEnvelope.keys.map(k => ({
            role: k.role,
            keyId: k.keyId,
            hasWrappedKey: !!k.wrappedKey
        })));

        // 6️⃣ Write updated envelope safely
        await writeEnvelopeSafely(envelopeName, updatedEnvelope);
    }

    log("✅ Recovery key added to envelope and saved");
}

/*-------------- Drive lock file io helpers recently added after baseline  ------------------------*/
async function readLockFromDrive(envelopeName) {
    const lockName = `${envelopeName}.lock`;

    const file = await findDriveFileByName(lockName);
    if (!file) return null;

    const json = await driveReadJsonFile(file.id);

    return {
        fileId: file.id,
        json
    };
}

/* ================= LOGOUT ================= */
function logout() {
    log("🔒 Logging out");

    // 1️⃣ Release Drive lock if held
    handleDriveLockLost(); // stops heartbeat & clears local driveLockState

    // 2️⃣ Clear user-specific memory
    accessToken = null;
    userEmail = null;

    // 3️⃣ Clear UI state
    unlockedView.style.display = "none";
    loginView.style.display = "block";

    signinBtn.disabled = false;

    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";

    passwordInput.value = "";
    confirmPasswordInput.value = "";

    resetUnlockUi();

    // 4️⃣ Clear biometric data (optional)
    localStorage.removeItem(bioCredKey());
    localStorage.removeItem(bioPwdKey());
    biometricRegistered = false;
    biometricIntent = false;

    log("✅ Logout completed");
}

/* ----------------- UI action handlers -------------------*/
// Ensure UI starts in a safe locked state
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

function resetUnlockUi() {
    // Clear password inputs
    passwordInput.value = "";
    confirmPasswordInput.value = "";

    // Reset button state
    unlockBtn.disabled = false;
    unlockBtn.textContent = "Unlock";

    // Clear messages
    showUnlockMessage("");
}

async function handleCreateRecoveryClick() {
    log("🛟 Starting recovery key creation");

    const pwd = passwordInput.value;
    const confirm = confirmPasswordInput.value;

    if (!pwd || pwd.length < 7) {
        throw new Error("Recovery password must be at least 7 characters.");
    }
    if (pwd !== confirm) {
        throw new Error("Recovery passwords do not match.");
    }

    unlockBtn.disabled = true;
    showUnlockMessage("Creating recovery key…");

    // 1️⃣ Generate RSA keypair (same as device)
    const keypair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
    log("✅ Recovery keypair generated");

    // 2️⃣ Export keys
    const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", keypair.privateKey);
    const publicKeySpki = await crypto.subtle.exportKey("spki", keypair.publicKey);
    log("✅ Recovery keys exported");

    // 3️⃣ Build recovery identity
    const recoveryIdentity = await buildIdentityFromKeypair(
        { privateKeyPkcs8, publicKeySpki },
        pwd,
        { type: "recovery", createdBy: getDeviceId() }
    );
    log("✅ Private key encrypted with recovery password");

    // 4️⃣ Ensure recovery folder
    const recoveryFolderId = await ensureRecoveryFolder();

    // 5️⃣ Write private recovery file
    await driveCreateJsonFile({
        name: "recovery.private.json",
        parents: [recoveryFolderId],
        json: recoveryIdentity
    });
    log("✅ recovery.private.json written");

    // 6️⃣ Write public recovery file (matching device key structure)
    const recoveryPublicJson = {
        type: "recovery",
        role: "recovery",
        keyId: recoveryIdentity.fingerprint,
        fingerprint: recoveryIdentity.fingerprint,
        created: recoveryIdentity.created,
        algorithm: {
            name: "RSA-OAEP",
            modulusLength: 2048,
            hash: "SHA-256",
            usage: ["encrypt"]
        },
        publicKey: {
            format: "spki",
            encoding: "base64",
            data: btoa(String.fromCharCode(...new Uint8Array(publicKeySpki)))
        }
    };

    await driveCreateJsonFile({
        name: "recovery.public.json",
        parents: [recoveryFolderId],
        json: recoveryPublicJson
    });
    log("✅ recovery.public.json written");

    // 7️⃣ Add to envelope for CEK housekeeping
    await addRecoveryKeyToEnvelope({
        publicKey: publicKeySpki,
        keyId: recoveryIdentity.fingerprint
    });

    log("🛟 Recovery key successfully established");
    showUnlockMessage("Recovery key created!", "unlock-message success");
    unlockBtn.disabled = false;
}

async function handleSaveClick() {
    const text = plaintextInput.value;
    if (!text) {
        log("⚠️ Nothing to encrypt");
        return;
    }

    try {
        await encryptAndPersistPlaintext(text);
        plaintextInput.value = "";
    } catch (e) {
        log("❌ Encryption failed: " + e.message);
    }
}

async function encryptAndPersistPlaintext(plainText) {
    const envelopeName = "envelope.json";

    // Ensure we own the lock
    if (!driveLockState || driveLockState.envelopeName !== envelopeName) {
        await acquireDriveWriteLock(envelopeName);
    }

    await assertEnvelopeWrite(envelopeName);

    // Load envelope
    const envelopeFile = await readEnvelopeFromDrive(envelopeName);
    if (!envelopeFile?.json) {
        throw new Error("Envelope missing");
    }

    const envelope = envelopeFile.json;

    console.log("[encryptAndPersistPlaintext] envelope: " + envelope)

    // Unwrap CEK using this device
    const selfEntry = envelope.keys.find(k =>
    k.deviceId === driveLockState.self.deviceId
    );

    if (!selfEntry) {
        throw new Error("No device key to unwrap CEK");
    }

    const cek = await unwrapContentKey(
        selfEntry.wrappedKey,
        selfEntry.keyId
    );

    log('cek: ${JSON.stringify(cek)}');

    // Encrypt new payload
    const payload = await encryptPayload(plainText, cek);

    // Update envelope payload only
    const updatedEnvelope = {
        ...envelope,
        payload
    };

    // Persist safely (generation + lock heartbeat preserved)
    const written = await writeEnvelopeSafely(envelopeName, updatedEnvelope);

    log("🔒 Payload encrypted & written to envelope");

    // Verify decrypt immediately (sanity + demo)
    const decrypted = await openEnvelope(written);
    log("🔓 Decrypted payload:");
    log(decrypted);
}

function isEnvelopeReadOnly() {
    return !driveLockState || driveLockState.mode !== "write";
}

function updateLockStatusUI() {
    if (!driveLockState) return;

    const { expiresAt } = driveLockState.lock;
    //log(`🔐 You hold the envelope lock (expires ${expiresAt})`);
}

function showVaultUI({ readOnly = false } = {}) {
    // Hide login / password sections
    loginView.style.display = "none";
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";

    // Show main unlocked view
    unlockedView.style.display = "block";

    // Update UI for read-only mode
    if (readOnly) {
        log("⚠️ Unlocked UI in read-only mode: disabling save button");
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
}

function showUnlockMessage(msg, type = "error") {
    const el = document.getElementById("unlockMessage");
    if (!el) return;

    el.textContent = msg;
    el.className = `unlock-message ${type}`;
}


// Button to invoke it doens't exist in the latest ui, add to enable (for testing biometric behavior)
function handleResetBiometricClick() {
    localStorage.removeItem(bioCredKey());
    localStorage.removeItem(bioPwdKey());
    biometricRegistered = false;
    biometricIntent = false;
    log("⚠️ Biometric registration cleared for testing");
};

function handleLogoutClick() {
    logout();
}

function resetIdleTimer() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(async () => {
        log("[resetIdleTimer] Inactivity timeout — releasing Drive lock");
        await releaseDriveLock();
    }, 10 * 60 * 1000); // 10 minutes
}


/* ---------- TEMPORARY ---------*/


/*-------- TEMPORARY ENDS -------*/

// IMPORTANT - DO NOT DELETE
window.onload = async () => {
    await onLoad();
    await initGIS();

    // Ensure app always starts in safe locked state
    initLoginUI();

    // Clear any lingering driveLockState in memory
    driveLockState = null;

    // Optional: detect if a user was partially logged in
    // If you want logout to be final, skip restoring user session
    // Otherwise, you could try reacquiring the lock here
};
