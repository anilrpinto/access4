"use strict";

/* ================= CONFIG ================= */
const CLIENT_ID = "738922366916-ppn1c24mp9qamr6pdmjqss3cqjmvqljv.apps.googleusercontent.com";
const SCOPES = "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email";
const ACCESS4_ROOT_ID = "1zQPiXTCDlPjzgD1YZiVKsRB2s4INUS_g";
const AUTH_FILE_NAME = "authorized.json";
const PUBKEY_FOLDER_NAME = "pub-keys";

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

/* ================= DOM ================= */
let userEmailSpan;
let signinBtn;
let passwordSection;
let confirmPasswordSection;
let unlockBtn;
let logoutBtn;

let loginView;
let unlockedView;
let passwordInput;
let confirmPasswordInput;
let logEl;

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
    logEl.textContent += msg + "\n";
}

/* ================= DEVICE ID (4.1) ================= */
function deviceIdKey() {
    return "access4.device.id";
}

function getDeviceId() {
    let id = localStorage.getItem(deviceIdKey());
    if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem(deviceIdKey(), id);
        log("🆔 New device ID generated");
    }
    return id;
}

/* ================= GOOGLE SIGN-IN ================= */
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

    // Initial UI state
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";
    unlockedView.style.display = "none";

    // Wire handlers
    signinBtn.onclick = handleSignInClick;
    unlockBtn.onclick = handleUnlockClick;
    logoutBtn.onclick = handleLogoutClick;

    setupTitleGesture();

    initLoginUI();

    log("UI ready");
}

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
    params.includeItemsFromAllDrives = true;
    return `https://www.googleapis.com/drive/v3/${path}?` +
    Object.entries(params).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
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

async function loadIdentity() {
    const raw = localStorage.getItem(identityKey());
    return raw ? JSON.parse(raw) : null;
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

async function decrypt(enc, key) {
    return crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: Uint8Array.from(atob(enc.iv), c => c.charCodeAt(0))
    },
        key,
        Uint8Array.from(atob(enc.data), c => c.charCodeAt(0))
    );
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

/* ================= CREATE IDENTITY ================= */
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
    log("↪ Supersedes keyId:", oldIdentity.fingerprint);

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

/* ================= UNLOCK FLOW ================= */
async function unlockIdentityFlow(pwd) {
    if (!pwd || pwd.length < 7) {
        const e = new Error(UNLOCK_ERROR_DEFS.WEAK_PASSWORD.message);
        e.code = UNLOCK_ERROR_DEFS.WEAK_PASSWORD.code;
        throw e;
    }

    log("🔓 Unlock attempt started");

    if (!accessToken) {
        const e = new Error(UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.message);
        e.code = UNLOCK_ERROR_DEFS.NO_ACCESS_TOKEN.code;
        throw e;
    }

    let id = await loadIdentity();

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

    // ─────────────────────────────
    // First-time identity creation (LOCKED)
    // ─────────────────────────────
    if (!id) {
        log("❌ No local identity found — cannot unlock");
        const e = new Error(UNLOCK_ERROR_DEFS.NO_IDENTITY.message);
        e.code = UNLOCK_ERROR_DEFS.NO_IDENTITY.code;
        throw e;
    } else {
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

        // ─────────────────────────────
        // 🔓 Attempt private key decrypt
        // (Safari may fail here)
        // ─────────────────────────────
        let decrypted = false;
        try {
            await decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("✅ Identity successfully decrypted");
        } catch {
            log("⚠️ Safari crypto limitation detected");
        }

        // ─────────────────────────────
        // 🔁 Rotation allowed ONLY after
        // password verification
        // ─────────────────────────────
        if (id.supersedes || !decrypted) {
            log("🔁 Identity superseded or Safari-limited — rotating device key");
            await rotateDeviceIdentity(pwd);
            id = await loadIdentity();
            decrypted = true;
        }

        // ─────────────────────────────
        // 🔁 Final Safari recovery path
        // ─────────────────────────────
        if (!decrypted) {
            log("🔁 Safari recovery path — recreating identity");
            await createIdentity(pwd);
            id = await loadIdentity();

            if (!id) {
                const e = new Error(UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.message);
                e.code = UNLOCK_ERROR_DEFS.SAFARI_RECOVERY.code;
                throw e;
            }
        }
    }

    // ─────────────────────────────
    // Session unlocked
    // ─────────────────────────────
    unlockedPassword = pwd;

    if (biometricIntent && !biometricRegistered) {
        await enrollBiometric(pwd);
        biometricRegistered = true;
    }

    log("🔑 Proceeding to device public key exchange");
    await ensureDevicePublicKey();

    return id;
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

        log("🔁 Device public key updated after rotation (content only)");
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

/* ================= STEP 5: ENVELOPE CRYPTO ================= */

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

/* ---Unwrap CEK Using Local Private Key (rotation-safe) --- */
async function unwrapContentKey(wrappedKeyBase64, keyId) {
    const id = await loadIdentity();
    if (!id) throw new Error("Local identity missing");

    const pwd = unlockedPassword;
    if (!pwd) throw new Error("Identity not unlocked");

    // 1️⃣ Determine which private key must be used
    let encryptedPrivateKey, kdf;

    if (keyId === id.fingerprint) {
        encryptedPrivateKey = id.encryptedPrivateKey;
        kdf = id.kdf;
    } else if (id.previousKeys?.length) {
        const prev = id.previousKeys.find(k => k.fingerprint === keyId);
        if (!prev) {
            throw new Error("No matching previous private key for keyId");
        }
        encryptedPrivateKey = prev.encryptedPrivateKey;
        kdf = prev.kdf;
    } else {
        throw new Error("No private key available for keyId");
    }

    // 2️⃣ Decrypt the correct private key
    const derivedKey = await deriveKey(pwd, kdf);
    const privateKeyPkcs8 = await decrypt(encryptedPrivateKey, derivedKey);

    // 3️⃣ Import private key
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyPkcs8,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["unwrapKey"]
    );

    // 4️⃣ Unwrap CEK
    const wrappedBytes = Uint8Array.from(atob(wrappedKeyBase64), c => c.charCodeAt(0));

    return crypto.subtle.unwrapKey(
        "raw",
        wrappedBytes,
        privateKey,
        { name: "RSA-OAEP" },
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
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
            account: devicePublicKeyRecord.account,
            deviceId: devicePublicKeyRecord.deviceId,
            keyId: devicePublicKeyRecord.fingerprint,
            keyVersion: devicePublicKeyRecord.version,
            wrappedKey
        }],
        created: new Date().toISOString()
    };
}

async function openEnvelope(envelope) {
    validateEnvelope(envelope);

    const entry = await selectDecryptableKey(envelope);

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
    if (!envelope.version) throw new Error("Envelope missing version");
    if (!Array.isArray(envelope.keys) || !envelope.keys.length)
    throw new Error("Envelope has no key entries");

    for (const k of envelope.keys) {
        if (!k.deviceId) throw new Error("Key entry missing deviceId");
        if (!k.wrappedKey) throw new Error("Key entry missing wrappedKey");

        // keyId is REQUIRED for rotation safety
        if (!k.keyId) {
            throw new Error("Key entry missing keyId (rotation unsafe)");
        }
    }
}

async function selectDecryptableKey(envelope) {
    const id = await loadIdentity();
    if (!id) throw new Error("Local identity missing");

    const entry = envelope.keys.find(k => {
        if (k.deviceId !== id.deviceId) return false;
        // Rotation-aware selection
        return keyMatchesOrIsSuperseded(k.keyId, id);
    });

    if (!entry) throw new Error("No decryptable key for this device identity");

    if (entry.keyId !== id.fingerprint) {
        log("🔁 Envelope encrypted with previous device key — rotation detected");
    }

    return entry;
}

function keyMatchesOrIsSuperseded(entryKeyId, localIdentity) {
    if (!localIdentity?.fingerprint) return false;
    // Exact match (current key)
    if (entryKeyId === localIdentity.fingerprint) return true;
    // Superseded key (previous rotation)
    if (localIdentity.previousKeys?.some(k => k.fingerprint === entryKeyId)) return true;
    return false;
}


function isKeyUsableForEncryption(pubKeyRecord) {
    return pubKeyRecord.state === "active";
}

function isKeyUsableForDecryption(pubKeyRecord) {
    return pubKeyRecord.state === "active" ||
    pubKeyRecord.state === "deprecated";
}

/* ------------------- Public key Registry building steps ---------------- */
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

function buildSupersedenceIndex(keys) {
    const superseded = new Set();

    for (const key of keys) {
        if (key.supersedes) {
            superseded.add(key.supersedes);
        }
    }

    return superseded;
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

function finalizeKeyRegistry(registry) {
    Object.freeze(registry.flat.activeDevices);
    Object.freeze(registry.flat.deprecatedDevices);
    Object.freeze(registry.flat.recoveryKeys);
    Object.freeze(registry.flat);
    Object.freeze(registry.accounts);
    Object.freeze(registry);
}

async function buildKeyRegistryFromDrive(rawPublicKeyJsons) {
    resetKeyRegistry();

    for (const raw of rawPublicKeyJsons) {
        const normalized = normalizePublicKey(raw);
        registerPublicKey(normalized);
    }

    keyRegistry.loadedAt = new Date().toISOString();

    // Validate structural integrity
    validateKeyRegistry(keyRegistry);

    // Resolve terminal active devices
    const activeDevices =
    resolveEffectiveActiveDevices(keyRegistry.flat);

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

/* ------------------- Envelope check+acquire lock helpers ---------------- */
function evaluateEnvelopeLock(lock, self) {
    if (!lock) return { status: "free" };

    const now = Date.now();
    const expired = Date.parse(lock.expiresAt) <= now;

    if (expired) return { status: "free", reason: "expired" };

    if (
    lock.owner.account === self.account &&
    lock.owner.deviceId === self.deviceId
    ) {
        return { status: "owned", lock };
    }

    return { status: "locked", lock };
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

            log(`💓 Heartbeat OK (gen=${extended.generation}, expires ${extended.expiresAt})`);

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

async function acquireDriveWriteLock(envelopeName) {
    log("🔐 acquireDriveWriteLock: start");

    const identity = await loadIdentity();
    const self = { account: userEmail, deviceId: identity.deviceId };

    const lockFile = await readLockFromDrive(envelopeName);
    const evalResult = evaluateEnvelopeLock(lockFile?.json, self);

    if (evalResult.status === "locked") {
        throw new Error("Failed to acquire lock: locked-by-other");
    }

    const envelope = await readEnvelopeFromDrive(envelopeName).catch(() => null);
    const generation = envelope?.generation ?? 0;

    const lock = createLockPayload(self, envelopeName, generation);

    log("🔐 writing lock to Drive...");
    const fileId = await writeLockToDrive(envelopeName, lock, lockFile?.fileId);

    log("🔐 lock written, fileId:", fileId);

    driveLockState = {
        envelopeName,
        fileId,
        lock,
        self,
        heartbeat: startLockHeartbeat({
            envelopeName,
            self,
            readLockFromDrive,
            writeLockToDrive,
            onLost: info => log("❌ Lock lost: " + JSON.stringify(info))
        })
    };

    log("✅ acquireDriveWriteLock completed");
    return driveLockState;
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

/* ================= WRITE ENVELOPE WITH LOCK ================= */
async function writeEnvelopeWithLock(envelopeName, envelopeData) {

    log("➡️ Entered writeEnvelopeWithLock()");

    if (!driveLockState || driveLockState.envelopeName !== envelopeName) {
        throw new Error("Cannot write: Drive lock not held for this envelope");
    }

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

        log(`✅ Envelope "${envelopeName}" written, generation=${newGeneration}`);
        return newEnvelopeContent;

    } catch (err) {
        log(`❌ Failed to write envelope "${envelopeName}": ${err.message}`);
        throw err;
    }
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

async function readEnvelopeFromDrive(envelopeName) {
    const file = await findDriveFileByName(envelopeName);
    if (!file) return null;

    const json = await driveReadJsonFile(file.id);

    return {
        fileId: file.id,
        json
    };
}



/* ================= LOGOUT ================= */
function logout() {
    unlockedView.style.display = "none";
    loginView.style.display = "block";

    signinBtn.disabled = false;
    passwordSection.style.display = "none";
    passwordInput.value = "";
    confirmPasswordInput.value = "";

    accessToken = null;
    userEmail = null;
    location.reload();
}

/* ----------------- TESTS -------------------*/

async function runLockTest() {
    try {
        const envelopeName = "envelope-test.json";
        const envelopeData = { message: "Hello Drive!", createdAt: new Date().toISOString() };

        log("🚀 Starting test: acquire lock → write envelope → release lock");

        await acquireDriveWriteLock(envelopeName);

        await writeEnvelopeWithLock(envelopeName, envelopeData);
        await releaseDriveLock();

        log("🎉 Test completed successfully");
    } catch (err) {
        log("❌ Test failed: " + err.message);
    }
}


/* ----------------- UI action handlers -------------------*/
// Ensure UI starts in a safe locked state
function initLoginUI() {
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";
    unlockBtn.disabled = true;
    unlockMessage.textContent = "";
}

function resetUnlockUi() {
    // ✅ Reset inputs & enable button for create
    passwordInput.value = "";
    confirmPasswordInput.value = "";
    unlockBtn.disabled = false;
}

function handleSignInClick() {
    signinBtn.disabled = true;
    logEl.textContent = "";
    passwordSection.style.display = "block";

    tokenClient.requestAccessToken({ prompt: "consent select_account" });
}

async function onAuthReady(email) {
    userEmailSpan.textContent = email;

    try {
        const id = await loadIdentity();

        if (!id) {
            // New device → create identity
            showCreatePasswordUI();
            log("🆔 New device detected, prompting password creation");
            resetUnlockUi();
            return;
        }

        if (!id.passwordVerifier) {
            // Legacy identity → migration
            showUnlockPasswordUI({ migration: true });
            log("🧭 Identity missing password verifier — migration mode");
            resetUnlockUi();
            return;
        }

        // Returning user → unlock
        showUnlockPasswordUI();
        log("📁 Existing device detected, prompting unlock");
        resetUnlockUi();

    } catch (e) {
        log("❌ Error loading identity: " + e.message);
        unlockMessage.textContent = "Failed to load identity. Try again.";
    }
}

function showCreatePasswordUI() {
    passwordSection.style.display = "block";
    confirmPasswordSection.style.display = "block"; // confirmation required
    unlockBtn.textContent = "Create Password";
    unlockBtn.onclick = handleCreatePasswordClick;
    unlockMessage.textContent = "";
}

function showUnlockPasswordUI(options = {}) {
    passwordSection.style.display = "block";
    confirmPasswordSection.style.display = "none"; // no confirm for unlock
    unlockBtn.textContent = "Unlock";
    unlockBtn.onclick = handleUnlockClick;

    unlockMessage.textContent = options.migration
        ? "Identity missing password verifier — enter your password to upgrade."
        : "";
}

function hideLoginUI() {
    loginView.style.display = "none";
}

function showUnlockedUI() {
    unlockedView.style.display = "flex";
}

async function handleUnlockClick() {
    const pwd = passwordInput.value;

    showUnlockMessage(""); // clear previous

    if (!pwd) {
        showUnlockMessage("Password cannot be empty");
        return;
    }

    try {
        await unlockIdentityFlow(pwd);
        hideLoginUI();
        showUnlockedUI();
        log("🔑 Unlock successful!");
    } catch (e) {
        const def = Object.values(UNLOCK_ERROR_DEFS)
            .find(d => d.code === e.code);

        showUnlockMessage(def?.message || e.message || "Unlock failed");
        log("❌ Unlock failed: " + (def?.message || e.message));
    }
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
        hideLoginUI();
        showUnlockedUI();
        log("✅ New identity created and unlocked");
    } catch (e) {
        showUnlockMessage(e.message);
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

// IMPORTANT - DO NOT DELETE
window.onload = async () => {
    onLoad();
    await initGIS();
};
