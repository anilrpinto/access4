"use strict";

/* ================= CONFIG ================= */
const CLIENT_ID = "738922366916-ppn1c24mp9qamr6pdmjqss3cqjmvqljv.apps.googleusercontent.com";
const SCOPES = "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email";
const ACCESS4_ROOT_ID = "1zQPiXTCDlPjzgD1YZiVKsRB2s4INUS_g";
const AUTH_FILE_NAME = "authorized.json";
const PUBKEY_FOLDER_NAME = "pub-keys";

/* ================= STATE ================= */
let tokenClient;
let accessToken = null;
let userEmail = null;
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

const driveLockState = {
    held: false,
    envelopeName: null,
    self: null,
    lock: null,
    heartbeat: null
};


/* ================= LOG ================= */
function log(msg) {
    document.getElementById("log").textContent += msg + "\n";
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

    signinBtn.onclick = () => tokenClient.requestAccessToken({
        prompt: "consent select_account"
    });
    logoutBtn.onclick = logout;
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
    passwordBox.style.display = "block";

    biometricRegistered = !!localStorage.getItem(bioCredKey());
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
    document.getElementById("userEmail").textContent = userEmail;
    log("Signed in as xxx@gmail.com"); //+ userEmail);
}

/* ================= DRIVE HELPERS ================= */
function buildDriveUrl(path, params = {}) {
    params.supportsAllDrives = true;
    params.includeItemsFromAllDrives = true;
    return `https://www.googleapis.com/drive/v3/${path}?` +
    Object.entries(params).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
}

async function driveFetch(url, options = {}) {
    options.headers ||= {};
    options.headers.Authorization = `Bearer ${accessToken}`;
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

async function driveMultipartUpload({
    metadata,
    content,
    contentType = "application/json"
}) {
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

    return res;
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
    log("? Drive access verified (read OK)");
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

async function buildIdentityFromKeypair({
    privateKeyPkcs8,
    publicKeySpki
}, pwd, opts = {}) {
    const pubB64 = btoa(String.fromCharCode(...new Uint8Array(publicKeySpki)));
    const fingerprint = await computeFingerprintFromPublicKey(pubB64);

    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const kdf = {
        salt: btoa(String.fromCharCode(...saltBytes)),
        iterations: 100000
    };

    const key = await deriveKey(pwd, kdf);
    const encryptedPrivateKey = await encrypt(privateKeyPkcs8, key);

    return {
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

/* ================= UNLOCK FLOW ================= */
async function unlockIdentityFlow(pwd) {
    if (!pwd || pwd.length < 7) throw new Error("Weak password");
    log("🔓 Unlock attempt started");

    if (!accessToken) throw new Error("Access token missing");

    let id = await loadIdentity();
    if (!id) {
        log("📁 No local identity found, creating new one");
        await createIdentity(pwd);
        id = await loadIdentity();
    } else {
        log("📁 Local identity found");
        let decrypted = false;
        try {
            const key = await deriveKey(pwd, id.kdf);
            await decrypt(id.encryptedPrivateKey, key);
            decrypted = true;
            log("✅ Identity successfully decrypted");
        } catch {
            log("⚠️ Identity decryption failed on this device (Safari limitation)");
        }

        // --- Auto-rotate if envelope shows previous key was used
        if (!decrypted || id.supersedes) {
            log("🔁 Local identity superseded or decryption failed — rotating device key");
            await rotateDeviceIdentity(pwd);
            id = await loadIdentity(); // reload new identity
            decrypted = true;
        }

        if (!decrypted) {
            log("🔁 Recreating device identity for Safari compatibility");
            await createIdentity(pwd);
            id = await loadIdentity();
        }
    }

    unlockedPassword = pwd;
    if (biometricIntent && !biometricRegistered) {
        await enrollBiometric(pwd);
        biometricRegistered = true;
    }

    log("🔑 Proceeding to Step 4.1: device public key exchange");
    await ensureDevicePublicKey();
}


unlockBtn.onclick = async () => {
    try {
        await unlockIdentityFlow(passwordInput.value);
    } catch (e) {
        log("❌ Unlock failed: " + e.message);
    }
};

/* ================= BIOMETRIC ================= */
function bioCredKey() {
    return `access4.bio.cred::${userEmail}::${getDeviceId()}`;
}

function bioPwdKey() {
    return `access4.bio.pwd::${userEmail}::${getDeviceId()}`;
}

resetBioBtn.onclick = () => {
    localStorage.removeItem(bioCredKey());
    localStorage.removeItem(bioPwdKey());
    biometricRegistered = false;
    biometricIntent = false;
    log("⚠️ Biometric registration cleared for testing");
};

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

(() => {
    const t = document.getElementById("titleGesture");
    let timer = null;
    t.addEventListener("pointerdown", () => timer = setTimeout(armBiometric, 5000));
    ["pointerup", "pointerleave", "pointercancel"].forEach(e => t.addEventListener(e, () => clearTimeout(timer)));
    t.addEventListener("click", async () => {
        if (!biometricRegistered) return;
        await biometricAuthenticateFromGesture();
    });
})();

/* ================= LOGOUT ================= */
function logout() {
    accessToken = null;
    userEmail = null;
    location.reload();
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

/* ================= STEP 5: DEVICE PUBLIC KEY ================= */

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
function evaluateEnvelopeLock(lockJson, selfIdentity) {
    const now = Date.now();

    if (!lockJson || lockJson.version !== 1) {
        return Object.freeze({
            status: "free",
            reason: "no-lock-or-invalid",
            lock: null
        });
    }

    const expiresAt = Date.parse(lockJson.expiresAt);
    if (Number.isNaN(expiresAt) || expiresAt <= now) {
        return Object.freeze({
            status: "free",
            reason: "lock-expired",
            lock: null
        });
    }

    if (
    lockJson.owner?.account === selfIdentity.account &&
    lockJson.owner?.deviceId === selfIdentity.deviceId
    ) {
        return Object.freeze({
            status: "owned",
            reason: "lock-owned-by-self",
            lock: Object.freeze(lockJson)
        });
    }

    return Object.freeze({
        status: "locked",
        reason: "lock-owned-by-other",
        lock: Object.freeze(lockJson)
    });
}

function createLockPayload(self, envelopeName, generation) {
    const now = Date.now();
    const ttlMs = 30000;

    return {
        version: 1,
        envelope: envelopeName,

        owner: {
            account: self.account,
            deviceId: self.deviceId
        },

        lockId: crypto.randomUUID(),
        mode: "write",

        generation, // 🔒 WRITE FENCE

        acquiredAt: new Date(now).toISOString(),
        expiresAt: new Date(now + ttlMs).toISOString(),

        heartbeatIntervalMs: 10000
    };
}

async function attemptEnvelopeLock({envelopeName, self, readLockFromDrive, writeLockToDrive }) {
    // Step 1 — Read existing lock
    const existingLock = await readLockFromDrive(envelopeName);
    const evaluation = evaluateEnvelopeLock(existingLock, self);

    if (evaluation.status === "locked") {
        return Object.freeze({
            acquired: false,
            reason: "locked-by-other",
            lock: evaluation.lock
        });
    }

    // Step 2 — Create new lock
    const currentGeneration = readEnvelopeGeneration(existingEnvelope);
    const newLock = createLockPayload(self, envelopeName, currentGeneration);
    await writeLockToDrive(envelopeName, newLock);

    // Step 3 — Re-read to confirm
    const confirmLock = await readLockFromDrive(envelopeName);
    const confirmEval = evaluateEnvelopeLock(confirmLock, self);

    if (confirmEval.status === "owned") {
        return Object.freeze({
            acquired: true,
            reason: "lock-acquired",
            lock: confirmLock
        });
    }

    return Object.freeze({
        acquired: false,
        reason: "race-lost",
        lock: confirmLock
    });
}

const mockDrive = {
    lock: null
};

async function mockReadLock() {
    return mockDrive.lock;
}

async function mockWriteLock(_, lockJson) {
    mockDrive.lock = lockJson;
}

function extendLock(lockJson, ttlMs) {
    const now = Date.now();

    return {
        ...lockJson,
        expiresAt: new Date(now + ttlMs).toISOString()
    };
}

function startLockHeartbeat({ envelopeName, self, ttlMs, heartbeatMs, readLockFromDrive, writeLockToDrive, onLost }) {
    let stopped = false;

    const tick = async () => {
        if (stopped) return;

        try {
            const currentLock = await readLockFromDrive(envelopeName);
            const evalResult = evaluateEnvelopeLock(currentLock, self);

            if (evalResult.status !== "owned") {
                stopped = true;
                onLost?.(evalResult);
                return;
            }

            const extended = extendLock(currentLock, ttlMs);
            await writeLockToDrive(envelopeName, extended);
        } catch (err) {
            // Silent failure → allow TTL to expire
            stopped = true;
            onLost?.({ reason: "heartbeat-failed", error: err });
        }
    };

    const timer = setInterval(tick, heartbeatMs);

    return Object.freeze({
        stop() {
            stopped = true;
            clearInterval(timer);
        }
    });
}

async function acquireDriveWriteLock(envelopeName) {
    const identity = await loadIdentity();
    if (!identity) throw new Error("Identity not loaded");

    const self = {
        account: userEmail,
        deviceId: identity.deviceId
    };

    const result = await attemptEnvelopeLock({
        envelopeName,
        self,
        readLockFromDrive: mockReadLock,
        writeLockToDrive: mockWriteLock
    });

    if (!result.acquired) {
        throw new Error("Failed to acquire lock: " + result.reason);
    }

    driveLockState.held = true;
    driveLockState.envelopeName = envelopeName;
    driveLockState.self = self;
    driveLockState.lock = result.lock;

    // Start heartbeat
    driveLockState.heartbeat = startLockHeartbeat({
        envelopeName,
        self,
        ttlMs: 30000,
        heartbeatMs: 10000,
        readLockFromDrive: mockReadLock,
        writeLockToDrive: mockWriteLock,
        onLost: (info) => {
            log("❌ Lost lock:", info);
            driveLockState.held = false;
        }
    });

    log("🔒 Drive write lock acquired");
}

async function mockDriveDeleteLock() {
    mockDrive.lock = null;
}

async function releaseDriveLock() {
    if (!driveLockState.held) {
        log("ℹ️ No lock held — nothing to release");
        return;
    }

    log("🔓 Releasing Drive write lock");

    try {
        driveLockState.heartbeat?.stop();
        await mockDriveDeleteLock();

        driveLockState.held = false;
        driveLockState.envelopeName = null;
        driveLockState.self = null;
        driveLockState.lock = null;
        driveLockState.heartbeat = null;

        log("✅ Drive lock released");
    } catch (e) {
        log("⚠️ Failed to release lock (will expire naturally)");
    }
}

function readEnvelopeGeneration(envelopeJson) {
    return Number(envelopeJson?.generation) || 0;
}

function assertWriteFence(lock, envelope) {
    const envGen = Number(envelope?.generation) || 0;

    if (lock.generation !== envGen) {
        throw new Error(
            `Write fence violated — lock gen ${lock.generation}, envelope gen ${envGen}`
        );
    }
}

async function writeEnvelopeWithLock({envelopeName, envelope, lockState, writeFn}) {
    if (!lockState?.lock) {
        throw new Error("No active lock — write denied");
    }

    // Fence check
    assertWriteFence(lockState.lock, envelope);

    // Let caller mutate a copy
    const workingCopy = structuredClone(envelope);

    await writeFn(workingCopy);

    // Increment generation AFTER mutation
    const prevGen = Number(workingCopy.generation) || 0;
    workingCopy.generation = prevGen + 1;

    // Persist
    await writeEnvelopeToDrive(envelopeName, workingCopy);

    // Update local view
    envelope.generation = workingCopy.generation;

    return workingCopy;
}

// TEMP STUB — Phase 2C only
async function writeEnvelopeToDrive(envelopeName, envelopeJson) {
    log(`📝 [STUB] writeEnvelopeToDrive(${envelopeName})`);
    log(JSON.stringify(envelopeJson, null, 2));
}

/* ----------------- TESTS -------------------*/
async function testStep5_1() {
    log("🧪 Step 5.1 test started");

    // 1️⃣ Ensure identity is unlocked
    const id = await loadIdentity();
    if (!id) throw new Error("No local identity");

    if (!unlockedPassword) {
        throw new Error("Identity must be unlocked first");
    }

    // 2️⃣ Construct a mock device public-key record
    const deviceRecord = {
        account: userEmail,
        deviceId: getDeviceId(),
        version: "1",
        fingerprint: id.fingerprint,
        state: "active", // ✅ REQUIRED
        role: "device", // (optional but good)
        publicKey: {
            data: id.publicKey
        }
    };

    if (!deviceRecord.fingerprint) {
        log("WARN: Envelope created without keyId (Step 5.1 test mode)");
    }

    // 3️⃣ Encrypt test payload
    const message = "Hello Step 5.1 – envelope crypto works ✅";

    const envelope = await createEnvelope(message, deviceRecord);
    log("📦 Envelope created: " + JSON.stringify(envelope));

    // 4️⃣ Decrypt it
    const decrypted = await openEnvelope(envelope);

    log("🔓 Decrypted payload: " + decrypted);

    // 5️⃣ Assert
    if (decrypted !== message) {
        throw new Error("❌ Step 5.1 FAILED: plaintext mismatch");
    }

    log("✅ Step 5.1 PASSED");
}

async function testStep5_15_3() {
    log("🧪 Step 5.15.3 rotation test started");

    if (!unlockedPassword) throw new Error("Identity must be unlocked first");

    const oldId = await loadIdentity();
    if (!oldId) throw new Error("No local identity to rotate");

    // 1️⃣ Rotate the device identity
    log("🔁 Rotating device identity key");
    await rotateDeviceIdentity(unlockedPassword);

    const newId = await loadIdentity();
    log("✅ Device rotated successfully");
    log("↪ Old fingerprint: " + oldId.fingerprint);
    log("↪ New fingerprint: " + newId.fingerprint);

    // 2️⃣ Create an envelope using the old keyId (simulate old data)
    const oldDeviceRecord = {
        account: userEmail,
        deviceId: getDeviceId(),
        version: "1",
        fingerprint: oldId.fingerprint,
        state: "active",
        role: "device",
        publicKey: { data: oldId.publicKey }
    };

    const message = "Hello Step 5.15.3 – rotation test ✅";
    const envelope = await createEnvelope(message, oldDeviceRecord);

    log("📦 Envelope created with old keyId");

    // 3️⃣ Open the envelope — should detect rotation and decrypt using new identity
    const entry = await selectDecryptableKey(envelope);
    if (entry.keyId !== newId.fingerprint) {
        log("🔁 Envelope encrypted with previous device key — rotation detected");
    }

    const decrypted = await openEnvelope(envelope);

    log("🔓 Envelope decrypted after rotation: " + decrypted);

    if (decrypted !== message) throw new Error("❌ Step 5.15.3 FAILED: plaintext mismatch");

    log("✅ Step 5.15.3 PASSED");
}

async function testNormalizePublicKey() {
    log("🧪 Phase 2A.2 – normalizePublicKey() test started");

    // 🔒 Static sample — EXACT format fetched from Drive
    const rawPublicKeyFromDrive = {
        "version": "1",
        "account": "axxx@gmail.com",
        "deviceId": "06480138-79dd-4a23-8c97-8204f186f649",
        "keyId": "UgjDkqV55rfP9EwU9czbmMtstkKQjzTUO86ypxD2mLM=",
        "fingerprint": "UgjDkqV55rfP9EwU9czbmMtstkKQjzTUO86ypxD2mLM=",
        "state": "active",
        "role": "device",
        "supersedes": null,
        "created": "2026-01-17T22:54:12.842Z",
        "algorithm": {
            "type": "RSA",
            "usage": ["wrapKey"],
            "modulusLength": 2048,
            "hash": "SHA-256"
        },
        "publicKey": {
            "format": "spki",
            "encoding": "base64",
            "data": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8U2g..."
        },
        "deviceName": "Linux armv81 - Mozilla/5.0",
        "browser": "Google Chrome,Chromium",
        "os": "Linux armv81"
    };

    // 1️⃣ Normalize
    const normalized = normalizePublicKey(rawPublicKeyFromDrive);

    // 2️⃣ Log clearly
    log("🔍 Normalized public key:");
    log(JSON.stringify(normalized, null, 2));

    // 3️⃣ Assertions (minimal but strict)
    if (!normalized.keyId) throw new Error("Missing keyId after normalization");
    if (!normalized.fingerprint) throw new Error("Missing fingerprint");
    if (!normalized.publicKey?.data) throw new Error("Missing publicKey.data");
    if (normalized.role !== "device") throw new Error("Role mismatch");
    if (normalized.state !== "active") throw new Error("State mismatch");

    log("✅ Phase 2A.2 PASSED — normalization is stable and deterministic");
}

async function testStep2A_fullRegistryPipeline() {
    log("🧪 Step 2A.4.3 – full registry pipeline test");

    const raws = [
        {
            account: userEmail,
            role: "device",
            deviceId: "d1",
            fingerprint: "A",
            keyId: "A",
            state: "deprecated",
            publicKey: { format: "spki", encoding: "base64", data: "AAA" }
        },
        {
            account: userEmail,
            role: "device",
            deviceId: "d1",
            fingerprint: "B",
            keyId: "B",
            state: "active",
            supersedes: "A",
            publicKey: { format: "spki", encoding: "base64", data: "BBB" }
        }
    ];

    const registry = await buildKeyRegistryFromDrive(raws);

    if (registry.flat.activeDevices.length !== 1) {
        throw new Error("Expected exactly one effective active device");
    }

    log("📦 Final registry:");
    log(JSON.stringify(registry.flat.activeDevices, null, 2));
    log("✅ Step 2A.4.3 PASSED");
}

async function testStep2B_1() {
    console.clear();
    log("🧪 Step 2B.1 — Lock discovery & validation");

    const identity = await loadIdentity();

    const self = {
        account: userEmail,
        deviceId: identity.deviceId
    };

    const activeForeignLock = {
        version: 1,
        envelope: "envelope.json",
        owner: {
            account: "other@gmail.com",
            deviceId: "other-device"
        },
        lockId: "lock-123",
        mode: "write",
        acquiredAt: new Date(Date.now() - 5000).toISOString(),
        expiresAt: new Date(Date.now() + 20000).toISOString(),
        heartbeatIntervalMs: 10000
    };

    const expiredLock = {
        ...activeForeignLock,
        expiresAt: new Date(Date.now() - 1000).toISOString()
    };

    log("▶ Active foreign lock:");
    log(JSON.stringify(evaluateEnvelopeLock(activeForeignLock, self)));

    log("▶ Expired lock:");
    log(JSON.stringify(evaluateEnvelopeLock(expiredLock, self)));

    log("▶ No lock:");
    log(JSON.stringify(evaluateEnvelopeLock(null, self)));

    log("✅ Step 2B.1 PASSED");
}

async function testStep2B_2() {
    console.clear();
    log("🧪 Step 2B.2 — Lock acquisition");

    const identity = await loadIdentity();

    const self = {
        account: userEmail,
        deviceId: identity.deviceId
    };

    // First device acquires lock
    const result1 = await attemptEnvelopeLock({
        envelopeName: "envelope.json",
        self,
        readLockFromDrive: mockReadLock,
        writeLockToDrive: mockWriteLock
    });

    log("▶ First attempt:");
    log(JSON.stringify(result1));

    // Second device tries to acquire
    const other = {
        account: "other@gmail.com",
        deviceId: "other-device"
    };

    const result2 = await attemptEnvelopeLock({
        envelopeName: "envelope.json",
        self: other,
        readLockFromDrive: mockReadLock,
        writeLockToDrive: mockWriteLock
    });

    log("▶ Second attempt:");
    log(JSON.stringify(result2));

    log("Final lock:");
    log(JSON.stringify(mockDrive.lock));

    log("✅ Step 2B.2 PASSED");
}

async function testStep2B_3() {
    console.clear();
    log("🧪 Step 2B.3 — Lock heartbeat");

    const identity = await loadIdentity();

    const self = {
        account: userEmail,
        deviceId: identity.deviceId
    };

    // Seed lock (as if acquired)
    mockDrive.lock = createLockPayload(self, "envelope.json");

    const originalExpiry = mockDrive.lock.expiresAt;
    log("Initial expiresAt:" + originalExpiry);

    const hb = startLockHeartbeat({
        envelopeName: "envelope.json",
        self,
        ttlMs: 30000,
        heartbeatMs: 1000,
        readLockFromDrive: mockReadLock,
        writeLockToDrive: mockWriteLock,
        onLost: (info) => log("❌ Lost lock:", info)
    });

    // Let heartbeat run twice
    await new Promise(r => setTimeout(r, 2500));

    hb.stop();

    log("Extended expiresAt:" + mockDrive.lock.expiresAt);

    if (!originalExpiry || !mockDrive.lock.expiresAt) {
        throw new Error("expiresAt missing — heartbeat invalid");
    }

    if (Date.parse(mockDrive.lock.expiresAt) <= Date.parse(originalExpiry)) {
        throw new Error("Heartbeat did not extend lock");
    }

    const delta = Date.parse(mockDrive.lock.expiresAt) - Date.parse(originalExpiry);

    log("TTL extended by (ms): " + delta);

    log("✅ Step 2B.3 PASSED");
}

async function testStep2B_4() {
    log("🧪 Step 2B.4 — Explicit lock release");

    await acquireDriveWriteLock("envelope.json");

    if (!driveLockState.held) {
        throw new Error("Lock was not acquired");
    }

    await releaseDriveLock();

    if (driveLockState.held) {
        throw new Error("Lock still marked as held after release");
    }

    log("✅ Step 2B.4 PASSED — lock released cleanly");
}

async function testStep2C_2() {
    console.clear();
    log("🧪 Step 2C.2 — Lock-bound write API");

    const envelopeName = "envelope.json";
    const identity = await loadIdentity();

    // Fake envelope
    const envelope = {
        version: "1.0",
        generation: 3,
        payload: {}
    };

    // Fake lock (fresh)
    const lockState = {
        lock: {
            generation: 3,
            owner: { deviceId: identity.deviceId }
        }
    };

    // SHOULD SUCCEED
    await writeEnvelopeWithLock({
        envelopeName,
        envelope,
        lockState,
        writeFn: async (env) => {
            env.payload.test = "ok";
        }
    });

    if (envelope.generation !== 4) {
        throw new Error("Generation not incremented");
    }

    log("✅ Valid write passed");

    // STALE LOCK
    const staleLockState = {
        lock: {
            generation: 2,
            owner: { deviceId: identity.deviceId }
        }
    };

    let failed = false;
    try {
        await writeEnvelopeWithLock({
            envelopeName,
            envelope,
            lockState: staleLockState,
            writeFn: async () => {}
        });
    } catch {
        failed = true;
    }

    if (!failed) {
        throw new Error("Stale write should have failed");
    }

    log("✅ Stale write correctly rejected");
    log("🎉 Step 2C.2 PASSED");
}


// IMPORTANT - DO NOT DELETE
window.onload = initGIS;