import { C, G, ID, log, trace, debug, info, warn, error } from './exports.js';

const DB_VERSION = 1;

function bioScopeKey(type) {
    return `access4.bio::${type}::${G.userEmail}::${ID.getDeviceId()}`;
}

async function openDB({ write = false } = {}) {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(C.BIO_DB_NAME);

        req.onerror = (e) => reject(e.target.error);

        req.onsuccess = async (e) => {
            const db = e.target.result;

            const hasStore = db.objectStoreNames.contains(C.BIO_STORE);

            // ✅ Store exists → done
            if (hasStore) {
                resolve(db);
                return;
            }

            // ❌ Store missing + read mode → treat as empty
            if (!write) {
                db.close();
                resolve(null);
                return;
            }

            // 🔥 Store missing + write mode → upgrade DB
            const newVersion = db.version + 1;
            db.close();

            const upgradeReq = indexedDB.open(C.BIO_DB_NAME, newVersion);

            upgradeReq.onupgradeneeded = (ev) => {
                const upgradedDB = ev.target.result;
                if (!upgradedDB.objectStoreNames.contains(C.BIO_STORE)) {
                    upgradedDB.createObjectStore(C.BIO_STORE);
                }
            };

            upgradeReq.onsuccess = (ev) => resolve(ev.target.result);
            upgradeReq.onerror = (ev) => reject(ev.target.error);
        };
    });
}

async function storePWK(keyId, cryptoKey) {
    log("BM.storePWK", "called");

    const db = await openDB({ write: true });

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readwrite");
        tx.objectStore(C.BIO_STORE).put(cryptoKey, keyId);

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

async function saveBiometricRecord(record) {
    log("BM.saveBiometricRecord", "called");

    const db = await openDB({ write: true });

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readwrite");
        tx.objectStore(C.BIO_STORE).put(record, bioScopeKey("record"));

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

async function loadBiometricRecordFromIndexedDB() {
    log("BM.loadBiometricRecordFromIndexedDB", "called");

    const db = await openDB({ write: false });
    if (!db) return null;

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readonly");
        const req = tx.objectStore(C.BIO_STORE).get(bioScopeKey("record"));

        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
    });
}

async function loadPWK(keyId) {
    log("BM.loadPWK", "called");
    const db = await openDB({ write: false });
    if (!db) return null;

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readonly");
        const req = tx.objectStore(C.BIO_STORE).get(keyId);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
    });
}

/**
 * EXPORTED FUNCTIONS
 */
export async function isBiometricRegistered() {
    log("BM.isBiometricRegistered", "called");
    const record = await loadBiometricRecordFromIndexedDB();
    return !!record;
}

export async function enrollBiometric(password) {
    log("BM.enrollBiometric", "called");

    if (!window.PublicKeyCredential) return;

    // 1️⃣ Create WebAuthn credential
    const cred = await navigator.credentials.create({
        publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: { name: "Access4", id: window.location.hostname },
            user: {
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: G.userEmail,
                displayName: G.userEmail
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: { userVerification: "required" },
            timeout: 60000
        }
    });

    const credentialId = btoa(String.fromCharCode(...new Uint8Array(cred.rawId)));

    // 2️⃣ Generate PWK (non-extractable)
    const pwk = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    // 3️⃣ Encrypt password using PWK
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedPwd = new TextEncoder().encode(password);

    const cipher = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        pwk,
        encodedPwd
    );

    // 4️⃣ Store biometric record in IndexedDB
    await saveBiometricRecord({
        credentialId,
        wrappedPassword: btoa(String.fromCharCode(...new Uint8Array(cipher))),
        iv: btoa(String.fromCharCode(...iv)),
        created: Date.now()
    });

    // 5️⃣ Store PWK in IndexedDB
    await storePWK(bioScopeKey("pwk"), pwk);
    log("BM.enrollBiometric", "Biometric shortcut securely enrolled");
}

export async function attemptBiometricUnlock(callback) {
    log("BM.attemptBiometricUnlock", "called");

    if (!window.PublicKeyCredential) {
        warn("BM.attemptBiometricUnlock", "Biometric not supported");
        return;
    }

    const record = await loadBiometricRecordFromIndexedDB();
    if (!record) {
        warn("BM.attemptBiometricUnlock", "No biometric record found");
        return;
    }

    const { credentialId, wrappedPassword, iv } = record;

    try {
        log("BM.attemptBiometricUnlock", "Triggering biometric prompt...");
        // 1️⃣ Trigger biometric assertion
        await navigator.credentials.get({
            publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                allowCredentials: [{
                    type: "public-key",
                    id: Uint8Array.from(atob(credentialId), c => c.charCodeAt(0))
                }],
                userVerification: "required"
            }
        });

        // 2️⃣ Load PWK from IndexedDB
        const pwk = await loadPWK(bioScopeKey("pwk"));
        if (!pwk) throw new Error("PWK not found");

        // 3️⃣ Decrypt password
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0)) },
            pwk,
            Uint8Array.from(atob(wrappedPassword), c => c.charCodeAt(0))
        );

        const password = new TextDecoder().decode(decrypted);

        log("BM.attemptBiometricUnlock", "Password decrypted via biometric, proceeding with implicit unlock");

        if (callback)
        await callback(password);

    } catch (err) {
        warn("BM.attemptBiometricUnlock", "Biometric unlock failed:", err.message);
    }
}

export async function debugBiometricDB() {
    trace("BM.debugBiometricDB", "----- BIOMETRIC DB DEBUG -----");

    // 1️⃣ Check if database exists
    const dbList = await indexedDB.databases?.();
    const dbMeta = dbList?.find(db => db.name === C.BIO_DB_NAME);

    if (!dbMeta) {
        log("BM.debugBiometricDB", "DB does not exist.");
        log("BM.debugBiometricDB", "------------------------------");
        return;
    }

    log("BM.debugBiometricDB", "DB exists.");
    log("BM.debugBiometricDB", "Version:", dbMeta.version);

    // 2️⃣ Open DB safely (read-only mode, no creation)
    const db = await openDB({ write: false });

    if (!db) {
        log("BM.debugBiometricDB", "Store missing.");
        log("BM.debugBiometricDB", "------------------------------");
        return;
    }

    log("BM.debugBiometricDB", "Object stores:", [...db.objectStoreNames]);

    if (!db.objectStoreNames.contains(C.BIO_STORE)) {
        log("BM.debugBiometricDB", "BIO_STORE does NOT exist.");
        log("BM.debugBiometricDB", "------------------------------");
        return;
    }

    // 3️⃣ Dump contents
    await new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readonly");
        const store = tx.objectStore(C.BIO_STORE);
        const req = store.getAll();

        req.onsuccess = () => {
            log("BM.debugBiometricDB", "Records:", req.result);
            resolve();
        };

        req.onerror = () => reject(req.error);
    });

    log("BM.debugBiometricDB", "------------------------------");
}

export async function clearBiometricIndexedDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase(C.BIO_DB_NAME);

        request.onsuccess = () => {
            log("clearBiometricIndexedDB", `Biometric IndexedDB '${C.BIO_DB_NAME}' deleted successfully`);
            resolve(true);
        };

        request.onerror = (event) => {
            error("clearBiometricIndexedDB", "Error deleting IndexedDB:", event);
            reject(event);
        };

        request.onblocked = () => {
            warn("clearBiometricIndexedDB", `Delete blocked — close all tabs using '${C.BIO_DB_NAME}'`);
        };
    });
}
