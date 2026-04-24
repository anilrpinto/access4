import { C, G, CR, LS, log, trace, debug, info, warn, error } from '@/shared/exports.js';

export async function isBiometricRegistered() {
    log("BM.isBiometricRegistered", "called");
    const record = await _loadBiometricRecordFromIndexedDB();
    return !!record;
}

export async function enrollBiometric(password) {
    log("BM.enrollBiometric", "called");

    if (!window.PublicKeyCredential) return;

    // Create WebAuthn credential
    const cred = await navigator.credentials.create({
        publicKey: {
            challenge: CR.randomBytes(32),
            rp: { name: "Access4", id: window.location.hostname },
            user: {
                id: CR.randomBytes(16),
                name: G.userEmail,
                displayName: G.userEmail
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: { userVerification: "required" },
            timeout: 60000
        }
    });

    const credentialId = CR.bufToB64(cred.rawId);

    // Generate PWK (non-extractable)
    const pwk = await CR.generateAESKey(false);

    // Encrypt password using PWK
    const encResult = await CR.encrypt(password, pwk);

    // Store biometric record in IndexedDB
    await _saveBiometricRecord({ credentialId, wrappedPassword: encResult.data, iv: encResult.iv, created: Date.now() });

    // Store PWK in IndexedDB
    await _storePWK(pwk);
    log("BM.enrollBiometric", "Biometric shortcut securely enrolled");
}

export async function attemptBiometricUnlock(callback) {
    log("BM.attemptBiometricUnlock", "called");

    if (!window.PublicKeyCredential) {
        warn("BM.attemptBiometricUnlock", "Biometric not supported");
        return;
    }

    const record = await _loadBiometricRecordFromIndexedDB();
    if (!record) {
        warn("BM.attemptBiometricUnlock", "No biometric record found");
        return;
    }

    const { credentialId, wrappedPassword, iv } = record;

    try {
        log("BM.attemptBiometricUnlock", "Triggering biometric prompt...");
        // Trigger biometric assertion
        await navigator.credentials.get({
            publicKey: {
                challenge: CR.randomBytes(32),
                allowCredentials: [{
                    type: "public-key",
                    id: CR.b64ToBuf(credentialId)
                }],
                userVerification: "required"
            }
        });

        // Load PWK from IndexedDB
        const pwk = await _loadPWK(_bioScopeKey("pwk"));
        if (!pwk) throw new Error("PWK not found");

        // Decrypt password
        const decryptedBuffer = await CR.decrypt({ iv: iv, data: wrappedPassword }, pwk);
        const password = CR.decodeBuf(decryptedBuffer);

        log("BM.attemptBiometricUnlock", "Password decrypted via biometric, proceeding with implicit unlock");

        if (callback) await callback(password);

    } catch (err) {
        warn("BM.attemptBiometricUnlock", "Biometric unlock failed:", err.message);
    }
}

export async function debugBiometricDB() {
    log("BM.debugBiometricDB", "----- BIOMETRIC DB DEBUG -----");

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
    const db = await _openDB({ write: false });

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

/** INTERNAL FUNCTIONS **/

function _bioScopeKey(type) {
    return `${LS.getKeyPrefix()}bio::${type}`;
}

async function _openDB({ write = false } = {}) {
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

async function _storePWK(cryptoKey) {
    return _saveData(cryptoKey, _bioScopeKey("pwk"));
}

async function _saveBiometricRecord(record) {
    return _saveData(record, _bioScopeKey("record"));
}

async function _saveData(data, key) {
    log("BM._saveData", `called with key "${key}"`);

    const db = await _openDB({ write: true });

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readwrite");
        tx.objectStore(C.BIO_STORE).put(data, key);

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

async function _loadBiometricRecordFromIndexedDB() {
    log("BM._loadBiometricRecordFromIndexedDB", "called");

    const db = await _openDB({ write: false });
    if (!db) return null;

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readonly");
        const req = tx.objectStore(C.BIO_STORE).get(_bioScopeKey("record"));

        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
    });
}

async function _loadPWK(keyId) {
    log("BM._loadPWK", "called");
    const db = await _openDB({ write: false });
    if (!db) return null;

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readonly");
        const req = tx.objectStore(C.BIO_STORE).get(keyId);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
    });
}
