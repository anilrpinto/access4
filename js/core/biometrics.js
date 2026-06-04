import { C, G, CR, LS, log, trace, debug, info, warn, error } from '@/shared/exports.js';

/**
 * Checks if a biometric record exists for a specific vault boundary.
 * @param {'shared'|'private'} vaultType
 */
export async function isBiometricRegistered(vaultType = "shared") {
    log("BM.isBiometricRegistered", `called for ${vaultType}`);
    const record = await _loadBiometricRecordFromIndexedDB(vaultType);
    return !!record;
}

/**
 * Enrolls a vault password under hardware-bound biometric protections.
 * @param {string} password - Plaintext password payload to wrap
 * @param {'shared'|'private'} vaultType - Targeted context
 */
export async function enrollBiometric(password, vaultType = "shared") {
    log("BM.enrollBiometric", `called for context: ${vaultType}`);

    if (!window.PublicKeyCredential) return;

    const cred = await navigator.credentials.create({
        publicKey: {
            challenge: CR.randomBytes(32),
            rp: { name: "Access4", id: window.location.hostname },
            user: {
                id: CR.randomBytes(16),
                name: `${G.userEmail}_${vaultType}`,
                displayName: `${G.userEmail} (${vaultType === 'shared' ? 'Shared' : 'Private'} Vault)`
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: { userVerification: "required" },
            timeout: 60000
        }
    });

    const credentialId = CR.bufToB64(cred.rawId);
    const pwk = await CR.generateAESKey(false);
    const encResult = await CR.encrypt(password, pwk);

    await _saveData(
        { credentialId, wrappedPassword: encResult.data, iv: encResult.iv, created: Date.now() },
        _bioScopeKey("record", vaultType)
    );

    await _saveData(pwk, _bioScopeKey("pwk", vaultType));
    log("BM.enrollBiometric", `Biometric shortcut successfully enrolled for ${vaultType}`);
}

/**
 * Attempts biometric hardware collection to surface a wrapped vault keying asset.
 * @param {'shared'|'private'} vaultType
 * @param {Function} callback - Success execution hook receiving decrypted plaintext
 */
export async function attemptBiometricUnlock(vaultType = "shared", callback) {
    log("BM.attemptBiometricUnlock", `called for context: ${vaultType}`);

    if (!window.PublicKeyCredential) return;

    const record = await _loadBiometricRecordFromIndexedDB(vaultType);
    if (!record) {
        warn("BM.attemptBiometricUnlock", `No biometric record found for context: ${vaultType}`);
        return;
    }

    const { credentialId, wrappedPassword, iv } = record;

    try {
        log("BM.attemptBiometricUnlock", `Triggering hardware assertion for ${vaultType}...`);
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

        const pwk = await _loadPWK(_bioScopeKey("pwk", vaultType));
        if (!pwk) throw new Error("PWK cryptographic asset missing from storage.");

        const decryptedBuffer = await CR.decrypt({ iv: iv, data: wrappedPassword }, pwk);
        const password = CR.decodeBuf(decryptedBuffer);

        log("BM.attemptBiometricUnlock", `Password parsed successfully for ${vaultType}. running handler...`);
        if (callback) await callback(password);

    } catch (err) {
        warn("BM.attemptBiometricUnlock", `Biometric validation rejected for ${vaultType}:`, err.message);
    }
}

/**
 * Evicts biometric tracking metrics for an explicit vault context (e.g., when password rolls)
 */
export async function evictBiometricRecord(vaultType = "shared") {
    log("BM.evictBiometricRecord", `Evicting biometric data arrays for ${vaultType}`);
    const db = await _openDB({ write: true });
    if (!db) return;

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readwrite");
        const store = tx.objectStore(C.BIO_STORE);

        store.delete(_bioScopeKey("record", vaultType));
        store.delete(_bioScopeKey("pwk", vaultType));

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
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

/**
 * Scopes internal IndexedDB keys uniquely by vault context type.
 * 'shared' preserves backward compatibility with your legacy key formats.
 */
function _bioScopeKey(type, vaultType = "shared") {
    const suffix = vaultType === "shared" ? type : `${vaultType}::${type}`;
    return `${LS.getKeyPrefix()}bio::${suffix}`;
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

async function _loadBiometricRecordFromIndexedDB(vaultType = "shared") {
    const db = await _openDB({ write: false });
    if (!db) return null;

    return new Promise((resolve, reject) => {
        const tx = db.transaction(C.BIO_STORE, "readonly");
        const req = tx.objectStore(C.BIO_STORE).get(_bioScopeKey("record", vaultType));
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
