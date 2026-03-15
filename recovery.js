import { C, G, CR, E, GD, log, trace, debug, info, warn, error } from './exports.js';

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

/**
 * Load the recovery.private.json blob from the shared "recovery" folder
 * on Google Drive.
 *
 * @returns {Promise<Object>} Parsed JSON of recovery private key
 */
// referenced internally in decryptRecoveryPassword and unlockRecoveryIdentity
async function loadRecoveryPrivateBlob() {
    log("R.loadRecoveryPrivateBlob", "called");

    const recoveryFolderId = await ensureRecoveryFolder();

    const result = await GD.readJsonByName(C.RECOVERY_KEY_PRIVATE_FILE, recoveryFolderId);

    if (!result)
    throw new Error(`${C.RECOVERY_KEY_PRIVATE_FILE} not found`);

    return result.json;
}

/**
 * Returns the decrypted private key bytes if the recovery password is correct.
 * Returns null if password is invalid or recovery key is missing/corrupted.
 */
// referenced internally in [verifyRecoveryPassword, handleRecovery]
async function decryptRecoveryPassword(pwd) {
    log("R.decryptRecoveryPassword", "called");

    try {
        // Load encrypted recovery private key
        const recoveryBlob = await loadRecoveryPrivateBlob();
        if (!recoveryBlob) return null;

        // Derive key
        const recoveryKey = await CR.deriveKey(pwd, recoveryBlob.kdf);

        // Attempt decrypt
        const decryptedPrivateKeyBytes = await CR.decrypt(recoveryBlob.encryptedPrivateKey, recoveryKey);

        // Success
        return decryptedPrivateKeyBytes;
    } catch (err) {
        log("R.verifyRecoveryPassword", "failed:", err?.message || err?.name || err);
        return null;
    }
}

/**
 * EXPORTED FUNCTIONS
 */

// Referenced in loader.js AND internally by loadRecoveryPrivateBlob and [hasRecoveryKeyOnDrive]
export async function ensureRecoveryFolder() {
    return GD.findOrCreateFolder(C.RECOVERY_FOLDER_NAME, C.ACCESS4_ROOT_ID);
}

// Only referenced by loader.js
export async function verifyRecoveryPassword(pwd) {
    return !!(await decryptRecoveryPassword(pwd));
}

// Only referenced by loader.js
export async function handleRecovery(pwd, onCEKSuccessCb) {

    log("R.handleRecovery", "called");

    // 1️⃣ Verify password and get decrypted key
    const recoveryPrivateKeyBytes = await decryptRecoveryPassword(pwd);
    if (!recoveryPrivateKeyBytes) throw new Error("Incorrect recovery password or corrupted recovery key");

    // Import decrypted private key into crypto subtle
    const recoveryPrivateKey = await CR.importRSAPrivateKey(recoveryPrivateKeyBytes, ["unwrapKey"]);

    log("R.handleRecovery", "Recovery private key decrypted");

    // 4️⃣ Load vault envelope (grab CEK)
    const envelopeFile = await E.readEnvelopeFromDrive(C.ENVELOPE_NAME);
    if (!envelopeFile) throw new Error("Vault envelope not found");

    const envelope = envelopeFile.json;
    log("R.handleRecovery", "Vault envelope loaded");

    // 5️⃣ Find the CEK wrapped for recovery identity
    const wrappedCEK = envelope.keys.find(k => k.role === "recovery")?.wrappedKey;
    if (!wrappedCEK) throw new Error("Vault CEK not wrapped for recovery");

    // 3️⃣ Attempt to unwrap CEK using recovery private key
    const cek = await CR.unwrapCEKWithPrivateKey(wrappedCEK, recoveryPrivateKey);

    if (!cek) throw new Error("CEK unwrap failed — invalid recovery password or vault corrupted");

    G.recoverySession = true;
    G.recoveryCEK = cek;

    log("R.handleRecovery", `Vault CEK unwrapped successfully - G.recoverySession: ${G.recoverySession}, G.recoveryCEK: ${G.recoveryCEK}`);

    if (onCEKSuccessCb)
        await onCEKSuccessCb();
}

// Only referenced by loader.js
export async function hasRecoveryKeyOnDrive() {
    log("R.hasRecoveryKeyOnDrive", "called");

    try {

        const recoveryFolderId = await ensureRecoveryFolder();

        const pub = await GD.findDriveFileByNameInFolder(
            C.RECOVERY_KEY_PUBLIC_FILE,
            recoveryFolderId
        );

        const priv = await GD.findDriveFileByNameInFolder(
            C.RECOVERY_KEY_PRIVATE_FILE,
            recoveryFolderId
        );

        const exists = !!(pub && priv);

        log("R.hasRecoveryKeyOnDrive", `recovery pair exists: ${exists}`);

        return exists;

    } catch (e) {
        error("R.hasRecoveryKeyOnDrive", `Recovery key check failed: ${e.message}`);
        throw e;
    }
}
