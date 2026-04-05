import { C, G, CR, GD, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { showOverlayAlertUI, showOverlayPasswordUI } from '@/ui/modal.js';
import { vaultCreatePrivateUI  } from '@/ui/loader.js';
import { showSilentToast } from '@/ui/uihelper.js';

let onGenesisSuccess = null;

let privateFileName = null;
let privateFileId = null
let privateKey = null;

async function load() {
    log("vaultCreatePrivateUI.load", "called");

    vaultCreatePrivateUI.createBtn.onClick(doCreateVaultClick);
    vaultCreatePrivateUI.cancelBtn.onClick(() => window.ScreenManager.goHome());

    showCreateVaultStatusMessage("Use a strong password to create your personal vault and remember it!", "status-message");
}

async function unload() {
    log("vaultCreatePrivateUI.unload", "called");
    showCreateVaultStatusMessage("");
}

function showCreateVaultStatusMessage(msg, type = "error") {
    if (!vaultCreatePrivateUI.statusMsg) return;

    vaultCreatePrivateUI.statusMsg.textContent = msg;
    vaultCreatePrivateUI.statusMsg.className = `status-message ${type}`;
}

async function doCreateVaultClick() {
    log("vaultCreatePrivateUI.doCreateVaultClick", "called");

    try {

        const pwd = vaultCreatePrivateUI.pwdInput.value;
        const confirm = vaultCreatePrivateUI.confirmPwdInput.value;

        if (!pwd || pwd.length < C.PASSWORD_MIN_LEN) {
            throw new Error("Recovery password must be at least 7 characters.");
        }
        if (pwd !== confirm) {
            throw new Error("Passwords do not match.");
        }

        const result = await setupPrivateVault(G.userEmail, pwd);

        if (onGenesisSuccess) {
            await onGenesisSuccess(result);
        }

        window.ScreenManager.goHome();
    } catch (err) {
        showCreateVaultStatusMessage(err.message);
    }
}

/**
 * INITIALIZES A NEW PRIVATE VAULT
 * 1. Generates File Salt
 * 2. Encrypts Blank Vault
 * 3. Uploads to GDrive
 * 4. Wraps Pointer
 * 5. Updates Main Envelope
 */
async function setupPrivateVault(userEmail, privatePassword) {

    // 1. Generate the "Real" Salt for the actual file
    const fileSalt = CR.bufToB64(CR.randomBytes(32));

    // 2. Create the Genesis Private JSON (Standard Vault Structure)
    const genesisData = {
        meta: { version: "1.0", lastModified: new Date().toISOString(), type: "private" },
        groups: [{ id: "g-" + CR.generateUUID(), name: "Private Genesis", items: [] }]
    };

    // 3. Encrypt the Private File using high iterations
    privateKey = await CR.deriveKey(privatePassword, {
        salt: fileSalt,
        iterations: 600000
    });

    // Encrypt returns {iv, data} - we stringify this to store as the file content
    const encryptedObj = await CR.encrypt(JSON.stringify(genesisData), privateKey);

    const parentId = await GD.findOrCreateFolder(C.PRIVATE_VAULT_FOLDER_NAME, C.ACCESS4_ROOT_ID)

    const emailHash = await CR.hashString(userEmail);
    privateFileName = `a4_pvt_${emailHash.substring(0,8)}.dat`;

    // 4. Upload to Google Drive
    privateFileId = await GD.upsertBinaryFile({
        name: privateFileName,
        parentId: parentId,
        content: JSON.stringify(encryptedObj),
        mimeType: "application/octet-stream"
    });

    // 5. Wrap the Pointer for the Shared Vault
    const pointerData = { fileId: privateFileId, salt: fileSalt, iterations: 600000 };
    const encryptedPointer = await wrapPointer(pointerData, privatePassword, emailHash);

    // RETURN EVERYTHING vault.js needs to take over
    return {
        pointer: encryptedPointer, // To save in the Main Envelope
        data: genesisData         // To show in the UI immediately
    };
}

/**
 * WRAPS THE POINTER (Metadata)
 * Encrypts the { fileId, salt, iterations } into a single Base64 string.
 */
export async function wrapPointer(metadataObj, password, emailHash) {
    // 1. Derive the "Pointer Key" using the Email Hash as a deterministic salt
    const pointerKey = await CR.deriveKey(password, {
        salt: CR.bufToB64(emailHash), // Uses email hash to anchor the pointer
        iterations: 100000 // Standard iterations for the pointer layer
    });

    // 2. Encrypt the metadata object
    const jsonString = JSON.stringify(metadataObj);
    const encrypted = await CR.encrypt(jsonString, pointerKey);

    // 3. Combine IV and Data into a single string for storage
    // Format: "iv.data" (Simple and standard for your app)
    return `${encrypted.iv}.${encrypted.data}`;
}

/**
 * UNWRAPS THE POINTER
 * Returns the object: { fileId, salt, iterations }
 */
export async function unwrapPointer(pointerBlob, password, emailHash) {
    try {
        // 1. Split the "iv.data" format
        const [iv, data] = pointerBlob.split('.');

        // 2. Re-derive the same Pointer Key
        const pointerKey = await CR.deriveKey(password, {
            salt: CR.bufToB64(emailHash),
            iterations: 100000
        });

        // 3. Decrypt using your CR.decrypt helper
        const decryptedBuf = await CR.decrypt({ iv, data }, pointerKey);

        // 4. Parse back to JSON
        const jsonString = new TextDecoder().decode(decryptedBuf);
        return JSON.parse(jsonString);
    } catch (err) {
        // Error logging is handled inside your CR module,
        // but we catch here to return null for "Wrong Password"
        return null;
    }
}

/**
 * EXPORTED FUNCTIONS
 */
export async function showCreatePrivateVaultUI(onSuccess = () => alert('Private vault created')) {

    if (onSuccess)
        onGenesisSuccess = onSuccess;

    const screenKey = window.ScreenManager.CREATE_PRIVATE_VAULT_SCREENKEY;
    window.ScreenManager.register(screenKey, vaultCreatePrivateUI.mainSection, {
        onShow: load,
        onHide: unload
    });

    window.ScreenManager.switchView(screenKey);
}

export async function promptPrivateVaultPassword(pointer, emailHash, onSuccess = (pwd, data) => alert('Unlocked')) {

    // --- SESSION CHECK ---
    // If we already have the key and ID, the vault is "Open" in the background.
    // We can skip the password prompt entirely for this session.
    if (privateKey && privateFileId) {
        log("privateVault.prompt", "Session active. Skipping password prompt.");

        // We still need to provide the data to the UI, but we don't need
        // to re-fetch/re-decrypt if vault.js is already holding privateVaultData.
        // If vault.js lost the data but we kept the key, we'd re-fetch here:
        if (onSuccess) onSuccess(null); // Passing null implies "use existing memory" or trigger a specific refresh
        return;
    }

    const pwd = await showOverlayPasswordUI({
        title: "Unlock Private Vault",
        message: "Enter your private password to decrypt this vault.",
        okText: "Unlock"
    });

    if (!pwd) return;

    try {
        showSilentToast("Decrypting...");

        // 1. Unwrap the pointer to get the File ID and Salt
        // (Uses the logic we discussed to derive the key and decrypt the pointer)
        const decryptedPointer = await unwrapPointer(pointer, pwd, emailHash);
        privateFileId = decryptedPointer.fileId;
        privateFileName = `a4_pvt_${emailHash.substring(0,8)}.dat`;

        // 2. Fetch and Decrypt the actual .dat file from Drive
        const { json: encryptedContent } = await GD.readJsonByFileId(privateFileId);

        privateKey = await CR.deriveKey(pwd, {
            salt: decryptedPointer.salt,
            iterations: decryptedPointer.iterations
        });

        const decryptedRaw = await CR.decrypt(encryptedContent, privateKey);

        if (onSuccess)
            onSuccess(pwd, JSON.parse(new TextDecoder().decode(decryptedRaw)));

    } catch (err) {
        privateKey = null;
        error("Unlock failed", err);
        showOverlayAlertUI({ title: "Unlock Failed", message: "Incorrect password or corrupted vault data." });
    }
}

export async function savePrivateVaultData(data) {
    if (!privateKey || !privateFileId) {
        throw new Error("Private vault context lost. Please re-unlock.");
    }

    log("savePrivateVaultData", `Uploading to file: ${privateFileId}`);

    const encryptedObj = await CR.encrypt(JSON.stringify(data), privateKey);

    await GD.upsertBinaryFile({
        name: privateFileName,
        fileId: privateFileId,
        content: JSON.stringify(encryptedObj),
        mimeType: "application/octet-stream"
    });
}

/**
 * SECURITY: Wipes the sensitive session state from memory.
 * Call this when the user closes the private vault or logs out.
 */
export function lockPrivateVault() {
    log("privateVault.lock", "Wiping private session state...");
    privateKey = null;
    privateFileId = null;
    privateFileName = null;
}

export function isPrivateVaultUnlocked() {
    return !!privateKey;
}