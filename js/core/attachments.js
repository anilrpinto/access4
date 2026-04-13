import { C, G, CR, GD, SV, log, trace, debug, info, warn, error } from '@/shared/exports.js';

/**
 * Handles the encryption and Drive upload of an attachment.
 * Returns the metadata object to be stored in the Vault JSON.
 * @param {string} folderName - The bname of the destination folder.
 * @param {string} name - The display name/label for the file.
 * @param {Uint8Array} binary - The raw file bytes.
 * @param {string} mimeType - The original mime type (for metadata).
 */
export async function saveAttachment(folderName = C.ATTACHMENTS_FOLDER_NAME, name, binary, mimeType) {
    log("AT.saveAttachment", `Processing: ${name}`);

    const fileUuid = CR.generateUUID();
    const encryptedBytes = await _encryptAttachment(binary, fileUuid);

    // 1. Get the folder ID (this should be cached in G.attachmentsFolderId eventually)
    const folderId = await GD.findOrCreateFolder(folderName, C.ACCESS4_ROOT_ID);

    // --- TEMP DEV LOGIC ---
    const driveName = _getDevDriveName(name);    //`${fileUuid}.bin`

    // 2. Use the new wrapper
    const driveFileId = await GD.upsertBinaryFile({
        name: driveName,/*`${fileUuid}.bin`,*/
        parentId: folderId,
        content: encryptedBytes,
        mimeType: "application/octet-stream"
    });

    // 3. Construct the Vault Entry
    // 'val' is now explicitly the driveFileId for direct access
    return {
        key: name,
        type: "file",
        val: driveFileId,
        uuid: fileUuid,
        oid: G.userId,
        meta: {
            size: binary.length,
            mime: mimeType,
            updated: new Date().toISOString(),
            uploadedBy: G.userEmail
        }
    };
}

/**
 * High-level coordinator to fetch and decrypt an attachment.
 * @param {Object} attachment - The attachment entry from the Vault JSON.
 * @returns {Uint8Array} - The decrypted file bytes.
 */
export async function openAttachment(attachment) {
    log("AT.openAttachment", `Fetching and decrypting: ${attachment.key}`);

    // 1. Fetch encrypted bytes via Drive (using your existing GD helper)
    // Note: ensure GD is imported at the top of server.js
    const buffer = await GD.readBinaryByFileId(attachment.val);
    const encryptedCombined = new Uint8Array(buffer);

    // 2. Perform the Decryption
    // This calls your _decryptAttachment logic (getting CEK, deriving FEK, splitting IV)
    return await _decryptAttachment(encryptedCombined, attachment.uuid);
}

/**
 * Universal file removal: Tries permanent delete, falls back to trash.
 * Returns true if the file is gone or the attempt was made.
 */
export async function deleteAttachmentFile(fileId) {
    if (!fileId) return true;

    try {
        log("AT.deleteAttachmentFile", `Primary: Attempting DELETE for ${fileId}`);
        await GD.deleteFileById(fileId);
        return true;

    } catch (err) {
        // 1. EXTRACT THE CODE (Google often buries it in err.message or err.body)
        const errMsg = err.message || "";
        const statusCode = err.status || (errMsg.includes("403") ? 403 : errMsg.includes("405") ? 405 : 0);

        // 2. CHECK FOR PERMISSION/METHOD ERRORS
        if (statusCode === 403 || statusCode === 405 || errMsg.toLowerCase().includes("permission")) {
            warn("AT.deleteAttachmentFile", `DELETE blocked (${statusCode}). Trying Trash fallback...`);

            try {
                await GD.trashFileById(fileId);
                return true;
            } catch (trashErr) {
                // If even Trash fails, we've done our best.
                warn("AT.deleteAttachmentFile", `Ownership wall for ${fileId}. Skipping physical delete.`);
                return false; // This 'false' tells doSaveClick it was a handled skip
            }
        }

        // 3. IF 404, IT'S ALREADY GONE
        if (statusCode === 404 || errMsg.includes("404")) return true;

        // 4. REAL SYSTEM ERROR (Network down, Auth expired, etc)
        throw err;
    }
}

/** INTERNAL FUNCTIONS **/

/**
 * Encrypts a binary blob (Uint8Array) for Drive storage.
 */
async function _encryptAttachment(binaryData, fileUuid) {
    log("AT._encryptAttachment", "called");

    // Get the CEK (Borrowing your existing unwrap logic)
    const cek = await SV.getTransientCEK();

    // Derive the unique key for this specific UUID
    const fek = await _deriveFileKey(cek, fileUuid);

    // Use existing CR.encrypt (it returns {iv, data} in B64)
    // NOTE: For large binaries, we convert to a flat Uint8Array for Drive efficiency
    const encrypted = await CR.encrypt(binaryData, fek);

    const ivBuf = CR.b64ToBuf(encrypted.iv);
    const dataBuf = CR.b64ToBuf(encrypted.data);

    // Combine into a single binary packet: [IV (12 bytes)][Ciphertext]
    const combined = new Uint8Array(ivBuf.length + dataBuf.length);
    combined.set(ivBuf, 0);
    combined.set(dataBuf, ivBuf.length);

    return combined;
}

/**
 * Decrypts a binary blob from Drive.
 */
async function _decryptAttachment(combinedBuffer, fileUuid) {
    log("AT._decryptAttachment", "called");

    const cek = await SV.getTransientCEK();
    const fek = await _deriveFileKey(cek, fileUuid);

    const iv = combinedBuffer.slice(0, 12);
    const data = combinedBuffer.slice(12);

    // Reconstruct the format CR.decrypt expects
    const enc = {
        iv: CR.bufToB64(iv),
        data: CR.bufToB64(data)
    };

    return CR.decrypt(enc, fek);
}

/**
 * Derives a unique AES-GCM key for a specific file using the Vault CEK.
 */
async function _deriveFileKey(cek, fileUuid) {
    log("AT._deriveFileKey", `Deriving key for ${fileUuid}`);

    // We pass the CEK, a versioned salt, and the unique UUID.
    // normalizeBytes in CR handles the string-to-buffer conversion for us.
    return CR.deriveSubKey(cek, C.ATTACHMENT_FILEKEY_SALT, fileUuid);
}

/**
 * TEMPORARY DEV HELPER:
 * Creates a readable name for Google Drive to assist in testing.
 * REVERT THIS BEFORE PRODUCTION.
 */
function _getDevDriveName(originalName) {
    const timestamp = new Date().toLocaleTimeString().replace(/:/g, '-');
    // We keep the original name but append 'DEV' and a time to avoid collisions
    return `DEV_${timestamp}_${originalName}.enc`;
}
