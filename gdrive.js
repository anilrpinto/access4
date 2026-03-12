import { C, G, U, log, trace, debug, info, warn, error } from './exports.js';

/**
 * IMPORTANT:
 * Drive has separate endpoints for metadata vs file content.
 * NEVER send JSON content to drive/v3/files.
 * Use upload/drive/v3/files for media writes.
 */

function _buildDriveListUrl(params = {}) {
    return buildDriveUrl("files", {
        ...params,
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
    });
}

/*
 * URL builder (media uploads) (KEEP)
 */
function _buildDriveUploadUrl(path, params = {}) {
    const qs = new URLSearchParams({
        supportsAllDrives: "true",
        includeItemsFromAllDrives: "true",
        ...params
    });
    return `https://www.googleapis.com/upload/drive/v3/${path}?${qs}`;
}

/*
 * URL builder (metadata & listing) (KEEP)
 */
function buildDriveUrl(path, params = {}) {
    params.supportsAllDrives = true;
    // Commented as only needed for LIST calls not GET
    //params.includeItemsFromAllDrives = true;
    return `https://www.googleapis.com/drive/v3/${path}?` +
    Object.entries(params).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
}

async function _driveFindFileByNameInFolder(name, folderId) {
    const q = [
        `name='${name.replace(/'/g, "\\'")}'`,
        `'${folderId}' in parents`,
        `trashed=false`
    ].join(" and ");

    const res = await _driveApiGet("files", { q, fields: "files(id,name,modifiedTime)" });

    return res.files?.[0] || null;
}

/*
 * GET wrapper (KEEP)
 */
async function _driveApiGet(path, params = {}) {
    return driveFetch(
        buildDriveUrl(path, params),
        { method: "GET" }
    );
}

/*
 * raw response (KEEP)
 */
async function _driveFetchRaw(url, options = {}) {
    options.headers ||= {};
    options.headers.Authorization = `Bearer ${G.accessToken}`;

    const res = await fetch(url, options);
    if (!res.ok) {
        const text = await res.text();
        throw new Error(text);
    }
    return res;
}

/*
 * JSON response (KEEP)
 */
async function driveFetch(url, options = {}) {
    options.headers ||= {};
    options.headers.Authorization = `Bearer ${G.accessToken}`;
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`Drive fetch failed: ${res.status} ${res.statusText}`);
    return res.json();
}


/**
 * EXPORTED FUNCTIONS
 */

// KEEP
export async function fetchUserEmail() {
    const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: {
            Authorization: `Bearer ${G.accessToken}`
        }
    });
    const data = await res.json();
    G.userEmail = data.email;

    log("GD.fetchUserEmail", "Signed in as xxx@gmail.com"); //+ G.userEmail);
}

// KEEP
export async function verifyWritable(folderId) {
    log("GD.verifyWritable", "called - Verifying Drive write access (probe)");
    await fetch(buildDriveUrl("files", {
        q: `'${folderId}' in parents`,
        pageSize: 1
    }), {
        headers: {
            Authorization: `Bearer ${G.accessToken}`
        }
    });
    log("GD.verifyWritable", "Drive access verified (read scope OK)");
}

// KEEP
export async function verifySharedRoot(root) {
    log("GD.verifySharedRoot", "called");
    await driveFetch(buildDriveUrl(`files/${root}`, {
        fields: "id"
    }));
}

/*
 * Convenience for root (KEEP) - rename to indicate ROOT files finder
 */
export async function findDriveFileByName(name) {
    return findDriveFileByNameInFolder(name, C.ACCESS4_ROOT_ID);
}

export async function findDriveFileByNameInFolder(name, folderId) {
    return _driveFindFileByNameInFolder(name, folderId);
}

/*
 * JSON reader (KEEP)
 */
export async function driveReadJsonFile(fileId) {
    const res = await _driveFetchRaw(
        buildDriveUrl(`files/${fileId}`, { alt: "media" })
    );
    return await res.json();
}

/*
 * JSON writer (KEEP)
 */
export async function drivePatchJsonFile(fileId, json) {
    await _driveFetchRaw(
        _buildDriveUploadUrl(`files/${fileId}`, { uploadType: "media" }),
        {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: U.format(json)
        }
    );
}

/*
 * File listing (KEEP)
 */
export async function driveList(params) {
    const res = await driveFetch(_buildDriveListUrl(params));
    return res.files || [];
}

/*
 * File creation (KEEP)
 */
export async function driveMultipartUpload({ metadata, content, contentType = "application/json" }) {
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
                Authorization: `Bearer ${G.accessToken}`,
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

export async function driveCreateJsonFile({ name, parents, json, overwrite = false }) {

    if (overwrite) {
        const existingFile = await findDriveFileByNameInFolder(name, parents?.[0]);
        if (existingFile?.id) {
            await drivePatchJsonFile(existingFile.id, json);
            return existingFile.id;
        }
    }

    // Otherwise, create new
    const data = await driveMultipartUpload({
        metadata: { name, parents, mimeType: "application/json" },
        content: U.format(json),
        contentType: "application/json"
    });

    return data.id;
}

// KEEP
export async function findOrCreateUserFolder() {

    log("GD.findOrCreateUserFolder", "called");
    const rootQ = `'${C.ACCESS4_ROOT_ID}' in parents and name='${C.PUBKEY_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder'`;
    const rootRes = await driveFetch(buildDriveUrl("files", { q: rootQ, fields:"files(id)" }));

    const root = rootRes.files.length ? rootRes.files[0].id : (await driveFetch(buildDriveUrl("files"), {
        method:"POST",
        headers: {
            "Content-Type":"application/json"
        },
        body: JSON.stringify({
            name: C.PUBKEY_FOLDER_NAME,
            mimeType:"application/vnd.google-apps.folder",
            parents: [C.ACCESS4_ROOT_ID]
        })
    })).id;

    const userQ = `'${root}' in parents and name='${G.userEmail}' and mimeType='application/vnd.google-apps.folder'`;
    const userRes = await driveFetch(buildDriveUrl("files", {
        q: userQ,
        fields:"files(id)"
    }));
    if (userRes.files.length) return userRes.files[0].id;

    const folder = await driveFetch(buildDriveUrl("files"), {
        method:"POST",
        headers: {
            "Content-Type":"application/json"
        },
        body: JSON.stringify({
            name: G.userEmail,
            mimeType:"application/vnd.google-apps.folder",
            parents: [root]
        })
    });

    return folder.id;
}

export async function createFileOrFolder(name, parents = [], folder = false) {
    // Ensure parents is always an array, even if a single string is passed
    const parentArray = Array.isArray(parents) ? parents : [parents];

    const body = {
        name: name,
        parents: parentArray
    };

    if (folder)
        body.mimeType = "application/vnd.google-apps.folder";

    return await driveFetch(buildDriveUrl("files"), {
        method:"POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify(body)
    });
}

// KEEP
export async function ensureRecoveryFolder() {
    const q = `'${C.ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`;
    const res = await driveFetch(buildDriveUrl("files", { q, fields:"files(id)" }));

    if (res.files.length) {
        return res.files[0].id;
    }

    const folder = await driveFetch(buildDriveUrl("files"), {
        method:"POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({
            name:"recovery",
            mimeType:"application/vnd.google-apps.folder",
            parents: [C.ACCESS4_ROOT_ID]
        })
    });

    return folder.id;
}

// KEEP
export async function readEnvelopeFromDrive(envelopeName) {
    log("GD.readEnvelopeFromDrive", "called");

    const file = await findDriveFileByName(envelopeName);
    if (!file) return null;

    const json = await driveReadJsonFile(file.id);

    return {
        fileId: file.id,
        json
    };
}

// KEEP
export async function readLockFromDrive(envelopeName) {
    //trace("GD.readLockFromDrive", "called");
    const lockName = `${envelopeName}.lock`;

    const file = await findDriveFileByName(lockName);
    if (!file) return null;

    const json = await driveReadJsonFile(file.id);

    return {
        fileId: file.id,
        json
    };
}

// KEEP
export async function writeLockToDrive(envelopeName, lockJson, existingFileId = null) {
    //trace("GD.writeLockToDrive", "called lockJson:", JSON.stringify(lockJson));

    const lockName = `${envelopeName}.lock`;

    if (existingFileId) {
        // ✅ Content-only update
        await drivePatchJsonFile(existingFileId, lockJson);
        return existingFileId;
    }

    // ✅ New file creation
    return await driveCreateJsonFile({
        name: lockName,
        parents: [C.ACCESS4_ROOT_ID],
        json: lockJson
    });
}

/**
 * Load the recovery.private.json blob from the shared "recovery" folder
 * on Google Drive.
 *
 * @returns {Promise<Object>} Parsed JSON of recovery private key
 */
// KEEP
export async function loadRecoveryPrivateBlob() {
    log("GD.loadRecoveryPrivateBlob", "called");

    try {
        // 1️⃣ Locate the recovery folder under shared root
        const recoveryFolders = await driveList({
            q: `'${C.ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`,
            pageSize: 1
        });

        if (recoveryFolders.length === 0) {
            throw new Error("Recovery folder not found on Drive");
        }

        const recoveryFolderId = recoveryFolders[0].id;

        // 2️⃣ Find the recovery.private.json file
        const recoveryFiles = await driveList({
            q: `'${recoveryFolderId}' in parents and name='recovery.private.json' and mimeType='application/json'`,
            pageSize: 1
        });

        if (recoveryFiles.length === 0) {
            throw new Error("recovery.private.json not found in recovery folder");
        }

        const fileId = recoveryFiles[0].id;

        // 3️⃣ Read the file content as JSON
        const recoveryJson = await driveReadJsonFile(fileId);

        log("GD.loadRecoveryPrivateBlob", "recovery.private.json loaded successfully");
        return recoveryJson;

    } catch (err) {
        error("GD.loadRecoveryPrivateBlob", "Failed to load recovery private blob:", err.message);
        throw err;
    }
}

/*async function markPreviousDriveKeyDeprecated(oldFingerprint, newFingerprint) {
    log("GD.markPreviousDriveKeyDeprecated", "called");

    const folder = await findOrCreateUserFolder();
    const filenamePattern = `${G.userEmail}__`; // all device keys for this user
    const q = `'${folder}' in parents and name contains '${filenamePattern}'`;
    const res = await driveFetch(buildDriveUrl("files", { q, fields:"files(id,name)" }));

    if (!res.files.length) {
        log("GD.markPreviousDriveKeyDeprecated", "no drive files found to mark keys as deprecated");
        return; // nothing to patch
    }

    for (const file of res.files) {
        const fileData = await driveFetch(buildDriveUrl(`files/${file.id}`, { alt:"media" }));
        if (fileData.keyId !== oldFingerprint) continue; // not the old key

        // --- PATCH only mutable fields ---
        const patchData = {
            state:"deprecated",
            supersededBy: newFingerprint
        };

        await driveFetch(buildDriveUrl(`files/${file.id}`, { uploadType:"media" }), {
            method:"PATCH",
            headers: { "Content-Type":"application/json" },
            body: JSON.stringify(patchData)
        });

        log("GD.markPreviousDriveKeyDeprecated", `Marked keyId (${oldFingerprint}) as deprecated in file:${file.id}`);
    }
}*/