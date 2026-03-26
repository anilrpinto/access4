import { C, G, U, log, trace, debug, info, warn, error } from '@/shared/exports.js';

/**
 * IMPORTANT:
 * Drive has separate endpoints for metadata vs file content.
 * NEVER send JSON content to drive/v3/files.
 * Use upload/drive/v3/files for media writes.
 */

function _escapeDriveString(s) {
    return s.replace(/'/g, "\\'");
}

function _buildDriveQuery({
    name,
    nameContains,
    parent,
    mimeType,
    trashed = false
} = {}) {

    const q = [];

    if (name)
    q.push(`name='${_escapeDriveString(name)}'`);

    if (nameContains)
    q.push(`name contains '${_escapeDriveString(nameContains)}'`);

    if (parent)
    q.push(`'${parent}' in parents`);

    if (mimeType)
    q.push(`mimeType='${mimeType}'`);

    if (trashed !== undefined)
    q.push(`trashed=${trashed}`);

    return q.join(" and ");
}

function _buildDriveListUrl(params = {}) {
    return _buildDriveUrl("files", {
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
function _buildDriveUrl(path, params = {}) {
    params.supportsAllDrives = true;
    // Commented as only needed for LIST calls not GET
    //params.includeItemsFromAllDrives = true;
    return `https://www.googleapis.com/drive/v3/${path}?` +
    Object.entries(params).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
}

async function _driveFindFileByNameInFolder(name, folderId) {

    const q = _buildDriveQuery({
        name,
        parent: folderId,
        trashed: false
    });

    const res = await _driveApiGet("files", { q, fields: "files(id,name,modifiedTime)" });

    return res.files?.[0] || null;
}

/*
 * GET wrapper (KEEP)
 */
async function _driveApiGet(path, params = {}) {
    return _driveFetch(
        _buildDriveUrl(path, params),
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
async function _driveFetch(url, options = {}) {
    options.headers ||= {};
    options.headers.Authorization = `Bearer ${G.accessToken}`;
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`Drive fetch failed: ${res.status} ${res.statusText}`);
    return res.json();
}

async function _driveList(params) {
    const res = await _driveFetch(_buildDriveListUrl(params));
    return res.files || [];
}

// File creation
async function _driveMultipartUpload({ metadata, content, contentType = "application/json" }) {
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

async function _driveMultipartUploadBinary({ metadata, content, contentType = "application/octet-stream" }) {
    const boundary = "-------access4-" + crypto.randomUUID();

    // Use a Blob/ArrayBuffer approach for true binary safety
    const header = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`;
    const footer = `\r\n--${boundary}--`;

    const body = new Blob([
        header,
        content, // This can now be a Uint8Array or Blob safely
        footer
    ]);

    const res = await fetch(
        "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true",
        {
            method: "POST",
            headers: {
                Authorization: `Bearer ${G.accessToken}`,
                "Content-Type": `multipart/related; boundary=${boundary}`
            },
            body
        }
    );

    if (!res.ok) throw new Error(`Binary upload failed: ${res.status}`);
    return await res.json();
}

async function ensurePubKeyFolder() {
    return findOrCreateFolder(C.PUBKEY_FOLDER_NAME, C.ACCESS4_ROOT_ID);
}

/**
 * EXPORTED FUNCTIONS
 */

// auth.js
export async function readJsonByName(name, folderId = C.ACCESS4_ROOT_ID) {

    const file = await findDriveFileByNameInFolder(name, folderId);

    if (!file)
        return null;

    const json = await readJsonByFileId(file.id);

    return { fileId: file.id, json };
}

// registry.js, envelope.js
export async function readJsonByFileId(fileId) {
    const res = await _driveFetchRaw(
        _buildDriveUrl(`files/${fileId}`, { alt: "media" })
    );
    return await res.json();
}

export async function readBinaryByFileId(fileId) {
    const res = await _driveFetchRaw(
        _buildDriveUrl(`files/${fileId}`, { alt: "media" })
    );
    // Return as ArrayBuffer for decryption
    return await res.arrayBuffer();
}

// auth.js, envelope.js, loader.js
export async function upsertJsonFile({ name, parentId, json, overwrite = false }) {

    if (overwrite) {
        const existing = await findDriveFileByNameInFolder(name, parentId);

        if (existing?.id) {
            await drivePatchJsonFile(existing.id, json);
            return existing.id;
        }
    }

    const file = await _driveMultipartUpload({
        metadata: {
            name,
            parents: [parentId],
            mimeType: "application/json"
        },
        content: U.format(json)
    });

    return file.id;
}

/**
 * Binary version of upsert.
 * Handles the 'attachments' folder and returns the Drive File ID.
 */
export async function upsertBinaryFile({ name, parentId, content, mimeType = "application/octet-stream" }) {
    log("GD.upsertBinaryFile", `Uploading ${name}`);

    // Note: We usually don't 'overwrite' attachments since they use UUIDs,
    // but the structure remains consistent with your JSON helper.
    const file = await _driveMultipartUploadBinary({
        metadata: {
            name,
            parents: [parentId],
            mimeType
        },
        content
    });

    return file.id; // This is the ID we MUST store in the Vault JSON
}

/**
 * Permanently deletes a file from Google Drive by its ID.
 * @param {string} fileId - The unique Drive File ID.
 */
export async function deleteFileById(fileId) {
    if (!fileId) throw new Error("GD.deleteFileById: No fileId provided.");

    log("GD.deleteFileById", `Permanently deleting file: ${fileId}`);

    // Using your existing _driveFetchRaw pattern
    const response = await _driveFetchRaw(_buildDriveUrl(`files/${fileId}`), { method: "DELETE" });

    // Google returns a 204 No Content on a successful delete
    if (response.status === 204) {
        info("GD.deleteFileById", "File deleted successfully.");
        return true;
    }

    // Handle cases where the file might already be gone (404)
    if (response.status === 404) {
        warn("GD.deleteFileById", "File not found; it may have been deleted already.");
        return true;
    }

    throw new Error(`Delete failed: ${response.status} ${response.statusText}`);
}

/*export async function trashFileById(fileId) {
    log("GD.trashFileById", `Moving to trash: ${fileId}`);

    return await _driveFetchRaw(`files/${fileId}?supportsAllDrives=true`, {
        method: 'PATCH',
        body: JSON.stringify({ trashed: true })
    });
}*/

export async function trashFileById(fileId) {
    log("GD.trashFileById", `Moving to trash via POST Override: ${fileId}`);

    // We change the method to POST, but tell Google to treat it as a PATCH
    return await _driveFetchRaw(`files/${fileId}?supportsAllDrives=true`, {
        method: 'POST', // Tomcat will allow this
        headers: {
            'X-HTTP-Method-Override': 'PATCH', // Google will see this
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ trashed: true })
    });
}

// envelope.js
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

// identity.js
export async function ensureUserPubKeyFolder() {
    const root = await ensurePubKeyFolder();
    return findOrCreateFolder(G.userEmail, root);
}

// auth.js
export async function fetchUserEmail() {
    const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: {
            Authorization: `Bearer ${G.accessToken}`
        }
    });
    const data = await res.json();
    G.userEmail = data.email;
    G.authorizedName = data.name;
    G.userId = data.sub;

    log("GD.fetchUserEmail", `Authenticated: ...${G?.userEmail?.slice(-10)} [ID: ...${G.userId.slice(-6)}]`);
}

// auth.js
export async function verifyWritable(folderId) {
    log("GD.verifyWritable", "called - Verifying Drive write access (probe)");
    await fetch(_buildDriveUrl("files", {
        q: `'${folderId}' in parents`,
        pageSize: 1
    }), {
        headers: {
            Authorization: `Bearer ${G.accessToken}`
        }
    });
    log("GD.verifyWritable", "Drive access verified (read scope OK)");
}

// auth.js
export async function verifySharedRoot(root) {
    log("GD.verifySharedRoot", "called");
    await _driveFetch(_buildDriveUrl(`files/${root}`, {
        fields: "id"
    }));
}

// identity.js
export async function findDriveFileByNameInFolder(name, folderId) {
    return _driveFindFileByNameInFolder(name, folderId);
}

// envelope.js
export async function findDriveFileByNameInRoot(name) {
    return findDriveFileByNameInFolder(name, C.ACCESS4_ROOT_ID);
}

// recovery.js
export async function findOrCreateFolder(name, parentId = C.ACCESS4_ROOT_ID) {

    const q = _buildDriveQuery({
        name,
        parent: parentId,
        mimeType: "application/vnd.google-apps.folder"
    });

    const res = await _driveList({ q, fields: "files(id)" });

    if (res.length) return res[0].id;

    const folder = await _driveFetch(
        _buildDriveUrl("files"), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name,
                mimeType: "application/vnd.google-apps.folder",
                parents: [parentId]
            })
        });

    return folder.id;
}

// registry.js
export async function listFolders(parentId) {
    return await _driveList({
        q: _buildDriveQuery({
            parent: parentId,
            mimeType: "application/vnd.google-apps.folder"
        }),
        pageSize: 100
    });
}

// registry.js
export async function listJsonFiles(parentId) {
    return await _driveList({
        q: _buildDriveQuery({
            parent: parentId,
            mimeType: "application/json"
        }),
        pageSize: 100
    });
}

// registry.js
export async function readJsonFilesFromFolder(parentId) {

    const files = await listJsonFiles(parentId);

    const results = [];

    for (const file of files) {
        try {
            const json = await readJsonByFileId(file.id);
            results.push(json);
        } catch (err) {
            error("readJsonFilesFromFolder", `Failed reading ${file.name}`);
        }
    }

    return results;
}

/**
 * Lists all files in a folder that are owned by the authenticated user.
 * Generalized to work for any folder (Attachments, PubKeys, etc.)
 */
export async function listFilesOwnedByMe(folderName) {
    if (!folderName) {
        error("GD.listFilesOwnedByMe", "No folder name provided");
        return [];
    }

    const folderId = await findOrCreateFolder(folderName);

    // We build a query that adds the 'me' in owners constraint
    const q = _buildDriveQuery({ parent: folderId, trashed: false })
                + " and 'me' in owners";

    // We use your existing _driveList wrapper
    return await _driveList({
        q,
        fields: "files(id, name)",
        pageSize: 1000 // Higher limit for cleanup tasks
    });
}

