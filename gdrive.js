"use strict";

import { C } from './constants.js';
import { G } from './global.js';
import { log, trace, debug, info, warn, error } from './log.js';

export async function fetchUserEmail() {
    const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: {
            Authorization: `Bearer ${G.accessToken}`
        }
    });
    const data = await res.json();
    G.userEmail = data.email;

    log("Signed in as xxx@gmail.com"); //+ G.userEmail);
}

export async function verifyWritable(folderId) {
    log("[GD.verifyWritable] called - Verifying Drive write access (probe)");
    await fetch(buildDriveUrl("files", {
        q: `'${folderId}' in parents`,
        pageSize: 1
    }), {
        headers: {
            Authorization: `Bearer ${G.accessToken}`
        }
    });
    log("[GD.verifyWritable] Drive access verified (read scope OK)");
}

export async function verifySharedRoot(root) {
    log("[GD.verifySharedRoot] called");
    await driveFetch(buildDriveUrl(`files/${root}`, {
        fields: "id"
    }));
}

export async function driveFetch(url, options = {}) {
    options.headers ||= {};
    options.headers.Authorization = `Bearer ${G.accessToken}`;
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`Drive fetch failed: ${res.status} ${res.statusText}`);
    return res.json();
}

export function buildDriveUrl(path, params = {}) {
    params.supportsAllDrives = true;
    // Commented as only needed for LIST calls not GET
    //params.includeItemsFromAllDrives = true;
    return `https://www.googleapis.com/drive/v3/${path}?` +
    Object.entries(params).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
}

export async function findDriveFileByName(name) {
    return _driveFindFileByNameInFolder(name, C.ACCESS4_ROOT_ID);
}

export async function driveReadJsonFile(fileId) {
    const res = await _driveFetchRaw(
        buildDriveUrl(`files/${fileId}`, { alt: "media" })
    );
    return await res.json();
}

export async function drivePatchJsonFile(fileId, json) {
    // Determine indentation: undefined (minified), other wise indent by 2 spaces
    const minify = G.settings?.minifyJson ? undefined : 2;

    await _driveFetchRaw(
        _buildDriveUploadUrl(`files/${fileId}`, { uploadType: "media" }),
        {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(json, null, minify)
        }
    );
}

export async function driveList(params) {
    const res = await driveFetch(_buildDriveListUrl(params));
    return res.files || [];
}

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

export async function driveCreateJsonFile({ name, parents, json }) {
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

function _buildDriveListUrl(params = {}) {
    return buildDriveUrl("files", {
        ...params,
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
    });
}

function _buildDriveUploadUrl(path, params = {}) {
    const qs = new URLSearchParams({
        supportsAllDrives: "true",
        includeItemsFromAllDrives: "true",
        ...params
    });
    return `https://www.googleapis.com/upload/drive/v3/${path}?${qs}`;
}

// IMPORTANT:
// Drive has separate endpoints for metadata vs file content.
// NEVER send JSON content to drive/v3/files.
// Use upload/drive/v3/files for media writes.
async function _driveFindFileByNameInFolder(name, folderId) {
    const q = [
        `name='${name.replace(/'/g, "\\'")}'`,
        `'${folderId}' in parents`,
        `trashed=false`
    ].join(" and ");

    const res = await _driveApiGet("files", { q, fields: "files(id,name,modifiedTime)" });

    return res.files?.[0] || null;
}

async function _driveApiGet(path, params = {}) {
    return driveFetch(
        buildDriveUrl(path, params),
        { method: "GET" }
    );
}

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

export async function findOrCreateUserFolder() {

    log("[GD.findOrCreateUserFolder] entered");
    const rootQ = `'${C.ACCESS4_ROOT_ID}' in parents and name='${C.PUBKEY_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder'`;
    const rootRes = await driveFetch(buildDriveUrl("files", {
        q: rootQ,
        fields:"files(id)"
    }));
    const root = rootRes.files.length ? rootRes.files[0].id :
    (await driveFetch(buildDriveUrl("files"), {
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

async function markPreviousDriveKeyDeprecated(oldFingerprint, newFingerprint) {
    log("[GD.markPreviousDriveKeyDeprecated] entered");

    const folder = await findOrCreateUserFolder();
    const filenamePattern = `${G.userEmail}__`; // all device keys for this user
    const q = `'${folder}' in parents and name contains '${filenamePattern}'`;
    const res = await driveFetch(buildDriveUrl("files", { q, fields:"files(id,name)" }));

    if (!res.files.length) return; // nothing to patch

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

        log(`[markPreviousDriveKeyDeprecated] Previous device key (${oldFingerprint}) marked deprecated on Drive`);
    }
}

export async function loadPublicKeyJsonsFromDrive() {
    log("[GD.loadPublicKeyJsonsFromDrive] called");
    const publicKeyJsons = [];

    // 1️⃣ Locate pub-keys folder
    const pubKeysFolders = await driveList({
        q: `'${C.ACCESS4_ROOT_ID}' in parents and name='pub-keys' and mimeType='application/vnd.google-apps.folder'`,
        pageSize: 1
    });

    if (pubKeysFolders.length === 0) {
        warn("[GD.loadPublicKeyJsonsFromDrive] pub-keys folder not found");
        return publicKeyJsons;
    }

    const pubKeysRootId = pubKeysFolders[0].id;

    // 2️⃣ Enumerate email subfolders
    const accountFolders = await driveList({
        q: `'${pubKeysRootId}' in parents and mimeType='application/vnd.google-apps.folder'`,
        pageSize: 100
    });

    for (const accountFolder of accountFolders) {
        // 3️⃣ Enumerate device key files
        const deviceKeyFiles = await driveList({
            q: `'${accountFolder.id}' in parents and mimeType='application/json'`,
            pageSize: 100
        });

        for (const file of deviceKeyFiles) {
            try {
                const json = await driveReadJsonFile(file.id);
                publicKeyJsons.push(json);
            } catch (err) {
                log(`[loadPublicKeyJsonsFromDrive] Failed to read ${file.name}: ${err.message}`);
            }
        }
    }

    // 4️⃣ Load recovery public key (optional)
    const recoveryFolders = await driveList({
        q: `'${C.ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`,
        pageSize: 1
    });

    if (recoveryFolders.length > 0) {
        const recoveryFolderId = recoveryFolders[0].id;

        const recoveryPublicFiles = await driveList({
            q: `'${recoveryFolderId}' in parents and name='recovery.public.json'`,
            pageSize: 1
        });

        if (recoveryPublicFiles.length > 0) {
            try {
                const recoveryJson = await driveReadJsonFile(recoveryPublicFiles[0].id);
                publicKeyJsons.push(recoveryJson);
            } catch (err) {
                log("[GD.loadPublicKeyJsonsFromDrive] Failed to read recovery.public.json");
            }
        }
    }

    log(`[loadPublicKeyJsonsFromDrive] Loaded ${publicKeyJsons.length} public keys`);
    return publicKeyJsons;
}

/* ================= RECOVERY KEY ================= */
export async function hasRecoveryKeyOnDrive() {
    log("[GD.hasRecoveryKeyOnDrive] called");

    try {
        const folders = await driveList({
            q: `'${C.ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`,
            pageSize: 1
        });

        log("[GD.hasRecoveryKeyOnDrive] recovery folders found:", folders.length);

        if (!folders.length) return false;

        const recoveryFolderId = folders[0].id;

        const files = await driveList({
            q: `'${recoveryFolderId}' in parents and name='recovery.public.json'`,
            pageSize: 1
        });

        return files.length === 1;

    } catch (e) {
        error("[GD.hasRecoveryKeyOnDrive] Recovery key check failed:", e.message);
        throw e; // mandatory block
    }
}

export async function ensureRecoveryFolder() {
    const q = `'${C.ACCESS4_ROOT_ID}' in parents and name='recovery' and mimeType='application/vnd.google-apps.folder'`;
    const res = await driveFetch(buildDriveUrl("files", {
        q,
        fields:"files(id)"
    }));

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

export async function readEnvelopeFromDrive(envelopeName) {
    log("[GD.readEnvelopeFromDrive] called");

    const file = await findDriveFileByName(envelopeName);
    if (!file) return null;

    const json = await driveReadJsonFile(file.id);

    return {
        fileId: file.id,
        json
    };
}

export async function readLockFromDrive(envelopeName) {
    //trace("[GD.readLockFromDrive] called");
    const lockName = `${envelopeName}.lock`;

    const file = await findDriveFileByName(lockName);
    if (!file) return null;

    const json = await driveReadJsonFile(file.id);

    return {
        fileId: file.id,
        json
    };
}

export async function writeLockToDrive(envelopeName, lockJson, existingFileId = null) {
    //trace("[GD.writeLockToDrive] called lockJson:", JSON.stringify(lockJson));

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