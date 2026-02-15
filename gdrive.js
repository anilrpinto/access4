"use strict";

import { C } from './constants.js';
import { G } from './global.js';
import { log, trace, debug, info, warn, error, setLogLevel, TRACE, DEBUG, INFO, WARN, ERROR } from './log.js';

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
    log("? Verifying Drive write access (probe)");
    await fetch(buildDriveUrl("files", {
        q: `'${folderId}' in parents`,
        pageSize: 1
    }), {
        headers: {
            Authorization: `Bearer ${G.accessToken}`
        }
    });
    log("? Drive access verified (read scope OK)");
}

export async function verifySharedRoot(root) {
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
    await _driveFetchRaw(
        _buildDriveUploadUrl(`files/${fileId}`, { uploadType: "media" }),
        {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(json)
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
