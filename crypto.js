"use strict";

import { log, trace, debug, info, warn, error } from './log.js';

export async function deriveKey(pwd, kdf) {

    log("[CR.deriveKey] called");

    const mat = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(pwd),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey({
        name:"PBKDF2",
        salt: Uint8Array.from(atob(kdf.salt), c => c.charCodeAt(0)),
        iterations: kdf.iterations,
        hash:"SHA-256"
    },
        mat, {
            name:"AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function computeFingerprintFromPublicKey(base64Spki) {
    log("[CR.computeFingerprintFromPublicKey] called");
    const pubBytes = Uint8Array.from(atob(base64Spki), c => c.charCodeAt(0));
    const hash = await crypto.subtle.digest("SHA-256", pubBytes);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

export async function decrypt(enc, key) {
    return crypto.subtle.decrypt({
        name:"AES-GCM",
        iv: Uint8Array.from(atob(enc.iv), c => c.charCodeAt(0))
    },
        key,
        Uint8Array.from(atob(enc.data), c => c.charCodeAt(0))
    );
}

export async function encrypt(data, key) {
    log("[CR.encrypt] called");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({
        name:"AES-GCM",
        iv
    }, key, data);
    return {
        iv: btoa(String.fromCharCode(...iv)),
        data: btoa(String.fromCharCode(...new Uint8Array(enc)))
    };
}