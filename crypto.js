"use strict";

import { log, trace, debug, info, warn, error } from './log.js';

export async function deriveKey(pwd, kdf) {

    log("CR.deriveKey", "called");

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
        mat,
        {
            name:"AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function computePublicKeyFingerprint(pubBytes) {
    log("CR.computePublicKeyFingerprint", "called");

    // Enforce that we are dealing with a buffer-like object
    if (!(pubBytes instanceof Uint8Array) && !(pubBytes instanceof ArrayBuffer)) {
        throw new Error("Fingerprint source must be raw bytes (Uint8Array or ArrayBuffer)");
    }

    const hashBuffer = await crypto.subtle.digest("SHA-256", pubBytes);

    // Convert resulting hash to Base64 (because Fingerprints are usually strings)
    return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
}

export async function decrypt(enc, key) {
    log("CR.decrypt", "called");
    return crypto.subtle.decrypt({
            name:"AES-GCM",
            iv: Uint8Array.from(atob(enc.iv), c => c.charCodeAt(0))
        },
        key,
        Uint8Array.from(atob(enc.data), c => c.charCodeAt(0))
    );
}

export async function encrypt(data, key) {
    log("CR.encrypt", "called");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({
            name:"AES-GCM",
            iv
        },
        key, data);
    return {
        iv: btoa(String.fromCharCode(...iv)),
        data: btoa(String.fromCharCode(...new Uint8Array(enc)))
    };
}