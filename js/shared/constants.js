"use strict";

import { U } from './exports.js';

export const C = U.deepFreeze({
    APP_VERSION: "15",
    CLIENT_ID: "738922366916-ppn1c24mp9qamr6pdmjqss3cqjmvqljv.apps.googleusercontent.com",
    SCOPES: "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email",
    ACCESS4_ROOT_ID: "1zQPiXTCDlPjzgD1YZiVKsRB2s4INUS_g",
    DEVICE_ID_KEY: "access4.device.id",

    AUTH_FILE_NAME: "authorized.json",
    ENVELOPE_NAME: "envelope.json",
    RECOVERY_KEY_PUBLIC_FILE: "recovery.public.json",
    RECOVERY_KEY_PRIVATE_FILE: "recovery.private.json",
    PUBKEY_FOLDER_NAME: "pub-keys",
    RECOVERY_FOLDER_NAME: "recovery",

    BACKUP_MANIFEST_KEY: "access4.backup.manifest",
    LAST_AUTO_BACKUP_KEY: "access4.last.auto.backup",
    BACKUP_CLEANUP_COUNTER_KEY: "access4.cleanup.counter",
    MAX_BACKUP_MANIFEST_ENTRIES: 10,

    HEARTBEAT_INTERVAL: 10_000, // 10 seconds
    LOCK_TTL_MS: 60_000,        // must be > heartbeat
    IDLE_TIMEOUT_MS: 300000,    // 5 mins

    BIO_DB_NAME: "access4_bio_db",
    BIO_STORE: "pwk_store",

    PASSWORD_MIN_LEN: 7,
    PASSWORD_VERIFIER_TEXT: "ACCESS4_VERIFIER",

    UNLOCK_ERROR_DEFS: {
        WEAK_PASSWORD: {
            code: "WEAK_PASSWORD",
            message: "Password must be at least 7 characters long."
        },
        NO_ACCESS_TOKEN: {
            code: "NO_ACCESS_TOKEN",
            message: "Authentication not ready. Please sign in again."
        },
        INCORRECT_PASSWORD: {
            code: "INCORRECT_PASSWORD",
            message: "Incorrect password. Please try again."
        },
        SAFARI_RECOVERY: {
            code: "SAFARI_RECOVERY",
            message: "Browser recovery required. Identity was recreated."
        },
        PASSWORD_SETUP_REQUIRED: {
            code: "PASSWORD_SETUP_REQUIRED",
            message: "Detected need for a password set up."
        },
        NO_IDENTITY: {
            code: "NO_IDENTITY",
            message: "No identity found on this device. Please create one first."
        },
        UNKNOWN: {
            code: "UNKNOWN_ERROR",
            message: "An unexpected error occurred."
        }
    }
});
