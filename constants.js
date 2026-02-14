"use strict";

import { deepFreeze } from './utils.js';

export const C = deepFreeze({
    CLIENT_ID: "738922366916-ppn1c24mp9qamr6pdmjqss3cqjmvqljv.apps.googleusercontent.com",
    SCOPES: "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email",
    ACCESS4_ROOT_ID: "1zQPiXTCDlPjzgD1YZiVKsRB2s4INUS_g",
    AUTH_FILE_NAME: "authorized.json",
    PUBKEY_FOLDER_NAME: "pub-keys",
    DEVICE_ID_KEY: "access4.device.id",
    HEARTBEAT_INTERVAL: 10_000, // 10 seconds
    LOCK_TTL_MS: 30_000,        // must be > heartbeat

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
