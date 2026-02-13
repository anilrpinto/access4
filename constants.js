import { deepFreeze } from './utils.js';

export const C = deepFreeze({
    CLIENT_ID: "738922366916-ppn1c24mp9qamr6pdmjqss3cqjmvqljv.apps.googleusercontent.com",
    SCOPES: "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email",
    ACCESS4_ROOT_ID: "1zQPiXTCDlPjzgD1YZiVKsRB2s4INUS_g",
    AUTH_FILE_NAME: "authorized.json",
    PUBKEY_FOLDER_NAME: "pub-keys",
    DEVICE_ID_KEY: "access4.device.id",
    HEARTBEAT_INTERVAL: 10_000, // 10 seconds
    LOCK_TTL_MS: 30_000        // must be > heartbeat
});
