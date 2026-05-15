"use strict";

import { C, G, clearGlobals, isValidSession, SV, log, trace, debug, info, warn, error, setLogLevel, onlyLogLevels, TRACE, DEBUG, INFO, WARN, ERROR } from '@/shared/exports.js';
import { rootUI } from '@/ui/loader.js';
import { loadLogin }  from '@/ui/login.js';
import { loadVault }  from '@/ui/vault.js';
import { copyToClipboard } from '@/ui/uihelper.js';

export let logEl = rootUI.log;

const _idleManager = {
    timer: null,
    lastReset: 0,
    boundHandler: null,
    threshold: 5000,
    events: ['mousedown', 'mousemove', 'keydown', 'keypress', 'click', 'scroll', 'touchstart']
};

const _resetTimer = (force = false) => {
    const now = Date.now();

    if (!force && (now - _idleManager.lastReset < _idleManager.threshold)) {
        return;
    }

    log("APP._resetTimer", "Refreshing idle timeout");
    _idleManager.lastReset = now;

    clearTimeout(_idleManager.timer);

    _idleManager.timer = setTimeout(async () => {
        logout("Auto logout");
    }, C.IDLE_TIMEOUT_MS);
};

export function activateIdleChecker() {
    log("APP.activateIdleChecker", "called");

    // 1. Create a clean wrapper that doesn't pass the Event object
    _idleManager.boundHandler = () => _resetTimer(false);

    // Events that "wake up" the timer
    // Clean up old listeners to prevent memory leaks/duplicate triggers
    _idleManager.events.forEach(evt => {
        document.removeEventListener(evt, _idleManager.boundHandler);
        document.addEventListener(evt, _idleManager.boundHandler, { passive: true });
    });

    _resetTimer(true);
}

export async function logout(reason = "User initiated") {
    log("APP.logout", "Initiating logout... reason:", reason);

    // 2️⃣ Clear the rest of the app state
    clearGlobals();
    sessionStorage.removeItem("sv_session_private_key");

    // 1️⃣ Wait for the lock to be released properly
    await _releaseDriveLock();

    _deactivateAutoLogout();

    // 3️⃣ Redirect to login
    loadLogin();

    G.biometricIntent = false;
    log("APP.logout", "Logout complete.");
}

function getVaultData() {
    return "{\n" +
        "  \"meta\": {\n" +
        "    \"version\": \"1.0\",\n" +
        "    \"lastModified\": null,\n" +
        "    \"type\": \"shared\",\n" +
        "    \"extensions\": {\n" +
        "      \"private_vaults\": {\n" +
        "        \"4q6Hbc44WO/1S4WqqemMHY4k79L3CK1Y2qpeK4CFxMs=\": \"VOrmC51enCS3HME1.15xgpfC8/er3FGHj4pAyQ5R7oW+ElG8Wv1dNU5d0hpuViy1r2xqRn+bZmNhMeHs3n2ZqIabftuTnyOGlqiFNXn8jZhhxoLaREHPMq4K76cGtqKBgfzJGtV2dSBsENpLk9CCkUVGUrf7medq1P6+puKG4Gxt/Poj6iW9LF81fGs2Tg9mGuIi/wQ==\"\n" +
        "      }\n" +
        "    }\n" +
        "  },\n" +
        "  \"groups\": [\n" +
        "    {\n" +
        "      \"id\": \"g-12345567890\",\n" +
        "      \"name\": \"Genesis\",\n" +
        "      \"items\": [\n" +
        "        {\n" +
        "          \"id\": \"i-1234567890\",\n" +
        "          \"label\": \"Access4\",\n" +
        "          \"created\": \"2026-01-10T08:00:00Z\",\n" +
        "          \"modified\": \"2026-02-20T15:30:00Z\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"type\": \"text\",\n" +
        "              \"key\": \"username\",\n" +
        "              \"val\": \"username1234\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"secure\",\n" +
        "              \"key\": \"Password\",\n" +
        "              \"val\": \"password1234\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"note\",\n" +
        "              \"key\": \"Notes\",\n" +
        "              \"val\": \"Some important notes\"\n" +
        "            }\n" +
        "          ],\n" +
        "          \"attachments\": []\n" +
        "        }\n" +
        "      ]\n" +
        "    },\n" +
        "    {\n" +
        "      \"id\": \"g-79c3e48a-b1c8-4a9b-8bd5-2f026175834b\",\n" +
        "      \"name\": \"This is a long group name\",\n" +
        "      \"items\": [\n" +
        "        {\n" +
        "          \"id\": \"i-e0cee957-c569-4549-a60c-345fb407a17f\",\n" +
        "          \"label\": \"A long item.name too\",\n" +
        "          \"created\": \"2026-04-14T21:12:43.995Z\",\n" +
        "          \"modified\": \"2026-04-14T21:12:43.995Z\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"type\": \"text\",\n" +
        "              \"key\": \"Username\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"secure\",\n" +
        "              \"key\": \"Password\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"note\",\n" +
        "              \"key\": \"Notes\",\n" +
        "              \"val\": \"\"\n" +
        "            }\n" +
        "          ]\n" +
        "        },\n" +
        "        {\n" +
        "          \"id\": \"i-697c0075-01b7-462c-9b9d-b3d46adda665\",\n" +
        "          \"label\": \"Small\",\n" +
        "          \"created\": \"2026-04-14T21:12:52.515Z\",\n" +
        "          \"modified\": \"2026-04-14T21:12:52.515Z\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"type\": \"text\",\n" +
        "              \"key\": \"Username\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"secure\",\n" +
        "              \"key\": \"Password\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"note\",\n" +
        "              \"key\": \"Notes\",\n" +
        "              \"val\": \"\"\n" +
        "            }\n" +
        "          ]\n" +
        "        }\n" +
        "      ]\n" +
        "    },\n" +
        "    {\n" +
        "      \"id\": \"g-0252b16b-f63b-44e4-ad65-ecdfbde81623\",\n" +
        "      \"name\": \"Unused-Renamed\",\n" +
        "      \"items\": []\n" +
        "    },\n" +
        "    {\n" +
        "      \"id\": \"g-994d414c-ba45-4918-817b-b97bc7654f85\",\n" +
        "      \"name\": \"Shared-Active-Grp\",\n" +
        "      \"items\": [\n" +
        "        {\n" +
        "          \"id\": \"i-6b32f10b-07e8-49d5-bf39-b1c76e1b7084\",\n" +
        "          \"label\": \"AAA\",\n" +
        "          \"created\": \"2026-05-10T06:52:00.372Z\",\n" +
        "          \"modified\": \"2026-05-10T06:52:00.372Z\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"type\": \"text\",\n" +
        "              \"key\": \"Username\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"secure\",\n" +
        "              \"key\": \"Password\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"note\",\n" +
        "              \"key\": \"Notes\",\n" +
        "              \"val\": \"\"\n" +
        "            }\n" +
        "          ]\n" +
        "        }\n" +
        "      ]\n" +
        "    }\n" +
        "  ],\n" +
        "  \"archived\": [\n" +
        "    {\n" +
        "      \"id\": \"g-d998c2ca-2207-43c9-a805-08da4449af30\",\n" +
        "      \"name\": \"Legacy\",\n" +
        "      \"items\": [\n" +
        "        {\n" +
        "          \"id\": \"i-575c8408-4f1e-4a05-a2a0-27d70977b00b\",\n" +
        "          \"label\": \"TestItem999\",\n" +
        "          \"created\": \"2026-04-12T04:44:15.482Z\",\n" +
        "          \"modified\": \"2026-05-10T07:10:49.598Z\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"type\": \"text\",\n" +
        "              \"key\": \"Username\",\n" +
        "              \"val\": \"testuser\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"secure\",\n" +
        "              \"key\": \"Password\",\n" +
        "              \"val\": \"testpassword\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"note\",\n" +
        "              \"key\": \"Notes\",\n" +
        "              \"val\": \"test notes\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"key\": \"PIN\",\n" +
        "              \"val\": \"123456\",\n" +
        "              \"type\": \"secure\"\n" +
        "            }\n" +
        "          ],\n" +
        "          \"attachments\": [\n" +
        "            {\n" +
        "              \"key\": \"zipota50 Instance creation (1).pdf\",\n" +
        "              \"type\": \"file\",\n" +
        "              \"val\": \"1wRHjUkOdb8rTx0EJ6IsY5DTFueSKmaH7\",\n" +
        "              \"uuid\": \"e40eda96-7a57-4c79-a81b-1c541330eeb4\",\n" +
        "              \"oid\": \"113798817106968961602\",\n" +
        "              \"meta\": {\n" +
        "                \"size\": 441592,\n" +
        "                \"mime\": \"application/pdf\",\n" +
        "                \"updated\": \"2026-04-12T04:45:00.730Z\",\n" +
        "                \"uploadedBy\": \"anilrpinto1@gmail.com\"\n" +
        "              }\n" +
        "            }\n" +
        "          ]\n" +
        "        }\n" +
        "      ]\n" +
        "    },\n" +
        "    {\n" +
        "      \"id\": \"g-269f3790-d3f2-471b-a750-df965c51d5af\",\n" +
        "      \"name\": \"New Group moved to archive\",\n" +
        "      \"items\": [\n" +
        "        {\n" +
        "          \"id\": \"i-471c2266-bdfa-4ef9-a857-92d1a61b9d46\",\n" +
        "          \"label\": \"New Item\",\n" +
        "          \"created\": \"2026-05-01T18:29:17.802Z\",\n" +
        "          \"modified\": \"2026-05-01T18:31:52.700Z\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"type\": \"text\",\n" +
        "              \"key\": \"Username\",\n" +
        "              \"val\": \"newuser\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"secure\",\n" +
        "              \"key\": \"Password\",\n" +
        "              \"val\": \"newpwd\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"note\",\n" +
        "              \"key\": \"Notes\",\n" +
        "              \"val\": \"new notes\\nsome more text\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"key\": \"new label\",\n" +
        "              \"val\": \"\",\n" +
        "              \"type\": \"text\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"key\": \"new secure\",\n" +
        "              \"val\": \"\",\n" +
        "              \"type\": \"secure\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"key\": \"new note\",\n" +
        "              \"val\": \"\",\n" +
        "              \"type\": \"note\"\n" +
        "            }\n" +
        "          ],\n" +
        "          \"attachments\": [\n" +
        "            {\n" +
        "              \"key\": \"new attachment\",\n" +
        "              \"type\": \"file\",\n" +
        "              \"val\": \"1hNefYawHnxXgIWyqo9oxX1cHjSyP33yt\",\n" +
        "              \"uuid\": \"e0f470bb-f360-4933-bd69-7b2b7f180947\",\n" +
        "              \"oid\": \"113798817106968961602\",\n" +
        "              \"meta\": {\n" +
        "                \"size\": 58313,\n" +
        "                \"mime\": \"application/pdf\",\n" +
        "                \"updated\": \"2026-05-01T18:31:01.303Z\",\n" +
        "                \"uploadedBy\": \"anilrpinto1@gmail.com\"\n" +
        "              }\n" +
        "            }\n" +
        "          ]\n" +
        "        },\n" +
        "        {\n" +
        "          \"id\": \"i-ddb347b2-29dd-430d-b087-7db81bde93f2\",\n" +
        "          \"label\": \"NewItemZZZ\",\n" +
        "          \"created\": \"2026-04-12T04:52:45.489Z\",\n" +
        "          \"modified\": \"2026-05-01T19:50:38.833Z\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"type\": \"text\",\n" +
        "              \"key\": \"Username\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"secure\",\n" +
        "              \"key\": \"Password\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"note\",\n" +
        "              \"key\": \"Notes\",\n" +
        "              \"val\": \"\"\n" +
        "            }\n" +
        "          ]\n" +
        "        }\n" +
        "      ]\n" +
        "    },\n" +
        "    {\n" +
        "      \"id\": \"g-14b195f9-e76d-4802-8952-80e5f7bbffd2\",\n" +
        "      \"name\": \"Shared-Archived-Grp\",\n" +
        "      \"items\": [\n" +
        "        {\n" +
        "          \"id\": \"i-3aa2fbba-6194-4f63-b63f-4671d2088d22\",\n" +
        "          \"label\": \"456\",\n" +
        "          \"created\": \"2026-05-10T06:53:26.181Z\",\n" +
        "          \"modified\": \"2026-05-10T07:11:09.574Z\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"type\": \"text\",\n" +
        "              \"key\": \"Username\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"secure\",\n" +
        "              \"key\": \"Password\",\n" +
        "              \"val\": \"\"\n" +
        "            },\n" +
        "            {\n" +
        "              \"type\": \"note\",\n" +
        "              \"key\": \"Notes\",\n" +
        "              \"val\": \"\"\n" +
        "            }\n" +
        "          ]\n" +
        "        }\n" +
        "      ]\n" +
        "    }\n" +
        "  ]\n" +
        "}";
}

async function setAuthData() {

    G.userEmail = 'anilrpinto1@gmail.com';
    G.auth = {
        version: 1,
        created: new Date().toISOString(),
        members: {
            [G.userEmail]: { role: "genesis", readonly: false, allowAttachments: true, forcePasswordChange: false }
        }
    };
}

/** INTERNAL FUNCTIONS **/
async function _onLoad() {

    //setLogLevel(INFO);
    //onlyLogLevels(INFO, TRACE);
    log("APP._onLoad", `called for [v${C.APP_VERSION}]`);

    //loadLogin();

    await setAuthData();
    loadVault("manager", JSON.parse(getVaultData()), { readOnly: false });

    logEl.setVisible(G.settings.showLogs === true);

    logEl.onClick(_doCopyToClipboardClick);

    window.addEventListener('focus', () => {
        if (G.driveLockState && !G.driveLockState.heartbeat) {
            log("APP.focus", "Tab focused - Attempting to restart stalled heartbeat...");

            if (!isValidSession) {
                warn("No valid session found, terminating lock status lost flow");
                return;
            }

            SV.tryAcquireEnvelopeWriteLock(); // This uses the new "Proactive" logic from earlier
        }
    });
}

function _deactivateAutoLogout() {
    log("vaultUI._deactivateAutoLogout", "called");

    _idleManager.events.forEach(evt => {
        document.removeEventListener(evt, _idleManager.boundHandler);
    });

    clearTimeout(_idleManager.timer);
    _idleManager.callback = null;
    _idleManager.boundHandler = null;
    _idleManager.lastReset = 0;
}

function _doCopyToClipboardClick() {
    copyToClipboard(logEl.innerText);
}

async function _releaseDriveLock() {
    log("AP._releaseDriveLock", "called");

    if (!G.driveLockState) return;

    // 1️⃣ Stop the heartbeat first so it doesn't try to tick during the release
    G.driveLockState.heartbeat?.stop();

    const { fileId, envelopeName, lock } = G.driveLockState;

    if (fileId && lock) {
        try {
            const cleared = {
                ...lock,
                expiresAt: new Date(0).toISOString(), // Kill the TTL on the server
                generation: (lock.generation || 0) + 1 // Increment to fence out late heartbeats
            };

            // 2️⃣ MUST AWAIT this to ensure the server actually receives the "Unlock"
            await SV.writeLockToDrive(cleared, fileId);
            log("AP._releaseDriveLock", "Drive lock explicitly expired on server");
        } catch (err) {
            warn("AP._releaseDriveLock", "Failed to release on server (network?), proceeding with local wipe", err);
        }
    }

    // 3️⃣ Finally, wipe local state
    G.driveLockState = null;
}

window.onload = async () => {
    await _onLoad();
    clearGlobals();
};
