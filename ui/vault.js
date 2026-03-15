import { C, G, AU, E, U, log, trace, debug, info, warn, error } from '../exports.js';

import { logout } from '../app.js';
import { loadUI } from './uihelper.js';

import { rootUI, vaultUI, copyLogsToClipboard } from './loader.js';
import { showRecoveryRotationUI } from './recovery-rotation.js';

let idleTimer;
let idleCallback = null;

const idleEvents = ['mousedown', 'mousemove', 'keydown', 'keypress', 'click', 'scroll', 'touchstart'];

const resetTimer = () => {
    clearTimeout(idleTimer);

    if (!idleCallback) return;

    idleTimer = setTimeout(async () => {
        if (typeof idleCallback === 'function') {
            await idleCallback('idle.timeout');
        }
    }, C.IDLE_TIMEOUT_MS);
};

async function loadVault() {
    log("vaultUI.loadVault", "called");

    vaultUI.logoutMenu.onClick(() => logout());

    // Toggle menu visibility
    vaultUI.menuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        vaultUI.menuDropdown.classList.toggle('show-menu');
    });

    // Close menu if user clicks anywhere else on the screen
    window.addEventListener('click', () => {
        if (vaultUI.menuDropdown.classList.contains('show-menu')) {
            vaultUI.menuDropdown.classList.remove('show-menu');
        }
    });

    vaultUI.saveMenu.onClick(doSaveClick);
    vaultUI.copyLogsMenu.onClick(copyLogsToClipboard);
    vaultUI.toggleLogsMenu.onClick(toggleLogs);
}

async function doSaveClick() {
    log("vaultUI.doSaveClick", "called");
    showStatusMessage("Saving...", null);

    const text = vaultUI.data.value;
    if (!text) {
        warn("vaultUIdoSaveClick] Nothing to encrypt");
        return;
    }

    try {
        await E.encryptAndPersistPlaintext(text, { onUpdate: updateLockStatusUI });
        showStatusMessage(`Saved changes at ${U.getCurrentTime()}`, "success");
        //vaultUI.data.value = "";
    } catch (err) {
        error("vaultUI.doSaveClick", "Encryption failed:" + err);
        showStatusMessage("Error while saving" + err, "error");
    }
    //alert("Saved!");
}

async function toggleLogs() {
    rootUI.log.toggleVisibility();
}

/**
 * EXPORTED FUNCTIONS
 */
export function showVaultUI({ readOnly = false, onIdle = () => { logout() } } = {}) {

    log("vaultUI.showVaultUI", "called");

    loadVault();

    // Hide login section
    rootUI.loginView.setVisible(false);

    if (AU.isAdmin()) {
        vaultUI.recoveryRotationMenu.setVisible(true);
        vaultUI.recoveryRotationMenu.onClick(showRecoveryRotationUI);
        vaultUI.toggleLogsMenu.setVisible(true);
    } else {
        warn("vaultUI.showVaultUI", "Recovery option turned off for non-admin user");
        vaultUI.recoveryRotationMenu.setVisible(false);
    }

    // Show main unlocked view
    rootUI.vaultView.setVisible(true);

    // Update UI for read-only mode
    if (readOnly) {
        warn("vaultUI.showVaultUI", "Unlocked UI in read-only mode: disabling save button");
        vaultUI.saveMenu.setEnabled(false);
        vaultUI.data.readOnly = true;
        rootUI.vaultTitle.setText("Unlocked (Read-only)");
    } else {
        vaultUI.saveMenu.setEnabled(true);
        vaultUI.data.readOnly = false;
        rootUI.vaultTitle.setText("Unlocked");
    }

    // Events that "wake up" the timer
    // Clean up old listeners to prevent memory leaks/duplicate triggers
    idleEvents.forEach(evt => {
        document.removeEventListener(evt, resetTimer);
        document.addEventListener(evt, resetTimer, { passive: true });
    });

    idleCallback = onIdle;
    resetTimer();
}

export function stopVaultIdleCheck() {

    log("vaultUI.stopVaultIdleCheck", "called");

    idleEvents.forEach(evt => {
        document.removeEventListener(evt, resetTimer);
    });

    clearTimeout(idleTimer);
    idleCallback = null;
}

export function updateLockStatusUI() {
    if (!G.driveLockState) return;

    const { expiresAt } = G.driveLockState.lock;
    //trace("updateLockStatusUI", `You hold the envelope lock (expires ${expiresAt})`);
    //showStatusMessage(`Vault lock expires at ${expiresAt}`, null)
}

export function showStatusMessage(msg, type = "error") {
    if (!vaultUI.statusMsg) return;

    vaultUI.statusMsg.textContent = msg;
    vaultUI.statusMsg.className = `status-message ${type}`;
}


/*function createNewVault() {
    return {
        meta: {
            version: "1.0",
            created: new Date().toISOString(),
            lastModified: new Date().toISOString(),
        },
        groups: [
            {
                id: crypto.randomUUID(), // Unique ID
                name: "General",
                items: []
            }
        ]
    };
}*/