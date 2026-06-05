import { C, G, ID, BM, CR, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { vaultChangePwdUI } from '@/ui/loader.js';
import { rotatePrivateVaultPayloadKey } from '@/ui/private-vault.js';
import { showOverlayAlertUI } from '@/ui/modal.js';

export async function showChangePasswordUI() {

    const screenKey = window.ScreenManager.CHANGE_PWD_SCREENKEY;
    window.ScreenManager.register(screenKey, vaultChangePwdUI.mainSection, {
        onShow: _load,
        onHide: _unload
    });

    window.ScreenManager.switchView(screenKey);
}

/** INTERNAL FUNCTIONS **/
async function _load() {
    const { isPrivateMode } = G.vaultContext();
    log("change-pwd._load", "called isPrivateMode:", isPrivateMode);

    //if (vaultChangePwdUI.title) vaultChangePwdUI.title.setText(`Change ${isPrivateMode ? "Private" : "Shared"} vault password`);

    _clearFields();
    _showStatus("", "info");

    vaultChangePwdUI.submitBtn.setText(`Change ${isPrivateMode ? "Private" : "Shared"} password`);

    vaultChangePwdUI.submitBtn.onClick((e) => _doSubmitClick(isPrivateMode));
    vaultChangePwdUI.cancelBtn.onClick((e) => _doCancelClick());
}

async function _unload() {
    log("change-pwd._unload", "called");
    _clearFields();
}

function _doCancelClick() {
    window.ScreenManager.goHome();
}

async function _doSubmitClick(isPrivateMode) {
    log("change-pwd._doSubmitClick", "called - isPrivateMode", isPrivateMode);
    _showStatus(""); // Flush display canvas

    const oldPwd = vaultChangePwdUI.currentInput.value;
    const newPwd = vaultChangePwdUI.newInput.value;
    const confirmPwd = vaultChangePwdUI.confirmNewInput.value;

    // ────────────────────────────────────────────────────────
    // DATA VALIDATION MATRICES (Mirrors login.js rules explicitly)
    // ────────────────────────────────────────────────────────
    if (!oldPwd || !newPwd || !confirmPwd) {
        _showStatus("All fields are required.", "error");
        return;
    }

    if (newPwd.length < C.PASSWORD_MIN_LEN) {
        _showStatus(`New password is too weak. Minimum length is ${C.PASSWORD_MIN_LEN} characters.`, "error");
        return;
    }

    if (newPwd !== confirmPwd) {
        _showStatus("New passwords do not match.", "error");
        return;
    }

    if (oldPwd === newPwd) {
        _showStatus("New password must be different from your current password.", "error");
        return;
    }

    // Toggle button visibility to mitigate race conditions
    vaultChangePwdUI.submitBtn.setEnabled(false);

    try {

        let msg;

        if (isPrivateMode) {
            // --- PRIVATE VAULT ROTATION ---
            log("change-pwd.submit", "Staging Private Vault password updates...");

            const emailHash = await CR.hashString(G.userEmail);

            const currentContext = G.vaultContext();
            const activePointer = currentContext.privateDataPointer(emailHash);

            if (!activePointer) {
                throw new Error("Unable to locate an operational Private Vault initialization pointer.");
            }

            // 1. Re-key memory references and retrieve the fresh pointer string
            const { freshPointerBlob } = await rotatePrivateVaultPayloadKey(
                oldPwd,
                newPwd,
                activePointer,
                emailHash
            );

            // 2. Inject the fresh pointer back into the Shared Envelope memory space
            currentContext.updatePrivateVaultPointer(emailHash, freshPointerBlob);

            // 3. Notify the user that their changes are staged
            msg = "Private vault password change will only take effect after vault changes are saved";
        } else {
            // --- SHARED VAULT ROTATION ---
            await ID.updateIdentityPassword(oldPwd, newPwd);

            // Evict any out-of-date shared biometrics
            await BM.evictBiometricRecord('shared');
            log("change-pwd.submit", "Shared identity boundaries updated. Stale credentials evicted.");

            msg = "Shared Vault password has been changed";
        }

        if (msg) showOverlayAlertUI({ title: "Note", message: msg });

        window.ScreenManager.goHome();
    } catch (err) {
        error("change-pwd.submit", "Rotation pipeline failed execution:", err);
        _showStatus(err.message, "error");
    } finally {
        // Re-enable the submit button so the user can try again if a field validation fails
        if (vaultChangePwdUI.submitBtn) {
            vaultChangePwdUI.submitBtn.setEnabled(true);
        }
    }
}

function _clearFields() {
    if (vaultChangePwdUI.currentInput) vaultChangePwdUI.currentInput.clear();
    if (vaultChangePwdUI.newInput) vaultChangePwdUI.newInput.clear();
    if (vaultChangePwdUI.confirmNewInput) vaultChangePwdUI.confirmNewInput.clear();
}

function _showStatus(msg, type = "error") {
    if (!vaultChangePwdUI.statusMsg) return;
    vaultChangePwdUI.statusMsg.setText(msg);
    vaultChangePwdUI.statusMsg.className = `status-message ${type}`;
}