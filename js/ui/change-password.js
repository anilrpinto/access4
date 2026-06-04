import { C, G, ID, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { vaultChangePwdUI } from '@/ui/loader.js';
import { rotatePrivateVaultPayloadKey } from '@/ui/private-vault.js';

// Central runtime marker tracking whether we are operating on the 'shared' or 'private' vault context
let _currentRotationContext = 'shared';

export async function showChangePasswordUI(context = 'shared') {

    _currentRotationContext = context;

    const screenKey = window.ScreenManager.CHANGE_PWD_SCREENKEY;
    window.ScreenManager.register(screenKey, vaultChangePwdUI.mainSection, {
        onShow: _load,
        onHide: _unload
    });

    window.ScreenManager.switchView(screenKey);
}

/** INTERNAL FUNCTIONS **/
async function _load() {
    log("change-pwd._load", `called for context: ${_currentRotationContext}`);

    if (vaultChangePwdUI.title) {
        vaultChangePwdUI.title.setText(_currentRotationContext === 'private' ? "Change Private Vault Password" : "Change Shared Vault Password");
    }

    _clearFields();
    _showStatus("", "info");

    vaultChangePwdUI.submitBtn.onClick((e) => _doSubmitClick());
    vaultChangePwdUI.cancelBtn.onClick((e) => _doCancelClick());
}

async function _unload() {
    log("change-pwd._unload", "called");
    _clearFields();
}

function _doCancelClick() {
    window.ScreenManager.goHome();
}

async function _doSubmitClick() {
    log("change-pwd._doSubmitClick", `Processing password rotation update for: ${_currentRotationContext}`);
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

        if (_currentRotationContext === 'shared') {
            // --- SHARED VAULT ROTATION ---
            await ID.updateIdentityPassword(oldPwd, newPwd);

            // Evict any out-of-date shared biometrics
            await BM.evictBiometricRecord('shared');
            log("change-pwd.submit", "Shared identity boundaries updated. Stale credentials evicted.");

            _showStatus("Shared Vault password updated successfully!", "success");
        } else {
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
            _showStatus("Password change staged! Click 'Save' on the main vault menu to commit changes to the cloud.", "success");
        }

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