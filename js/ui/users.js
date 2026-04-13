import { C, G, LS, GD, inReadOnlyMode, log, trace, debug, info, warn, error } from '@/shared/exports.js';
import { showSilentToast } from '@/ui/uihelper.js';
import { vaultUsersUI } from '@/ui/loader.js';

let _originalAuthSnapshot = null; // To track changes

export async function showUsersUI() {
    const screenKey = window.ScreenManager.USERS_SCREENKEY;
    window.ScreenManager.register(screenKey, vaultUsersUI.mainSection, {
        onShow: _load,
        onHide: _unload
    });

    window.ScreenManager.switchView(screenKey);
}

/** INTERNAL FUNCTIONS **/
async function _load() {
    log("users._load", "called");

    // Capture the state before any edits happen
    _originalAuthSnapshot = JSON.stringify(G.auth);

    //swapVisibility(vaultUI.mainSection, vaultUsersUI.mainSection);

    // --- READ-ONLY GUARD FOR BUTTONS ---
    if (inReadOnlyMode()) {
        vaultUsersUI.saveBtn.setVisible(false);
        vaultUsersUI.removeBtn.setVisible(false);
        // Maybe change the header text to indicate Audit Mode
        vaultUsersUI.title.setText("Member Administration (Read-Only)");
    } else {
        vaultUsersUI.saveBtn.setVisible(true);
        vaultUsersUI.removeBtn.setVisible(true);
    }

    const select = vaultUsersUI.userSelect;

    // Clear and Fill the dropdown from G.auth.members
    select.innerHTML = '<option value="">-- Choose a member --</option>';
    Object.keys(G.auth.members).forEach(email => {

        const user = G.auth.members[email];
        const isGenesis = user.role === "genesis";
        const isSelf = email === G.userEmail;

        // Hide Genesis from editing to prevent self-lockout
        if (!isGenesis && !isSelf) {
            const opt = document.createElement('option');
            opt.value = email;
            opt.textContent = email;
            select.appendChild(opt);
        }
    });

    select.onchange = _selectUser;

    // Attach "Live Update" listeners to all form fields
    vaultUsersUI.formFields.onchange = (e) => {
        log("users._load.onchange", "Field change detected via delegation");
        _updateLocalMemberState();
    };

    vaultUsersUI.closeBtn.onClick(_exitUsersUI);
    vaultUsersUI.cancelBtn.onClick(_exitUsersUI);
    vaultUsersUI.saveBtn.onClick(_save);
    vaultUsersUI.removeBtn.onClick(_remove);
}

async function _unload() {
    log("users._unload", "called");

    const currentAuthSnapshot = JSON.stringify(G.auth);

    if (currentAuthSnapshot !== _originalAuthSnapshot) {
        if (!confirm("You have unsaved changes. Discard them?")) {
            return false;
        }
        // User said OK to discard: Revert G.auth so it's not "dirty"
        G.auth = JSON.parse(_originalAuthSnapshot);
    }

    // --- UI CLEANUP ---
    // Hide sub-elements so they are fresh for the next time the screen is opened
    vaultUsersUI.formFields.setVisible(false);
    vaultUsersUI.userSelect.value = ""; // Clear selection

    return true; // ✅ Proceed with the switch
}

function _updateLocalMemberState() {
    const email = vaultUsersUI.userSelect.value;
    if (!email) return;

    log("users._updateLocalMemberState", `Drafting changes for ${email}`);

    G.auth.members[email] = {
        ...G.auth.members[email], // Preserve existing fields like 'added' or 'id'
        role: vaultUsersUI.roleSelect.value,
        readonly: vaultUsersUI.readonlyCheck.checked,
        allowAttachments: vaultUsersUI.attachmentsCheck.checked,
        forcePasswordChange: vaultUsersUI.forcePwdCheck.checked
    };
}

async function _exitUsersUI() {
    log("users._exitUsersUI", "Requesting return to explorer");

    // The ScreenManager will run '_unload' before this happens.
    // If '_unload' returns false, this switch will never complete.
    window.ScreenManager.goHome();
}

function _selectUser() {
    const email = vaultUsersUI.userSelect.value;
    const form = vaultUsersUI.formFields;

    if (!email) {
        form.setVisible(false);
        return;
    }

    const user = G.auth.members[email];
    form.setFlex().setVisible(true);

    // Load the Booleans
    vaultUsersUI.roleSelect.value = user.role || 'member';
    vaultUsersUI.readonlyCheck.checked = !!user.readonly;
    vaultUsersUI.attachmentsCheck.checked = !!user.allowAttachments;
    vaultUsersUI.forcePwdCheck.checked = !!user.forcePasswordChange;

    // --- READ-ONLY GUARD FOR INPUTS ---
    const isLocked = !!inReadOnlyMode();

    // Using your .setEnabled() helper!
    vaultUsersUI.roleSelect.setEnabled(!isLocked);
    vaultUsersUI.readonlyCheck.setEnabled(!isLocked);
    vaultUsersUI.attachmentsCheck.setEnabled(!isLocked);
    vaultUsersUI.forcePwdCheck.setEnabled(!isLocked);
}

async function _save() {
    const email = vaultUsersUI.userSelect.value;
    // We don't need to manually update G.auth here anymore,
    // because _updateLocalMemberState did it live!

    try {
        await _persistUserChanges();

        // Update the snapshot so we can exit without a prompt
        _originalAuthSnapshot = JSON.stringify(G.auth);

        showSilentToast(`All changes saved to Drive`);
    } catch (e) {
        error("users._save", e);
        showSilentToast("Failed to _save changes", true);
    }
}

async function _remove() {
    const email = vaultUsersUI.userSelect.value;
    if (!confirm(`Are you sure you want to revoke all access for ${email}?`)) return;

    try {
        delete G.auth.members[email];
        await _persistUserChanges();

        // ✅ ADD THIS: Reset the snapshot so the exit guard knows we are "clean"
        _originalAuthSnapshot = JSON.stringify(G.auth);

        showSilentToast(`${email} removed from vault`);
        showUsersUI(); // Refresh list
    } catch (e) {
        error("users._remove", e);
    }
}

/**
 * Helper to handle the "Heavy Lifting" of saving to Drive
 */
async function _persistUserChanges() {
    log("users._persistUserChanges", "Pushing registry updates to Drive...");

    G.auth.modified = new Date().toISOString();
    await GD.drivePatchJsonFile(LS.get(C.AUTH_FILE_ID_CACHE), G.auth);

    log("users._persistUserChanges", "authorized.json updated successfully.");
}
