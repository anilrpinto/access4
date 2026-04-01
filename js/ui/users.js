import { G, GD, inReadOnlyMode, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { ScreenManager } from '@/ui/screen-manager.js';
import { showSilentToast } from '@/ui/uihelper.js';
import { vaultUsersUI, vaultMenu } from '@/ui/loader.js';

let originalAuthSnapshot = null; // To track changes

async function unload() {
    log("users.unload", "called");

    const currentAuthSnapshot = JSON.stringify(G.auth);

    if (currentAuthSnapshot !== originalAuthSnapshot) {
        if (!confirm("You have unsaved changes. Discard them?")) {
            return false; // ✋ Veto! ScreenManager stops here.
        }
        // User said OK to discard: Revert G.auth so it's not "dirty"
        G.auth = JSON.parse(originalAuthSnapshot);
    }

    // --- UI CLEANUP ---
    // Hide sub-elements so they are fresh for the next time the screen is opened
    vaultUsersUI.formFields.setVisible(false);
    vaultUsersUI.userSelect.value = ""; // Clear selection

    return true; // ✅ Proceed with the switch
}

async function load() {
    log("users.load", "called");

    // Capture the state before any edits happen
    originalAuthSnapshot = JSON.stringify(G.auth);

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

    select.onchange = selectUser;

    // Attach "Live Update" listeners to all form fields
    vaultUsersUI.formFields.onchange = (e) => {
        log("users.load.onchange", "Field change detected via delegation");
        updateLocalMemberState();
    };

    vaultUsersUI.closeBtn.onClick(exitUsersUI);
    vaultUsersUI.cancelBtn.onClick(exitUsersUI);
    vaultUsersUI.saveBtn.onClick(save);
    vaultUsersUI.removeBtn.onClick(remove);
}

function updateLocalMemberState() {
    const email = vaultUsersUI.userSelect.value;
    if (!email) return;

    log("users.updateLocalMemberState", `Drafting changes for ${email}`);

    G.auth.members[email] = {
        ...G.auth.members[email], // Preserve existing fields like 'added' or 'id'
        role: vaultUsersUI.roleSelect.value,
        readonly: vaultUsersUI.readonlyCheck.checked,
        allowAttachments: vaultUsersUI.attachmentsCheck.checked,
        forcePasswordChange: vaultUsersUI.forcePwdCheck.checked
    };
}

async function exitUsersUI() {
    log("users.exitUsersUI", "Requesting return to explorer");

    // The ScreenManager will run 'unload' before this happens.
    // If 'unload' returns false, this switch will never complete.
    window.ScreenManager.goHome();
}

function selectUser() {
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

async function save() {
    const email = vaultUsersUI.userSelect.value;
    // We don't need to manually update G.auth here anymore,
    // because updateLocalMemberState did it live!

    try {
        await persistUserChanges();

        // Update the snapshot so we can exit without a prompt
        originalAuthSnapshot = JSON.stringify(G.auth);

        showSilentToast(`All changes saved to Drive`);
    } catch (e) {
        error("users.save", e);
        showSilentToast("Failed to save changes", true);
    }
}

async function remove() {
    const email = vaultUsersUI.userSelect.value;
    if (!confirm(`Are you sure you want to revoke all access for ${email}?`)) return;

    try {
        delete G.auth.members[email];
        await persistUserChanges();

        // ✅ ADD THIS: Reset the snapshot so the exit guard knows we are "clean"
        originalAuthSnapshot = JSON.stringify(G.auth);

        showSilentToast(`${email} removed from vault`);
        showUsersUI(); // Refresh list
    } catch (e) {
        error("users.remove", e);
    }
}

/**
 * Helper to handle the "Heavy Lifting" of saving to Drive
 */
async function persistUserChanges() {
    log("users.persistUserChanges", "Pushing registry updates to Drive...");

    G.auth.modified = new Date().toISOString();
    await GD.drivePatchJsonFile(localStorage.getItem('cache_auth_file_id'), G.auth);

    log("users.persistUserChanges", "authorized.json updated successfully.");
}

/**
 * EXPORTED FUNCTIONS
 */
export async function showUsersUI() {
    const screenKey = window.ScreenManager.USERS_SCREENKEY;
    window.ScreenManager.register(screenKey, vaultUsersUI.mainSection, {
        onShow: load,
        onHide: unload
    });

    window.ScreenManager.switchView(screenKey);
}