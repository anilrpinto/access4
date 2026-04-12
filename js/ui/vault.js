import { C, G, LS, inReadOnlyMode, isValidSession, CR, AU, SV, AT, U, log, trace, debug, info, warn, error, isDebugEnabled } from '@/shared/exports.js';

import { activateIdleChecker, logout } from '@/app.js';

import { runFullBackup, runSharedVaultBackup, runPrivateVaultBackup } from '@/core/backup.js';
import { runSharedVaultCleanup, runPrivateVaultCleanup, runVaultAccessHousekeeping } from '@/core/janitor.js';

import { ScreenManager } from '@/ui/screen-manager.js'; // Do not delete, need for initialization!
import { swapVisibility, showSilentToast } from '@/ui/uihelper.js';
import { rootUI, vaultUI, vaultNavBarUI, vaultRawDataUI, copyLogsToClipboard, vaultMenuBar, vaultMenu } from '@/ui/loader.js';
import { showConfirmUI } from '@/ui/confirm.js';
import { showOverlayConfirmUI, showOverlayAlertUI, showOverlayPasswordUI, showOverlayChoiceUI } from '@/ui/modal.js';

import { generateFilterMap  } from '@/ui/search.js';

import { lockPrivateVault, isPrivateVaultUnlocked, savePrivateVaultData } from "@/ui/private-vault.js";
import { loadExplorer, renderVaultExplorer } from '@/ui/explorer.js';

let originalVaultData = null;
let vaultData = null;

// Add these to your existing declarations
let privateVaultData = null;         // The decrypted JSON
let originalPrivateVaultData = null; // For discarding changes
let isPrivateMode = false;           // UI Toggle state

let vaultClipboard = {
    mode: null,      // 'cut' (we can add 'copy' later if needed)
    items: [],       // We will store just the IDs here for simplicity
    sourceParentId: null
};

let sessionState = {
    path: ['root'],       // The navigation stack
    isEditable: false,    // Global toggle for Phase 5
    showSecure: false,     // Global toggle for Requirement 1
    isSelectionMode: false
};

let currentFilterMap = null;
let searchDebounceTimer = null;
let currentSearchQuery = null;

let pendingFileDeletions = [];  // Google Drive File IDs to DELETE on Save
let pendingFileUploads = [];   // Google Drive File IDs to DELETE on Discard/Logout

async function init() {
    log("vaultUI.init", "called");

    sessionState.path = ['root'];

    swapVisibility(rootUI.loginView, vaultUI.mainSection);

    vaultMenu.menuBtn.onClick((e) => {
        // 1. Prevent the 'window' or 'body' from seeing this click
        e.stopPropagation();
        vaultMenu.menuDropdown.classList.toggle('show-menu');
    });

    // Add this to your global window listener to see what's CLOSING it
    window.addEventListener('click', (e) => {
        if (vaultMenu.menuDropdown.classList.contains('show-menu')) {
            //log(`[Menu Debug] Window click detected on:`, e.target);
            vaultMenu.menuDropdown.classList.remove('show-menu');
        }
    });

    vaultMenu.saveMenu.onClick(doSaveClick);

    vaultMenu.rawDataMenu.onClick(doShowRawDataClick);
    vaultMenu.discardChangesMenu.onClick(doDiscardChangesClick);

    vaultMenu.usersMenu.onClick(doUsersClick);
    vaultMenu.syncAccessMenu.onClick(doSyncAccessClick);
    vaultMenu.runBackupMenu.onClick(doRunBackupClick);
    vaultMenu.recoveryRotationMenu.onClick(doRecoveryKeyRotationClick);

    vaultUI.title.onClick(doToggleSecureClick);
    vaultUI.toggleSecureBtn.onClick(doToggleSecureClick);

    vaultMenu.logoutMenu.onClick(doLogout);

    // temporary menu
    vaultMenu.copyLogsMenu.onClick(copyLogsToClipboard);
    vaultMenu.toggleLogsMenu.onClick(toggleLogs);

    // Ensure these containers always use flex when shown
    //vaultRawDataUI.mainSection.setFlex();
    //vaultUI.mainSection.setFlex();
}

/**
 * SWITCHES THE UI CONTEXT
 * Changes the "Source of Truth" for the Explorer and Breadcrumbs.
 */
export async function toggleVaultMode(mode) {
    log("vaultUI.toggleVaultMode", `Switching to: ${mode}`);

    isPrivateMode = (mode === 'private');

    // 1. Reset navigation to the root of the selected vault
    sessionState.path = ['root'];

    // 2. Update UI Branding (Visual cues are vital for security)
    if (isPrivateMode) {
        vaultUI.title.setText("🛡️ Private Vault");
        vaultUI.title.style.color = "#FFD700"; // Gold/Security Yellow
        showSilentToast("Switched to Private Mode", false);
    } else {
        vaultUI.title.setText("Vault");
        vaultUI.title.style.color = ""; // Default
        showSilentToast("Returned to Shared Vault", false);
    }

    refreshVault();
}

/**
 * Returns the currently active vault data based on view mode.
 */
export function getActiveVaultData() {
    return isPrivateMode ? privateVaultData : vaultData;
}

function setActiveVaultData(activeData) {
    if (isPrivateMode) privateVaultData = activeData;
    else vaultData = activeData;
}

async function doUsersClick() {
    log("vaultUI.doUsersClick", "Lazy loading module...");

    try {
        const { showUsersUI } = await import('@/ui/users.js');
        await showUsersUI();
    } catch (err) {
        error("vaultUI.doUsersClick", "Failed to load Users module:", err);
        showSilentToast("Error loading component", true);
    }
}

async function doRecoveryKeyRotationClick() {
    log("vaultUI.doRecoveryKeyRotationClick", "called");

    try {
        const { showRecoveryRotationUI } = await import('@/ui/recovery-rotation.js');
        await showRecoveryRotationUI();
    } catch (err) {
        error("vaultUI.doRecoveryKeyRotationClick", "Failed to load recovery rotation module:", err);
        showSilentToast("Error loading component", true);
    }
}

async function doShowRawDataClick() {
    log("vaultUI.doShowRawDataClick", "called");

    try {
        const { showRawDataUI } = await import('@/ui/raw-data-viewer.js');
        const getViewState = () => ({ data: getActiveVaultData(), isMasked: !sessionState.showSecure });
        await showRawDataUI(getViewState, (data) => setActiveVaultData(data));
    } catch (err) {
        error("vaultUI.doShowRawDataClick", "Failed to load raw data viewer module:", err);
        showSilentToast("Error loading component", true);
    }
}

async function doSyncAccessClick() {
    log("vaultUI.doSyncAccessClick", "called");
    showSilentToast("Consolidating vault access...");
    await runVaultAccessHousekeeping();
    showSilentToast("Sync complete!");
}

async function doRunBackupClick() {
    log("vaultUI.doRunBackupClick", "called");

    const hasPrivate = isPrivateVaultUnlocked();

    // 1. Shared Vault Password Prompt
    const pwd = await showOverlayPasswordUI({
        title: "Shared Vault Backup",
        message: "Enter your password for Shared Vault backup.",
        okText: hasPrivate ? "Continue" : "Run"
    });

    if (!pwd) return; // Opted out - canceled

    let privPwd = null;

    // 2. Conditional Private Vault Password Prompt
    // Only prompt if the private vault is initialized/unlocked in this session
    if (hasPrivate) {
        privPwd = await showOverlayPasswordUI({
            title: "Private Vault Backup",
            message: "Enter password to your Private vault",
            okText: "Run"
        });

        // Note: If they cancel HERE, we can still proceed with just Shared,
        // or return if you want "Full or Nothing".
        // Let's assume they want both if they started the flow.
        if (!privPwd) return;
    }

    try {
        // 3. Updated runFullBackup (Sequential Downloads)
        // Pass both passwords into the generalized orchestrator
        await runFullBackup(pwd, vaultData, privPwd, privateVaultData, () => {
            showSilentToast("Writing backup packages (ZIP+HTML+TXT) to local storage...");
            refreshCleanupPill();
        });

    } catch (err) {
        error("vaultUI.doRunBackupUI", "Error:" + err);
        showOverlayAlertUI({
            title: "Backup Failed",
            message: "Authentication failed. Please ensure the passwords typed are correct."
        });
    }
}

function doDiscardChangesClick() {
    showConfirmUI({
        title: "Discard Changes",
        message: "This will revert the vault to the last saved state. All current progress will be lost.",
        okText: "Discard",
        cancelText: "Keep Editing",
        onConfirm: () => {
            log("vaultUI.doDiscardChangesClick", "reverting...");

            // 1. REVERT THE DATA CHANGES
            vaultData = structuredClone(originalVaultData);

            // 2. Revert Private (if unlocked)
            if (privateVaultData) {
                privateVaultData = structuredClone(originalPrivateVaultData);
            }

            // 1. Capture the IDs and clear the array immediately to prevent double-processing
            const filesToNuke = [...pendingFileUploads];
            pendingFileUploads = [];

            // 3. Nuke the "Orphaned" Uploads from Drive
            if (filesToNuke.length > 0) {
                log("vaultUI", `Cleaning up ${filesToNuke.length} unsaved uploads...`);
                // Non-blocking but tracked
                Promise.all(filesToNuke.map(id =>
                    AT.deleteAttachmentFile(id).catch(err => error("DiscardCleanup", `Failed: ${id}`, err))
                )).then(() => {
                    log("vaultUI", "Background upload cleanup finished.");
                });
            }

            // 4. Clear the delete queue (They are back in the vault now)
            if (typeof pendingFileDeletions !== 'undefined') {
                log("vaultUI.doDiscardChangesClick", `Rescuing ${pendingFileDeletions.length} files from deletion queue.`);
                pendingFileDeletions = [];
            }

            // Reset UI state
            sessionState.path = ['root'];
            vaultClipboard.items = [];
            vaultClipboard.mode = null;
            sessionState.isSelectionMode = false;

            showStatusMessage("Reverted to last save.", "info");

            refreshVault();
        }
    });
}

function doLogout() {
    log("vaultUI.doLogout", "called");

    showStatusMessage("");
    doSecure();
    logout();
}

function doSecure() {

    log("vaultUI.doSecure", "called");

    // 1. Wipe the Data
    vaultData = null;
    originalVaultData = null;
    privateVaultData = null;
    originalPrivateVaultData = null;
    isPrivateMode = false;

    lockPrivateVault();

    vaultRawDataUI.textContent.clear();

    // 2. Wipe the Session State (Crucial!)
    sessionState.isEditable = false;
    sessionState.showSecure = false;
    sessionState.isSelectionMode = false;
    sessionState.path = ['root']; // Reset breadcrumbs to root

    vaultClipboard.mode = null;
    vaultClipboard.sourceParentId = null;
    vaultClipboard.items = [];

    // 3. Clear the DOM (Prevents seeing old data for a split second on re-login)
    vaultNavBarUI.breadcrumbs.clear();
    vaultUI.explorer.clear();

    // Use vaultUI.mainSection and not rootUI.vaultView as there's rendering issues in certain cases after log in
    swapVisibility(vaultUI.mainSection, rootUI.loginView);
}

async function showVaultUI({ readOnly = false } = {}) {
    log("vaultUI.showVaultUI", "called");

    if (readOnly) warn("vaultUI.showVaultUI", "Showing vault read-only mode");

    swapVisibility(rootUI.loginView, rootUI.vaultView);
    refreshVault(readOnly);
    activateIdleChecker();
}

async function doToggleSecureClick() {
    log("vaultUI.doToggleSecureClick", "called");

    // 1. Toggle the state
    sessionState.showSecure = !sessionState.showSecure;

    vaultUI.toggleSecureBtn.setText(sessionState.showSecure ? '🔓' : '🔒');

    // 3. Add a subtle color change to the title to bring further attention
    vaultUI.title.style.color = sessionState.showSecure ? '#dd0000' : '#000';

    // Ensure we start at home if the path got corrupted
    if (!sessionState.path || sessionState.path.length === 0) {
        sessionState.path = ['root'];
    }

    // 4. Re-render the explorer to apply state to all secure type fields
    renderVaultExplorer();

    const { refreshRawDataTree } = await import('@/ui/raw-data-viewer.js');
    refreshRawDataTree(getActiveVaultData(), !sessionState.showSecure);
}

async function doSaveClick() {
    log("vaultUI.doSaveClick", "Starting save process...");

    if (!vaultData || Object.keys(vaultData).length === 0) {
        warn("vaultUI.doSaveClick", "Vault data is empty or missing.");
        showStatusMessage("Nothing to save.", "error");
        return;
    }

    // Check for any changes across both vaults
    const changedShared = JSON.stringify(vaultData) !== JSON.stringify(originalVaultData);
    const changedPrivate = privateVaultData && (JSON.stringify(privateVaultData) !== JSON.stringify(originalPrivateVaultData));

    if (!changedShared && !changedPrivate && pendingFileDeletions.length === 0) {
        info("vaultUI.doSaveClick", "Vault has not changed since last save");
        showSilentToast("No new changes to save");
        showStatusMessage("Vault has not changed since last save", "info");
        return;
    }

    showStatusMessage("Encrypting and saving...", null);

    try {

        const saveTasks = [];

        // Task: Shared Vault
        if (changedShared) {
            saveTasks.push((async () => {
                await SV.encryptAndPersistPlaintext(JSON.stringify(vaultData), { onUpdate: updateLockStatusUI });
                originalVaultData = structuredClone(vaultData);
            })());
        }

        // Task: Private Vault
        if (changedPrivate) {
            saveTasks.push((async () => {
                await savePrivateVaultData(privateVaultData);
                originalPrivateVaultData = structuredClone(privateVaultData);
            })());
        }

        // 1. Wait for all JSON updates to finish
        await Promise.all(saveTasks);

        // 2. Commit Uploads: Now that JSONs are saved, these files are "Official"
        // We clear the list so we don't nuke them on a future Discard/Logout.
        pendingFileUploads = [];

        // 3. PHYSICAL CLEANUP: Run this only after the JSON is safely saved
        if (typeof pendingFileDeletions !== 'undefined' && pendingFileDeletions.length > 0) {

            info("vaultUI.doSaveClick", `Processing ${pendingFileDeletions.length} queued deletions...`);

            // We use allSettled so one 403 (Permission) doesn't stop the others
            const cleanupResults = await Promise.allSettled(pendingFileDeletions.map(id => AT.deleteAttachmentFile(id)));

            // Optional: Log any files that couldn't be trashed (e.g., owned by User A)
            cleanupResults.forEach((res, i) => {
                const fileId = pendingFileDeletions[i];

                if (res.status === 'rejected') {
                    // Use res.reason.message to see the actual text instead of {}
                    const reason = res.reason?.message || res.reason || "Unknown Error";
                    error("vaultUI.doSaveClick", `System Error deleting ${fileId}: ${reason}`);
                }
                else if (res.value === false) {
                    // This is the clean log you want!
                    log("vaultUI.doSaveClick", `Skipped ${fileId}: Ownership restriction (Handled).`);
                }
            });

            // IMPORTANT: Clear the queue so we don't try to delete them again on the next save
            pendingFileDeletions = [];
        }

        // 4. UI SUCCESS STATE
        showOverlayAlertUI({
            title: "Vault Saved",
            message: `Your changes (and deletions) have been applied successfully.`,
            okText: "OK",
            onConfirm: () => {
                refreshVault();
            }
        });
        showStatusMessage(`Last saved at ${U.getCurrentTime()}`, "success");

    } catch (err) {
        error("vaultUI.doSaveClick", "Save failed:", err);
        showOverlayAlertUI({ title: "Save Failed", message: err.message });
        showStatusMessage(`Save failed: ${err.message || err}`, "error");
        // Note: we do NOT clear pendingFileDeletions here so the user can try saving again
    }
}

function hasVaultChanges() {
    return (JSON.stringify(vaultData) !== JSON.stringify(originalVaultData)) ||
        (privateVaultData && JSON.stringify(privateVaultData) !== JSON.stringify(originalPrivateVaultData));
}

async function toggleLogs() {
    rootUI.log.toggleVisibility();
}

/*function updateMoveToolbar() {
    const count = vaultClipboard.items.length;

    if (sessionState.isSelectionMode && count > 0) {
        // Change the "Vault" title to show the count
        vaultUI.title.setText(`${count} selected`);
    } else {
        vaultUI.title.setText("Vault");

        // Put the normal Breadcrumbs back if nothing is selected
        renderBreadcrumbs();
    }
}*/

export async function handlePrivateVaultGenesis(result) {
    // 1. Update the local Main Envelope
    if (!vaultData.meta.extensions) vaultData.meta.extensions = { private_vaults: {} };

    vaultData.meta.extensions.private_vaults[result.emailHash] = result.pointer;

    // 2. Persist the Main Envelope immediately (so the pointer isn't lost)
    await doSaveClick();

    // 3. Set the Private state
    privateVaultData = result.data;
    originalPrivateVaultData = structuredClone(result.data);

    // 4. Switch View
    toggleVaultMode('private');
}

export async function handlePrivateVaultUnlock(pwd, data) {
    if (data) {
        privateVaultData = data;
        originalPrivateVaultData = structuredClone(privateVaultData);
    } else
        log("vaultUI.handlePrivateVaultUnlock", "accessing already unlocked private vault");

    showSilentToast("Private Vault Accessible");
    toggleVaultMode('private');

    runPrivateVaultBackup(pwd, privateVaultData, true, () => showSilentToast("Private vault backup successful"), () => showSilentToast("Private vault backup failed"));

    runPrivateVaultCleanup(privateVaultData).catch(err => {
        warn("vaultUI.doPrivateVaultClick", "Ignoring private vault cleanup failure (non-critical):", err);
    });
}

/**
 * Updates the visual theme of the vault based on read-only status.
 */
function applyReadOnlyTheme(readOnly) {
    log("vaultUI.applyReadOnlyTheme", "called readOnly:", readOnly);

    const mainHeader = vaultUI.header;
    const body = document.body;

    if (readOnly) {
        mainHeader.classList.add('vault-readonly-mode');
        body.classList.add('vault-frozen');

        // Add a "Read Only" text indicator if it doesn't exist
        if (!document.getElementById('readonly_indicator')) {
            const badge = document.createElement('span');
            badge.id = 'readonly_indicator';
            badge.className = 'readonly-badge';
            badge.innerText = 'READ ONLY';
            vaultUI.title.appendChild(badge);
        }
    } else {
        mainHeader.classList.remove('vault-readonly-mode');
        body.classList.remove('vault-frozen');

        const badge = document.getElementById('readonly_indicator');
        if (badge) badge.remove();
    }
}

export function refreshMoveMenu() {
    log("vaultUI.refreshMoveMenu", "called");

    const count = vaultClipboard.items.length;
    const isCutting = vaultClipboard.mode === 'cut';
    const isSelecting = sessionState.isSelectionMode;

    // --- SECTION 1: APP TITLE (vaultUI.title) ---
    if (isCutting) {
        vaultUI.title.setText(`${count} Ready to Move`);
        vaultUI.title.style.color = "#FF9800"; // Orange
    } else if (isSelecting) {
        vaultUI.title.setText(count > 0 ? `${count} Selected` : "Select Items...");
        vaultUI.title.style.color = "var(--primary-color)"; // Blue
    } else {
        // RESET: Bring the title back to its default state
        vaultUI.title.setText("Vault");
        vaultUI.title.style.color = "";
    }

    // --- SECTION 3: MENU VISIBILITY (Updated for UX) ---

    // 1. Only show 'Cut' if we are selecting AND not already in 'Cut' mode
    vaultMenu.cutMenu.setVisible(isSelecting && count > 0 && !isCutting);

    const inGroup = sessionState.path.length === 2;
    vaultMenu.pasteMenu.setVisible(isCutting && inGroup);

    // 2. Update the "Select Multiple" toggle text to handle 'Cancel Move'
    if (isSelecting || isCutting) {
        vaultMenu.selectMenu.setText("\u2800\u2800 Cancel " + (isCutting ? "Move" : "Selection"));
        vaultMenu.selectMenu.classList.add('active-mode-text');
    } else {
        vaultMenu.selectMenu.setText("\u2800\u2800 Select Multiple");
        vaultMenu.selectMenu.classList.remove('active-mode-text');
    }
}

function refreshAddRenDelMenubar() {
    // 1. Check Permissions (The Master Gate)
    const writeable = !inReadOnlyMode();

    // 2. Check Navigation Depth
    const depth = sessionState.path.length;

    // 3. Logic: What is physically possible at this depth?
    let canAdd = true;          // Possible at Root (Add Group) and Group (Add Item)
    let canRenameDelete = true; // Possible at Group and Item Detail

    if (depth === 1) {
        // At Root: No existing target to Rename or Delete
        canRenameDelete = false;
    } else if (depth === 3) {
        // At Item Detail: "Add" logic happens back in the Item List (Depth 2)
        canAdd = false;
    }

    // 4. Apply: Must be logically possible AND the vault must be writeable
    vaultMenuBar.addBtn.setVisible(canAdd && writeable);
    vaultMenuBar.renameBtn.setVisible(canRenameDelete && writeable);
    vaultMenuBar.deleteBtn.setVisible(canRenameDelete && writeable);

    //log("vaultUI.refreshAddRenDelBtnVisibility", `depth:${depth} add:${canAdd} renDel:${canRenameDelete} writeable:${writeable}`);
}

function refreshMainMenuItemsState(readOnly) {
    log("vaultUI.refreshMainMenuItemsState", "called");

    const visible = !readOnly;
    const genesis = AU.isGenesisUser();
    const admin = AU.isAdmin();

    // These only care about read-only/admin status, not depth
    vaultMenu.saveMenu.setVisible(visible);
    vaultMenu.toggleEditMenu.setVisible(visible);

    vaultMenu.rawDataMenu.setVisible(genesis || (visible && admin));

    vaultMenu.syncAccessMenu.setVisible(visible && admin);
    vaultMenu.runBackupMenu.setVisible(admin);
    vaultMenu.recoveryRotationMenu.setVisible(visible && admin);

    // moved out of refreshMenuUI as part of explorer.js refactor
    vaultMenu.privateVaultMenu.setText((isPrivateVaultUnlocked() && isPrivateMode ? "🔒 Close" : "🛡️ Open") + " Private Vault");
    vaultMenu.discardChangesMenu.setVisible(hasVaultChanges());

    // NOTE: addBtn, renameBtn, and deleteBtn are intentionally removed from here
    // as they are handled by the render loop.
}

/**
 * EXPORTED FUNCTIONS
 */
export async function loadVault(pwd, data, options) {
    log("vaultUI.loadVault", "called options:", JSON.stringify(options));

    // ✅ 1. WIPE THE SESSION STATE
    window.ScreenManager.reset();

    init();

    vaultData = data;
    originalVaultData = structuredClone(data);

    if (AU.isAdmin()) {
        const cb = () => refreshCleanupPill();
        runSharedVaultBackup(pwd, vaultData, true, cb, cb);
    }
    pwd = null;

    const vaultContext = () => ({
        activeData: getActiveVaultData(),
        path: sessionState.path,
        depth: sessionState.path.length,
        groupId: sessionState.path[1],
        itemId: sessionState.path[2],
        isSelectionMode: sessionState.isSelectionMode,
        isEditable: sessionState.isEditable,
        showSecure: sessionState.showSecure,
        isPrivateMode,
        currentFilterMap,
        currentSearchQuery,
        vaultClipboard,
        atRoot: () => sessionState.path.length === 1 && sessionState.path[0] === 'root',
        navigateToRoot: () => { sessionState.path = ['root']; },
        hasPrivateVaultData: () => !!privateVaultData,
        privateDataPointer: (emailHash) => vaultData.meta.extensions?.private_vaults?.[emailHash],
        toggleShowSecure: () => {
            sessionState.showSecure = !sessionState.showSecure;
            refreshVault();
        },
        toggleEditable: () => {
            sessionState.isEditable = !sessionState.isEditable;
            refreshVault();
        },
        onNavigate: (id) => {
            sessionState.path.push(id);
            refreshVault();
        },
        onAttachmentDelete: (fileId) => {
            pendingFileDeletions.push(fileId);
            log("vault.handleDelete", `Added ${fileId} to pending deletes.`);
        },
        onAttachmentUpload: (fileId) => {
            pendingFileUploads.push(fileId);
            log("vaultUI.handleUploadAttachment", `Tracking new file for discard-safety: ${fileId}`);
        },
        refresh: () => {
            refreshVault();
        },
        refreshMenu: () => {
            refreshVault();
        },
        cancelMove: () => {
            sessionState.isSelectionMode = false;
            vaultClipboard.mode = null;
            vaultClipboard.items = []; // This clears the array, so the CSS class will drop
            vaultClipboard.sourceParentId = null;
            showStatusMessage("Move cancelled", "info");
        },
        setSelectionMode: (bool) => { sessionState.isSelectionMode = bool; },
    });

    await loadExplorer(vaultContext, async () => {
        log("vaultUI.loadExplorer", "Refreshing vault data from Drive...");

        // 1. Create a fresh copy of all original options
        // 2. Overwrite 'readOnly' with the ACTUAL current status
        const currentContext = {
            ...options,
            readOnly: inReadOnlyMode()
        };

        // Now 'currentContext' has all the original properties
        // (theme, language, flags, etc.) but the CORRECT read-only status.
        await showVaultUI(currentContext);
    });

    setTimeout(async () => runSharedVaultCleanup(vaultData), 5000); // 5-second delay to prioritize the initial UI render
}

export function resetToRoot() {
    sessionState.path = ['root'];
    refreshVault();
}

export function navigateToPath(index) {
    sessionState.path = sessionState.path.slice(0, index);
    refreshVault();
}

export function refreshVault(readOnly = false) {
    log("vaultUI.refreshVault", "called");

    if (readOnly)
        warn("vaultUI.refreshVault", "Read-Only mode, app will be limited to view info only!");

    vaultUI.title.classList.value = AU.isGenesisUser() ? 'genesis-user' : AU.isAdmin() ? 'admin-user' : 'member-user';

    refreshMoveMenu();

    // 3. Update the Action Bar (Add/Rename/Delete logic)
    refreshAddRenDelMenubar();

    // 4. Full Re-render
    renderVaultExplorer();
    refreshMainMenuItemsState(readOnly);
    applyReadOnlyTheme(readOnly);

    vaultRawDataUI.textContent.setReadOnly(readOnly || !AU.isGenesisUser());
}

/**
 * Triggered by the Input Event on the search bar
 */
export function handleSearchInput(query) {
    currentSearchQuery = query;
    clearTimeout(searchDebounceTimer);

    searchDebounceTimer = setTimeout(() => {
        // 💡 CRITICAL: If query is empty, reset to null
        if (!query || query.trim() === "") {
            currentFilterMap = null;
        } else {
            currentFilterMap = generateFilterMap(getActiveVaultData(), query);
        }

        // FORCE HOME: Reset the navigation path to the root
        // This ensures the user sees the top-level filtered groups immediately.
        sessionState.path = ['root'];

        // Re-run the existing master render flow
        renderVaultExplorer();

        // Log for your debugging
        log("vaultUI.handleSearchInput", `[Search] Query: "${query}" | Map Active: ${!!currentFilterMap}`);
    }, 150);
}

export function refreshCleanupPill() {
    log("vaultUI.refreshCleanupPill", "called");

    const count = parseInt(LS.get(C.BACKUP_CLEANUP_COUNTER_KEY) || 0);
    const header = vaultUI.headerRightSide;
    if (!header) return;

    let pill = document.getElementById('admin_cleanup_pill');

    if (count >= 2) {
        if (!pill) {
            pill = document.createElement('div');
            pill.id = 'admin_cleanup_pill';
            pill.className = 'admin-cleanup-pill';

            // prepend() puts it at the start of the right-side actions
            header.prepend(pill);
        }

        pill.innerHTML = `<span class="icon">⚠️</span> <span>${count}</span>`;
        pill.title = `${count} backups generated. Click to acknowledge.`;

        pill.onclick = () => {
            showOverlayConfirmUI({
                title: "Storage Cleanup",
                message: `You have <b>${count}</b> backup bundles saved on this device. Clear from storage manually and click <b>Cleared</b>.`,
                okText: "Cleared",
                onConfirm: () => {
                    LS.set(C.BACKUP_CLEANUP_COUNTER_KEY, 0);
                    pill.remove();
                    showSilentToast("Storage tracking counter reset.");
                }
            });
        };
    } else if (pill) {
        pill.remove();
    }
}

export function handleDriveLockLost(info) {
    warn("SV.handleDriveLockLost", "Reason:", info?.reason || "Timed out");

    if (!isValidSession) {
        warn("No valid session found, terminating lock status lost flow");
        return;
    }

    const wasWriteMode = G.driveLockState?.mode === "write";

    refreshVault(wasWriteMode);

    if (G.driveLockState?.heartbeat?.stop) {
        G.driveLockState.heartbeat.stop();
    }

    G.driveLockState = null;
    updateLockStatusUI("Lock lost!");

    showOverlayChoiceUI({
        title: "Write lock lost",
        message: `Exclusive lock over vault data has been lost. Vault set to read-only mode. 'Re-acquire' to save changes`,
        okText: "Re-acquire",
        cancelText: "Read-only",
        onConfirm: async () => {
            try {
                log("UI.lockLost", "User requested re-acquisition...");
                await SV.acquireDriveWriteLock();

                // Success! The heartbeat is back, UI stays in write mode.
                showSilentToast("Lock re-acquired successfully, save your changes first");
                refreshVault(false);
            } catch (err) {
                error("UI.lockLost", "Re-acquisition failed:", err.message);
                showSilentToast("Failed to re-acquire lock, downgrading to read-only mode");
                refreshVault(true);
            }
        },
        onCancel: async () => {
            showSilentToast("Continuing in read only mode");
            refreshVault(true);
        }
    });
}

export function updateLockStatusUI(msg = "") {
    //trace("vaultUI.updateLockStatusUI", "G.driveLockState.mode:", G.driveLockState ? G.driveLockState.mode : null);

    if (!G.driveLockState) return;

    const { expiresAt } = G.driveLockState.lock;
    //trace("updateLockStatusUI", `You hold the envelope lock (expires ${expiresAt})`);
    showStatusMessage(`Vault lock expires at ${U.asLocalTime(expiresAt)}`, null)
}

export function showStatusMessage(msg, type = "error") {
    if (!vaultUI.statusMsg) return;

    vaultUI.statusMsg.textContent = msg;
    vaultUI.statusMsg.className = `status-message ${type}`;
}
