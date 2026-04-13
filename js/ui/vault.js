import { C, G, LS, inReadOnlyMode, isValidSession, CR, AU, SV, AT, U, log, trace, debug, info, warn, error, isDebugEnabled } from '@/shared/exports.js';
import { ScreenManager } from '@/ui/screen-manager.js'; // Do not delete, need for initialization!
import { runFullBackup, runSharedVaultBackup, runPrivateVaultBackup } from '@/core/backup.js';
import { runSharedVaultCleanup, runPrivateVaultCleanup, runVaultAccessHousekeeping } from '@/core/janitor.js';
import { activateIdleChecker, logout } from '@/app.js';
import { swapVisibility, showSilentToast } from '@/ui/uihelper.js';
import { rootUI, vaultUI, vaultNavBarUI, vaultRawDataUI, copyLogsToClipboard, vaultMenuBar, vaultMenu } from '@/ui/loader.js';
import { showConfirmUI } from '@/ui/confirm.js';
import { showOverlayConfirmUI, showOverlayAlertUI, showOverlayPasswordUI, showOverlayChoiceUI } from '@/ui/modal.js';
import { generateFilterMap  } from '@/ui/search.js';
import { lockPrivateVault, isPrivateVaultUnlocked, savePrivateVaultData } from "@/ui/private-vault.js";
import { loadExplorer, renderVaultExplorer } from '@/ui/explorer.js';

let _originalVaultData = null;
let _vaultData = null;
let _privateVaultData = null;         // The decrypted JSON
let _originalPrivateVaultData = null; // For discarding changes
let _isPrivateMode = false;           // UI Toggle state
let _currentFilterMap = null;
let _searchDebounceTimer = null;
let _currentSearchQuery = null;
let _pendingFileDeletions = [];  // Google Drive File IDs to DELETE on Save
let _pendingFileUploads = [];   // Google Drive File IDs to DELETE on Discard/Logout

let _vaultClipboard = {
    mode: null,      // 'cut' (we can add 'copy' later if needed)
    items: [],       // We will store just the IDs here for simplicity
    sourceParentId: null
};

let _sessionState = {
    path: ['root'],       // The navigation stack
    isEditable: false,    // Global toggle for Phase 5
    showSecure: false,     // Global toggle for Requirement 1
    isSelectionMode: false
};

export async function loadVault(pwd, data, options) {
    log("vaultUI.loadVault", "called options:", JSON.stringify(options));

    // ✅ 1. WIPE THE SESSION STATE
    window.ScreenManager.reset();

    _init();

    _vaultData = data;
    _originalVaultData = structuredClone(data);

    if (AU.isAdmin()) {
        const cb = () => refreshCleanupPill();
        runSharedVaultBackup(pwd, _vaultData, true, cb, cb);
    }
    pwd = null;

    const vaultContext = () => ({
        activeData: getActiveVaultData(),
        path: _sessionState.path,
        depth: _sessionState.path.length,
        groupId: _sessionState.path[1],
        itemId: _sessionState.path[2],
        isSelectionMode: _sessionState.isSelectionMode,
        isEditable: _sessionState.isEditable,
        showSecure: _sessionState.showSecure,
        isPrivateMode: _isPrivateMode,
        currentFilterMap: _currentFilterMap,
        currentSearchQuery: _currentSearchQuery,
        vaultClipboard: _vaultClipboard,
        atRoot: () => _sessionState.path.length === 1 && _sessionState.path[0] === 'root',
        navigateToRoot: () => { _sessionState.path = ['root']; },
        hasPrivateVaultData: () => !!_privateVaultData,
        privateDataPointer: (emailHash) => _vaultData.meta.extensions?.private_vaults?.[emailHash],
        toggleShowSecure: () => {
            _sessionState.showSecure = !_sessionState.showSecure;
            refreshVault();
        },
        toggleEditable: () => {
            _sessionState.isEditable = !_sessionState.isEditable;
            refreshVault();
        },
        onNavigate: (id) => {
            _sessionState.path.push(id);
            refreshVault();
        },
        onAttachmentDelete: (fileId) => {
            _pendingFileDeletions.push(fileId);
            log("vault.handleDelete", `Added ${fileId} to pending deletes.`);
        },
        onAttachmentUpload: (fileId) => {
            _pendingFileUploads.push(fileId);
            log("vaultUI.handleUploadAttachment", `Tracking new file for discard-safety: ${fileId}`);
        },
        refresh: () => {
            refreshVault();
        },
        refreshMenu: () => {
            refreshVault();
        },
        cancelMove: () => {
            _sessionState.isSelectionMode = false;
            _vaultClipboard.mode = null;
            _vaultClipboard.items = []; // This clears the array, so the CSS class will drop
            _vaultClipboard.sourceParentId = null;
            showStatusMessage("Move cancelled", "info");
        },
        setSelectionMode: (bool) => { _sessionState.isSelectionMode = bool; },
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
        await _showVaultUI(currentContext);
    });

    setTimeout(async () => runSharedVaultCleanup(_vaultData), 5000); // 5-second delay to prioritize the initial UI render
}

/**
 * SWITCHES THE UI CONTEXT
 * Changes the "Source of Truth" for the Explorer and Breadcrumbs.
 */
export async function toggleVaultMode(mode) {
    log("vaultUI.toggleVaultMode", `Switching to: ${mode}`);

    _isPrivateMode = (mode === 'private');

    // 1. Reset navigation to the root of the selected vault
    _sessionState.path = ['root'];

    // 2. Update UI Branding (Visual cues are vital for security)
    if (_isPrivateMode) {
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
    return _isPrivateMode ? _privateVaultData : _vaultData;
}

export async function handlePrivateVaultGenesis(result) {
    // 1. Update the local Main Envelope
    if (!_vaultData.meta.extensions) _vaultData.meta.extensions = { private_vaults: {} };

    _vaultData.meta.extensions.private_vaults[result.emailHash] = result.pointer;

    // 2. Persist the Main Envelope immediately (so the pointer isn't lost)
    await _doSaveClick();

    // 3. Set the Private state
    _privateVaultData = result.data;
    _originalPrivateVaultData = structuredClone(result.data);

    // 4. Switch View
    toggleVaultMode('private');
}

export async function handlePrivateVaultUnlock(pwd, data) {
    if (data) {
        _privateVaultData = data;
        _originalPrivateVaultData = structuredClone(_privateVaultData);
    } else
        log("vaultUI.handlePrivateVaultUnlock", "accessing already unlocked private vault");

    showSilentToast("Private Vault Accessible");
    toggleVaultMode('private');

    runPrivateVaultBackup(pwd, _privateVaultData, true, () => showSilentToast("Private vault backup successful"), () => showSilentToast("Private vault backup failed"));

    runPrivateVaultCleanup(_privateVaultData).catch(err => {
        warn("vaultUI.doPrivateVaultClick", "Ignoring private vault cleanup failure (non-critical):", err);
    });
}

export function refreshMoveMenu() {
    log("vaultUI.refreshMoveMenu", "called");

    const count = _vaultClipboard.items.length;
    const isCutting = _vaultClipboard.mode === 'cut';
    const isSelecting = _sessionState.isSelectionMode;

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

    const inGroup = _sessionState.path.length === 2;
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

export function resetToRoot() {
    _sessionState.path = ['root'];
    refreshVault();
}

export function navigateToPath(index) {
    _sessionState.path = _sessionState.path.slice(0, index);
    refreshVault();
}

export function refreshVault(readOnly = false) {
    log("vaultUI.refreshVault", "called");

    if (readOnly)
        warn("vaultUI.refreshVault", "Read-Only mode, app will be limited to view info only!");

    vaultUI.title.classList.value = AU.isGenesisUser() ? 'genesis-user' : AU.isAdmin() ? 'admin-user' : 'member-user';

    refreshMoveMenu();

    // 3. Update the Action Bar (Add/Rename/Delete logic)
    _refreshAddRenDelMenubar();

    // 4. Full Re-render
    renderVaultExplorer();
    _refreshMainMenuItemsState(readOnly);
    _applyReadOnlyTheme(readOnly);

    vaultRawDataUI.textContent.setReadOnly(readOnly || !AU.isGenesisUser());
}

/**
 * Triggered by the Input Event on the search bar
 */
export function handleSearchInput(query) {
    _currentSearchQuery = query;
    clearTimeout(_searchDebounceTimer);

    _searchDebounceTimer = setTimeout(() => {
        // 💡 CRITICAL: If query is empty, reset to null
        if (!query || query.trim() === "") {
            _currentFilterMap = null;
        } else {
            _currentFilterMap = generateFilterMap(getActiveVaultData(), query);
        }

        // FORCE HOME: Reset the navigation path to the root
        // This ensures the user sees the top-level filtered groups immediately.
        _sessionState.path = ['root'];

        // Re-run the existing master render flow
        renderVaultExplorer();

        // Log for your debugging
        log("vaultUI.handleSearchInput", `[Search] Query: "${query}" | Map Active: ${!!_currentFilterMap}`);
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

/** INTERNAL FUNCTIONS **/
async function _init() {
    log("vaultUI._init", "called");

    _sessionState.path = ['root'];

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

    vaultMenu.saveMenu.onClick(_doSaveClick);

    vaultMenu.rawDataMenu.onClick(_doShowRawDataClick);
    vaultMenu.discardChangesMenu.onClick(_doDiscardChangesClick);

    vaultMenu.usersMenu.onClick(_doUsersClick);
    vaultMenu.syncAccessMenu.onClick(_doSyncAccessClick);
    vaultMenu.runBackupMenu.onClick(_doRunBackupClick);
    vaultMenu.recoveryRotationMenu.onClick(_doRecoveryKeyRotationClick);

    vaultUI.title.onClick(_doToggleSecureClick);
    vaultUI.toggleSecureBtn.onClick(_doToggleSecureClick);

    vaultMenu.logoutMenu.onClick(_doLogout);

    // temporary menu
    vaultMenu.copyLogsMenu.onClick(copyLogsToClipboard);
    vaultMenu.toggleLogsMenu.onClick(_toggleLogs);

    // Ensure these containers always use flex when shown
    //vaultRawDataUI.mainSection.setFlex();
    //vaultUI.mainSection.setFlex();
}

async function _showVaultUI({ readOnly = false } = {}) {
    log("vaultUI._showVaultUI", "called");

    if (readOnly) warn("vaultUI._showVaultUI", "Showing vault read-only mode");

    swapVisibility(rootUI.loginView, rootUI.vaultView);
    refreshVault(readOnly);
    activateIdleChecker();
}

function _setActiveVaultData(activeData) {
    if (_isPrivateMode) _privateVaultData = activeData;
    else _vaultData = activeData;
}

async function _doUsersClick() {
    log("vaultUI._doUsersClick", "Lazy loading module...");

    try {
        const { showUsersUI } = await import('@/ui/users.js');
        await showUsersUI();
    } catch (err) {
        error("vaultUI._doUsersClick", "Failed to load Users module:", err);
        showSilentToast("Error loading component", true);
    }
}

async function _doRecoveryKeyRotationClick() {
    log("vaultUI._doRecoveryKeyRotationClick", "called");

    try {
        const { showRecoveryRotationUI } = await import('@/ui/recovery-rotation.js');
        await showRecoveryRotationUI();
    } catch (err) {
        error("vaultUI._doRecoveryKeyRotationClick", "Failed to load recovery rotation module:", err);
        showSilentToast("Error loading component", true);
    }
}

async function _doShowRawDataClick() {
    log("vaultUI._doShowRawDataClick", "called");

    try {
        const { showRawDataUI } = await import('@/ui/raw-data-viewer.js');
        const getViewState = () => ({ data: getActiveVaultData(), isMasked: !_sessionState.showSecure });
        await showRawDataUI(getViewState, (data) => _setActiveVaultData(data));
    } catch (err) {
        error("vaultUI._doShowRawDataClick", "Failed to load raw data viewer module:", err);
        showSilentToast("Error loading component", true);
    }
}

async function _doSyncAccessClick() {
    log("vaultUI._doSyncAccessClick", "called");
    showSilentToast("Consolidating vault access...");
    await runVaultAccessHousekeeping();
    showSilentToast("Sync complete!");
}

async function _doRunBackupClick() {
    log("vaultUI._doRunBackupClick", "called");

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
        await runFullBackup(pwd, _vaultData, privPwd, _privateVaultData, () => {
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

function _doDiscardChangesClick() {
    showConfirmUI({
        title: "Discard Changes",
        message: "This will revert the vault to the last saved state. All current progress will be lost.",
        okText: "Discard",
        cancelText: "Keep Editing",
        onConfirm: () => {
            log("vaultUI._doDiscardChangesClick", "reverting...");

            // 1. REVERT THE DATA CHANGES
            _vaultData = structuredClone(_originalVaultData);

            // 2. Revert Private (if unlocked)
            if (_privateVaultData) {
                _privateVaultData = structuredClone(_originalPrivateVaultData);
            }

            // 1. Capture the IDs and clear the array immediately to prevent double-processing
            const filesToNuke = [..._pendingFileUploads];
            _pendingFileUploads = [];

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
            if (typeof _pendingFileDeletions !== 'undefined') {
                log("vaultUI._doDiscardChangesClick", `Rescuing ${_pendingFileDeletions.length} files from deletion queue.`);
                _pendingFileDeletions = [];
            }

            // Reset UI state
            _sessionState.path = ['root'];
            _vaultClipboard.items = [];
            _vaultClipboard.mode = null;
            _sessionState.isSelectionMode = false;

            showStatusMessage("Reverted to last save.", "info");

            refreshVault();
        }
    });
}

function _doLogout() {
    log("vaultUI._doLogout", "called");

    showStatusMessage("");
    _doSecure();
    logout();
}

function _doSecure() {

    log("vaultUI._doSecure", "called");

    // 1. Wipe the Data
    _vaultData = null;
    _originalVaultData = null;
    _privateVaultData = null;
    _originalPrivateVaultData = null;
    _isPrivateMode = false;

    lockPrivateVault();

    vaultRawDataUI.textContent.clear();

    // 2. Wipe the Session State (Crucial!)
    _sessionState.isEditable = false;
    _sessionState.showSecure = false;
    _sessionState.isSelectionMode = false;
    _sessionState.path = ['root']; // Reset breadcrumbs to root

    _vaultClipboard.mode = null;
    _vaultClipboard.sourceParentId = null;
    _vaultClipboard.items = [];

    // 3. Clear the DOM (Prevents seeing old data for a split second on re-login)
    vaultNavBarUI.breadcrumbs.clear();
    vaultUI.explorer.clear();

    // Use vaultUI.mainSection and not rootUI.vaultView as there's rendering issues in certain cases after log in
    swapVisibility(vaultUI.mainSection, rootUI.loginView);
}

async function _doToggleSecureClick() {
    log("vaultUI._doToggleSecureClick", "called");

    // 1. Toggle the state
    _sessionState.showSecure = !_sessionState.showSecure;

    vaultUI.toggleSecureBtn.setText(_sessionState.showSecure ? '🔓' : '🔒');

    // 3. Add a subtle color change to the title to bring further attention
    vaultUI.title.style.color = _sessionState.showSecure ? '#dd0000' : '#000';

    // Ensure we start at home if the path got corrupted
    if (!_sessionState.path || _sessionState.path.length === 0) {
        _sessionState.path = ['root'];
    }

    // 4. Re-render the explorer to apply state to all secure type fields
    renderVaultExplorer();

    const { refreshRawDataTree } = await import('@/ui/raw-data-viewer.js');
    refreshRawDataTree(getActiveVaultData(), !_sessionState.showSecure);
}

async function _doSaveClick() {
    log("vaultUI._doSaveClick", "Starting save process...");

    if (!_vaultData || Object.keys(_vaultData).length === 0) {
        warn("vaultUI._doSaveClick", "Vault data is empty or missing.");
        showStatusMessage("Nothing to save.", "error");
        return;
    }

    // Check for any changes across both vaults
    const changedShared = JSON.stringify(_vaultData) !== JSON.stringify(_originalVaultData);
    const changedPrivate = _privateVaultData && (JSON.stringify(_privateVaultData) !== JSON.stringify(_originalPrivateVaultData));

    if (!changedShared && !changedPrivate && _pendingFileDeletions.length === 0) {
        info("vaultUI._doSaveClick", "Vault has not changed since last save");
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
                await SV.encryptAndPersistPlaintext(JSON.stringify(_vaultData), { onUpdate: updateLockStatusUI });
                _originalVaultData = structuredClone(_vaultData);
            })());
        }

        // Task: Private Vault
        if (changedPrivate) {
            saveTasks.push((async () => {
                await savePrivateVaultData(_privateVaultData);
                _originalPrivateVaultData = structuredClone(_privateVaultData);
            })());
        }

        // 1. Wait for all JSON updates to finish
        await Promise.all(saveTasks);

        // 2. Commit Uploads: Now that JSONs are saved, these files are "Official"
        // We clear the list so we don't nuke them on a future Discard/Logout.
        _pendingFileUploads = [];

        // 3. PHYSICAL CLEANUP: Run this only after the JSON is safely saved
        if (typeof _pendingFileDeletions !== 'undefined' && _pendingFileDeletions.length > 0) {

            info("vaultUI._doSaveClick", `Processing ${_pendingFileDeletions.length} queued deletions...`);

            // We use allSettled so one 403 (Permission) doesn't stop the others
            const cleanupResults = await Promise.allSettled(_pendingFileDeletions.map(id => AT.deleteAttachmentFile(id)));

            // Optional: Log any files that couldn't be trashed (e.g., owned by User A)
            cleanupResults.forEach((res, i) => {
                const fileId = _pendingFileDeletions[i];

                if (res.status === 'rejected') {
                    // Use res.reason.message to see the actual text instead of {}
                    const reason = res.reason?.message || res.reason || "Unknown Error";
                    error("vaultUI._doSaveClick", `System Error deleting ${fileId}: ${reason}`);
                }
                else if (res.value === false) {
                    // This is the clean log you want!
                    log("vaultUI._doSaveClick", `Skipped ${fileId}: Ownership restriction (Handled).`);
                }
            });

            // IMPORTANT: Clear the queue so we don't try to delete them again on the next save
            _pendingFileDeletions = [];
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
        error("vaultUI._doSaveClick", "Save failed:", err);
        showOverlayAlertUI({ title: "Save Failed", message: err.message });
        showStatusMessage(`Save failed: ${err.message || err}`, "error");
        // Note: we do NOT clear _pendingFileDeletions here so the user can try saving again
    }
}

function _hasVaultChanges() {
    return (JSON.stringify(_vaultData) !== JSON.stringify(_originalVaultData)) ||
        (_privateVaultData && JSON.stringify(_privateVaultData) !== JSON.stringify(_originalPrivateVaultData));
}

async function _toggleLogs() {
    rootUI.log.toggleVisibility();
}

/**
 * Updates the visual theme of the vault based on read-only status.
 */
function _applyReadOnlyTheme(readOnly) {
    log("vaultUI._applyReadOnlyTheme", "called readOnly:", readOnly);

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

function _refreshAddRenDelMenubar() {
    // 1. Check Permissions (The Master Gate)
    const writeable = !inReadOnlyMode();

    // 2. Check Navigation Depth
    const depth = _sessionState.path.length;

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

function _refreshMainMenuItemsState(readOnly) {
    log("vaultUI._refreshMainMenuItemsState", "called");

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
    vaultMenu.privateVaultMenu.setText((isPrivateVaultUnlocked() && _isPrivateMode ? "🔒 Close" : "🛡️ Open") + " Private Vault");
    vaultMenu.discardChangesMenu.setVisible(_hasVaultChanges());

    // NOTE: addBtn, renameBtn, and deleteBtn are intentionally removed from here
    // as they are handled by the render loop.
}

/*function updateMoveToolbar() {
    const count = vaultClipboard.items.length;

    if (_sessionState.isSelectionMode && count > 0) {
        // Change the "Vault" title to show the count
        vaultUI.title.setText(`${count} selected`);
    } else {
        vaultUI.title.setText("Vault");

        // Put the normal Breadcrumbs back if nothing is selected
        renderBreadcrumbs();
    }
}*/