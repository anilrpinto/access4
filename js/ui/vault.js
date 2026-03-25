import { C, G, inReadOnlyMode, AU, E, U, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { logout } from '@/app.js';
import { runAdminBackup } from '@/core/backup.js';

import { loadUI, swapVisibility, showSilentToast } from '@/ui/uihelper.js';
import { rootUI, vaultUI, vaultNavBarUI, vaultRawDataUI, copyLogsToClipboard } from '@/ui/loader.js';
import { showConfirmUI, showOverlayConfirmUI, showOverlayAlertUI, showOverlayPasswordUI } from '@/ui/confirm.js';
import { showRecoveryRotationUI, hideRecoveryRotation } from '@/ui/recovery-rotation.js';
import { showAddNewUI, showRenameUI, showDeleteUI, hideAddRenDel } from '@/ui/add-rename-delete.js';
import { generateFilterMap, hideFilterUI } from '@/ui/filter.js';

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

let originalVaultData = null;
let vaultData = null;

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

async function init() {
    log("vaultUI.init", "called");

    sessionState.path = ['root'];

    swapVisibility(rootUI.loginView, vaultUI.mainSection);

    // Don't need this IF swapVisibility uses vaultUI.mainSection instead of rootUI.vaultView
    //vaultUI.mainSection.setVisible(true);

    vaultRawDataUI.mainSection.setVisible(false);
    hideRecoveryRotation();
    hideAddRenDel();

    vaultUI.menuBtn.onClick((e) => {
        // 1. Prevent the 'window' or 'body' from seeing this click
        e.stopPropagation();

        const menu = vaultUI.menuDropdown;
        const isVisible = menu.classList.contains('show-menu');

        console.log(`[Menu Debug] Clicked. Currently visible: ${isVisible}`);

        // 2. Toggle the class
        menu.classList.toggle('show-menu');

        // 3. Final check
        console.log(`[Menu Debug] New classList:`, menu.classList.value);
    });

    // Add this to your global window listener to see what's CLOSING it
    window.addEventListener('click', (e) => {
        if (vaultUI.menuDropdown.classList.contains('show-menu')) {
            console.log(`[Menu Debug] Window click detected on:`, e.target);
            vaultUI.menuDropdown.classList.remove('show-menu');
        }
    });

    vaultUI.saveMenu.onClick(doSaveClick);
    vaultUI.toggleEditMenu.onClick(doToggleEditClick);

    vaultUI.rawDataMenu.onClick(doShowRawDataClick);
    vaultUI.discardChangesMenu.onClick(doDiscardChangesClick);

    vaultUI.runBackupMenu.onClick(doRunBackupUI);
    vaultUI.recoveryRotationMenu.onClick(showRecoveryRotationUI);

    vaultUI.title.onClick(doToggleSecureClick);
    vaultUI.toggleSecureBtn.onClick(doToggleSecureClick);
    vaultUI.addBtn.onClick(doAddClick);
    vaultUI.renameBtn.onClick(doRenameClick);
    vaultUI.deleteBtn.onClick(doDeleteClick);

    vaultUI.selectMenu.onClick(doSelectClick);
    vaultUI.cutMenu.onClick(doCutClick);
    vaultUI.pasteMenu.onClick(doPasteClick);

    vaultUI.logoutMenu.onClick(doLogout);

    // temporary menu
    vaultUI.copyLogsMenu.onClick(copyLogsToClipboard);
    vaultUI.toggleLogsMenu.onClick(toggleLogs);

    // Ensure these containers always use flex when shown
    //vaultRawDataUI.mainSection.setFlex();
    //vaultUI.mainSection.setFlex();
}

/**
 * Triggered by the Input Event on your search bar
 */
export function handleSearchInput(query) {
    currentSearchQuery = query;
    clearTimeout(searchDebounceTimer);

    searchDebounceTimer = setTimeout(() => {
        // 💡 CRITICAL: If query is empty, reset to null
        if (!query || query.trim() === "") {
            currentFilterMap = null;
        } else {
            currentFilterMap = generateFilterMap(vaultData, query);
        }

        // FORCE HOME: Reset the navigation path to the root
        // This ensures the user sees the top-level filtered groups immediately.
        sessionState.path = ['root'];

        // Re-run the existing master render flow
        renderVaultExplorer();

        // Log for your debugging
        console.log(`[Search] Query: "${query}" | Map Active: ${!!currentFilterMap}`);
    }, 150);
}

export function refreshCleanupPill() {
    log("vaultUI.refreshCleanupPill", "called");

    const count = parseInt(localStorage.getItem(C.BACKUP_CLEANUP_COUNTER_KEY) || 0);
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
                    localStorage.setItem(C.BACKUP_CLEANUP_COUNTER_KEY, 0);
                    pill.remove();
                    showSilentToast("Storage tracking counter reset.");
                }
            });
        };
    } else if (pill) {
        pill.remove();
    }
}

async function doRunBackupUI() {
    log("vaultUI.doRunBackupUI", "called");

    // 1. Prompt for password
    const pwd = await showOverlayPasswordUI({
        title: "Manual Backup",
        message: "Password required to create a secure backup package.",
        okText: "Run"
    });

    if (!pwd) return; // Opted out - canceled

    try {
        // 2. Execute (true = explicit request)
        await runAdminBackup(pwd, vaultData, false, () => {
            showSilentToast("Writing backup package (ZIP+HTML+TXT) to local storage...");
            refreshCleanupPill();
        });

    } catch (err) {
        error("vaultUI.doRunBackupUI", "Error:" + err);
        showOverlayAlertUI({
            title: "Error",
            message: "Decryption failed. Please ensure your Master Password is correct."
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

            // Your logic using structuredClone
            vaultData = structuredClone(originalVaultData);

            // Reset UI state
            sessionState.path = ['root'];
            vaultClipboard.items = [];
            vaultClipboard.mode = null;
            sessionState.isSelectionMode = false;

            showStatusMessage("Reverted to last save.", "info");
            refreshMenuUI();
            renderVaultExplorer();
        }
    });
}

function doSelectClick() {
    log("vaultUI.doSelectClick", "called");

    // If we were in Cut mode OR Selection mode, clicking this should RESET everything
    if (vaultClipboard.mode === 'cut' || sessionState.isSelectionMode) {
        sessionState.isSelectionMode = false;
        vaultClipboard.mode = null;
        vaultClipboard.items = []; // This clears the array, so the CSS class will drop
        vaultClipboard.sourceParentId = null;
        showStatusMessage("Move cancelled", "info");
    } else {
        // Otherwise, just start selection mode normally
        sessionState.isSelectionMode = true;
    }

    refreshMenuUI();
    renderVaultExplorer();
}

function doCutClick() {
    log("vaultUI.doCutClick", "called");

    if (vaultClipboard.items.length === 0) return;

    vaultClipboard.mode = 'cut';
    // Remove the single sourceParentId line — it's now in the items array
    //vaultClipboard.sourceParentId = sessionState.path[1];

    // Turn off selection mode
    sessionState.isSelectionMode = false;

    // Auto-navigate to root
    sessionState.path = ['root'];

    refreshMenuUI();
    showStatusMessage(`${vaultClipboard.items.length} items cut. Select a group to paste.`, "info");

    // Re-render so we see the Group List now
    renderVaultExplorer();
}

async function doPasteClick() {
    log("vaultUI.doPasteClick", "called");

    const targetGroupId = sessionState.path[1];

    // 1. Validation: Must be in a group to paste
    if (!targetGroupId || targetGroupId === 'root') {
        showStatusMessage("Open a group to paste items", "error");
        return;
    }

    const targetGroup = vaultData.groups.find(g => g.id === targetGroupId);
    if (!targetGroup) {
        error("Paste failed: Target group not found");
        return;
    }

    let movedCount = 0;

    // 2. Loop through every item in the clipboard
    vaultClipboard.items.forEach(clipboardEntry => {
        // Find the source group for THIS specific item
        const sourceGroup = vaultData.groups.find(g => g.id === clipboardEntry.parentId);

        // Safety: Don't move if source is the same as target
        if (sourceGroup && sourceGroup.id !== targetGroupId) {
            const itemIndex = sourceGroup.items.findIndex(i => i.id === clipboardEntry.id);

            if (itemIndex > -1) {
                // Perform the move
                const [movedItem] = sourceGroup.items.splice(itemIndex, 1);
                targetGroup.items.push(movedItem);

                movedItem.modified = new Date().toISOString();
                movedCount++;
            }
        }
    });

    // 3. Cleanup
    vaultClipboard.items = [];
    vaultClipboard.mode = null;
    vaultClipboard.sourceParentId = null; // No longer needed, but good to clear

    // 4. Final UI Refresh
    if (movedCount > 0) {
        showStatusMessage(`Successfully moved ${movedCount} items`, "success");
    } else {
        showStatusMessage("No items were moved (already in target group)", "info");
    }

    refreshMenuUI();
    renderVaultExplorer();
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
    vaultRawDataUI.content.clear();

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

async function showVaultUI({ readOnly = false, onIdle = () => { doLogout() } } = {}) {

    log("vaultUI.showVaultUI", "called");

    // Hide login section
    rootUI.loginView.setVisible(false);

    handleReadonlyState(readOnly);

    // Show main unlocked view
    rootUI.vaultView.setVisible(true);

    // Events that "wake up" the timer
    // Clean up old listeners to prevent memory leaks/duplicate triggers
    idleEvents.forEach(evt => {
        document.removeEventListener(evt, resetTimer);
        document.addEventListener(evt, resetTimer, { passive: true });
    });

    idleCallback = onIdle;
    resetTimer();
}

function doToggleSecureClick() {
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
}

function doShowRawDataClick() {
    log("vaultUI.doShowRawDataClick", "called");
    refreshRawDisplay();
    swapVisibility(vaultUI.mainSection, vaultRawDataUI.mainSection);
    vaultRawDataUI.closeBtn.onClick(() => swapVisibility(vaultRawDataUI.mainSection, vaultUI.mainSection));
}

async function doAddClick() {
    const depth = sessionState.path.length;
    log("vaultUI.doAddClick", "called - depth:", depth);

    if (depth < 3) {
        vaultUI.mainSection.setVisible(false);
        showAddNewUI(depth, sessionState.path[depth-1], vaultData, {
            onAdd: (name) => {
                if (depth === 1) executeAddGroup(name);
                else if (depth === 2) executeAddItem(name);

                vaultUI.mainSection.setVisible(true);
            },
            onCancel: () => {
                vaultUI.mainSection.setVisible(true);
                renderVaultExplorer();
            }
        });
    }
}

async function doRenameClick() {
    const depth = sessionState.path.length;
    log("vaultUI.doRenameClick", "called - depth:", depth);

    // We only rename things we are currently "inside" or looking at
    if (depth < 2) return;

    vaultUI.mainSection.setVisible(false);

    showRenameUI(depth, vaultData, sessionState.path, {
        onRename: (newName) => {
            executeRename(newName);
            vaultUI.mainSection.setVisible(true);
        },
        onCancel: () => {
            vaultUI.mainSection.setVisible(true);
            renderVaultExplorer();
        }
    });
}

async function doDeleteClick() {
    const depth = sessionState.path.length;

    log("vaultUI.doDeleteClick", "called - depth:", depth);

    if (depth < 2) {
        warn("vaultUI.doDeleteClick", "Nothing selected to delete, ignoring delete");
        return; // Can't delete the root vault
    }

    vaultUI.mainSection.setVisible(false);

    showDeleteUI(depth, sessionState.path[1], sessionState.path[2], vaultData, {
        onConfirm: () => {
            executeDeletion();
            vaultUI.mainSection.setVisible(true);
        },
        onCancel: () => {
            vaultUI.mainSection.setVisible(true);
            renderVaultExplorer();
        }
    });
}

function refreshAddRenDelBtnVisibility() {
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
    vaultUI.addBtn.setVisible(canAdd && writeable);
    vaultUI.renameBtn.setVisible(canRenameDelete && writeable);
    vaultUI.deleteBtn.setVisible(canRenameDelete && writeable);

    //log("vaultUI.refreshAddRenDelBtnVisibility", `depth:${depth} add:${canAdd} renDel:${canRenameDelete} writeable:${writeable}`);
}

async function doToggleEditClick() {
    if (sessionState.isEditable) {
        // We are EXITING edit mode.
        // Update the timestamp now.
        const item = getCurrentItem();
        if (item) item.modified = new Date().toISOString();
    }

    sessionState.isEditable = !sessionState.isEditable;
    vaultUI.toggleEditMenu.setText(sessionState.isEditable ? "Exit Edit Mode" : "Edit Item");
    renderVaultExplorer();
}

async function doSaveClick() {
    log("vaultUI.doSaveClick", "Starting save process...");

    // Clear previous status and show 'Working' state
    showStatusMessage("Encrypting and saving...", null);

    if (!vaultData || Object.keys(vaultData).length === 0) {
        warn("vaultUI.doSaveClick", "Vault data is empty or missing.");
        showStatusMessage("Nothing to save.", "error");
        return;
    }

    try {
        await E.encryptAndPersistPlaintext(JSON.stringify(vaultData), { onUpdate: updateLockStatusUI });
        originalVaultData = structuredClone(vaultData);

        showOverlayAlertUI({
            title: "Vault Saved",
            message: `Your changes have been encrypted and saved successfully.`,
            okText: "OK",
            onConfirm: () => {
                refreshMenuUI(); // Hide the "Discard Changes" menu since we are in sync
            }
        });
        showStatusMessage(`Last saved: ${U.getCurrentTime()}`, "success");

    } catch (err) {
        error("vaultUI.doSaveClick", "Save failed:", err);
        showStatusMessage(`Save failed: ${err.message || err}`, "error");
    }
}

function executeAddGroup(name) {
    log("vaultUI.executeAddGroup", "called - name:", name);

    const newId = 'g-' + Date.now();
    const newGroup = { id: newId, name: name, items: [] };
    vaultData.groups.push(newGroup);

    // Auto-navigate into the new group
    sessionState.path.push(newId);
    renderVaultExplorer();
}

function executeAddItem(name) {
    log("vaultUI.executeAddItem", "called - name:", name);

    const groupId = sessionState.path[1];
    const group = vaultData.groups.find(g => g.id === groupId);
    const now = new Date().toISOString();
    const newItem = {
        id: 'i-' + Date.now(),
        label: name,
        created: now, modified: now,
        fields: [{ type: 'text', key: 'Username', val: '' }, { type: 'secure', key: 'Password', val: '' }, { type: 'note', key: 'Notes', val: '' }]
    };
    group.items.push(newItem);
    renderVaultExplorer();
}

function executeRename(newName) {
    log("vaultUI.executeRename", "called - newName:", newName);

    const depth = sessionState.path.length;
    const groupId = sessionState.path[1];

    if (depth === 2) {
        const group = vaultData.groups.find(g => g.id === groupId);
        if (group) group.name = newName;
    } else if (depth === 3) {
        const itemId = sessionState.path[2];
        const group = vaultData.groups.find(g => g.id === groupId);
        const item = group?.items.find(i => i.id === itemId);
        if (item) {
            item.label = newName;
            item.modified = new Date().toISOString();
        }
    }

    renderVaultExplorer();
}

function executeDeletion() {
    log("vaultUI.executeDeletion", "called");

    const depth = sessionState.path.length;

    if (depth === 2) {
        // --- DELETE GROUP ---
        const groupId = sessionState.path[1];
        const index = vaultData.groups.findIndex(g => g.id === groupId);

        if (index > -1) {
            vaultData.groups.splice(index, 1);
            // After deleting a group, we must go back to the root
            sessionState.path = ['root'];
        }
    }
    else if (depth === 3) {
        // --- DELETE ITEM ---
        const groupId = sessionState.path[1];
        const itemId = sessionState.path[2];
        const group = vaultData.groups.find(g => g.id === groupId);

        if (group) {
            const index = group.items.findIndex(i => i.id === itemId);
            if (index > -1) {
                group.items.splice(index, 1);
                // After deleting an item, go back to the group list
                sessionState.path.pop();
            }
        }
    }

    renderVaultExplorer();
}

function refreshMenuUI() {
    log("vaultUI.refreshMenuUI", "called");

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

    // --- SECTION 2: BREADCRUMBS ---
    // Always render breadcrumbs so the user knows where they are
    // globally, regardless of selection/move status.
    renderBreadcrumbs();

    // --- SECTION 3: MENU VISIBILITY (Updated for UX) ---

    // 1. Only show 'Cut' if we are selecting AND not already in 'Cut' mode
    vaultUI.cutMenu.setVisible(isSelecting && count > 0 && !isCutting);

    const inGroup = sessionState.path.length === 2;
    vaultUI.pasteMenu.setVisible(isCutting && inGroup);

    // 2. Update the "Select Multiple" toggle text to handle 'Cancel Move'
    if (isSelecting || isCutting) {
        vaultUI.selectMenu.setText(isCutting ? "Cancel Move" : "Cancel Selection");
        vaultUI.selectMenu.classList.add('active-mode-text');
    } else {
        vaultUI.selectMenu.setText("Select Multiple");
        vaultUI.selectMenu.classList.remove('active-mode-text');
    }

    vaultUI.discardChangesMenu.setVisible(JSON.stringify(vaultData) !== JSON.stringify(originalVaultData));
}

async function toggleLogs() {
    rootUI.log.toggleVisibility();
}

/**
 * Resolves an ID to a human-readable name for the breadcrumb
 */
function getNameFromId(id, index) {
    if (id === 'root') return "🏠";
    if (index === 1) { // It's a Group ID
        const group = vaultData.groups.find(g => g.id === id);
        return group ? group.name : "Unknown Group";
    }
    if (index === 2) { // It's an Item ID
        const groupId = sessionState.path[1];
        const group = vaultData.groups.find(g => g.id === groupId);
        const item = group?.items.find(i => i.id === id);
        return item ? item.label : "Unknown Item";
    }
    return id;
}

/**
 * Renders the Breadcrumb interface
 */
function renderBreadcrumbs() {
    const breadcrumbs = vaultNavBarUI.breadcrumbs;
    if (!breadcrumbs) return;

    breadcrumbs.innerHTML = "";
    sessionState.path.forEach((id, index) => {
        const isLast = index === sessionState.path.length - 1;
        const label = getNameFromId(id, index);

        const span = document.createElement('span');
        span.className = isLast ? 'breadcrumb-item active' : 'breadcrumb-item link';
        span.innerText = label;

        if (!isLast) {
            span.onclick = () => {
                sessionState.path = sessionState.path.slice(0, index + 1);
                renderVaultExplorer(); // We will build this next
            };
        }

        breadcrumbs.appendChild(span);
        if (!isLast) {
            const sep = document.createElement('span');
            sep.className = 'sep';
            sep.innerText = ' › ';
            breadcrumbs.appendChild(sep);
        }
    });
}

// --- Phase 3: UI Renderers ---

function renderGroupList(container) {
    log("vaultUI.renderGroupList", "called");

    container.innerHTML = ""; // Clear existing

    if (!vaultData.groups || vaultData.groups.length === 0) {
        container.innerHTML = `<div class="empty-state">No groups found.</div>`;
        return;
    }

    vaultData.groups.forEach(group => {

        // FILTER CHECK: Skip if not visible in search
        if (currentFilterMap && !currentFilterMap.visible.has(group.id)) {
            return;
        }

        // Check if any item in the clipboard is from THIS group
        const hasCutItems = vaultClipboard.items.some(i => i.parentId === group.id);

        // HIGHLIGHT CHECK: Is this group name a match?
        const isMatch = currentFilterMap?.highlighted.has(group.id);

        const div = document.createElement('div');
        // Add 'source-group' class if items are being cut from here
        // Add 'search-highlight' class if it's a match
        div.className = `list-row ${hasCutItems ? 'source-group-active' : ''} ${isMatch ? 'search-highlight' : ''}`;

        div.innerHTML = `
            <span>📁 ${group.name} ${hasCutItems ? '<small>(moving items...)</small>' : ''}</span>
            <span class="count">${group.items.length}</span>
        `;
        div.onclick = () => {
            hideFilterUI();
            sessionState.path.push(group.id);
            renderVaultExplorer();
        };
        container.appendChild(div);
    });

    // THE EMPTY CHECK: If the loop finished but added nothing
    if (container.children.length === 0 && currentFilterMap) {
        container.innerHTML = `<div class="empty-state">No data matching "${currentSearchQuery}".</div>`;
    }
}

function renderItemList(container, groupId) {
    log("vaultUI.renderItemList", "called");

    container.innerHTML = "";

    const group = vaultData.groups.find(g => g.id === groupId);
    if (!group) return;

    // 💡 EMPTY STATE TWEAK:
    if (group.items.length === 0) {
        container.innerHTML = `<div class="empty-state">This group is empty.</div>`;
        return;
    }

    group.items.forEach(item => {

        // FILTER CHECK: Skip if item is hidden by filter
        if (currentFilterMap && !currentFilterMap.visible.has(item.id)) {
            return;
        }

        const div = document.createElement('div');

        // 1. Check if item is in the clipboard (works for both Selection and Cut modes)
        const isSelected = vaultClipboard.items.some(i => i.id === item.id);

        // 💡 HIGHLIGHT CHECK: Is this item title a match?
        const isMatch = currentFilterMap?.highlighted.has(item.id);

        div.className = `list-row ${isSelected ? 'to-be-moved' : ''} ${isMatch ? 'search-highlight' : ''}`;
        div.innerHTML = `<span>📄 ${item.label}</span><span class="arrow">›</span>`;

        div.onclick = () => {
            // 2. If we are selecting OR if the item is already "Cut",
            // clicking should only toggle selection/do nothing, not navigate.
            if (sessionState.isSelectionMode || vaultClipboard.mode === 'cut') {
                toggleItemSelection(item.id, div);
            } else {
                // Normal navigation
                hideFilterUI();
                sessionState.path.push(item.id);
                renderVaultExplorer();
            }
        };
        container.appendChild(div);
    });

    // THE EMPTY CHECK:
    if (container.children.length === 0) {
        const msg = currentFilterMap ? "No items match your search." : "This group is empty.";
        container.innerHTML = `<div class="empty-state">${msg}</div>`;
    }
}

function toggleItemSelection(id, element) {
    const index = vaultClipboard.items.findIndex(i => i.id === id);

    if (index > -1) {
        vaultClipboard.items.splice(index, 1);
        element.classList.remove('to-be-moved');
    } else {
        // WE MUST STORE THE PARENT ID HERE
        vaultClipboard.items.push({ id: id, parentId: sessionState.path[1] });
        element.classList.add('to-be-moved');
    }
    refreshMenuUI();
}

function updateMoveToolbar() {
    const count = vaultClipboard.items.length;

    if (sessionState.isSelectionMode && count > 0) {
        // Change the "Vault" title to show the count
        vaultUI.title.setText(`${count} selected`);
    } else {
        vaultUI.title.setText("Vault");

        // Put the normal Breadcrumbs back if nothing is selected
        renderBreadcrumbs();
    }
}

function renderItemDetails(container, groupId, itemId) {
    log("vaultUI.renderItemDetails", "called");

    const group = vaultData.groups.find(g => g.id === groupId);
    const item = group?.items.find(i => i.id === itemId);

    if (!item) {
        container.innerHTML = `<div class="empty-state">Item not found.</div>`;
        return;
    }

    const detailEl = document.createElement('div');
    detailEl.className = 'detail-view';

    // 1. Audit Meta Bar (Existing)
    const metaBar = document.createElement('div');
    metaBar.className = 'item-meta-bar';
    const dateOpts = { dateStyle: 'short', timeStyle: 'short' };
    const createdStr = new Date(item.created).toLocaleString(undefined, dateOpts);
    const modifiedStr = new Date(item.modified).toLocaleString(undefined, dateOpts);
    const isModified = item.created !== item.modified;
    metaBar.innerHTML = `
        <span class="meta-left">${createdStr}</span>
        ${isModified ? `<span class="meta-right">${modifiedStr}</span>` : ''}
    `;
    detailEl.appendChild(metaBar);

    const readonlyAttr = sessionState.isEditable ? "" : "readonly";

    // 2. Render Standard Fields (Text, Secure, Note)
    item.fields.forEach((field, index) => {
        const fieldMatchID = `${item.id}-field-${field.key}`;
        const isMatch = currentFilterMap?.highlighted.has(fieldMatchID);
        const fieldBox = document.createElement('div');
        fieldBox.className = `field-box ${sessionState.isEditable ? 'editable' : ''}`;

        let html = `
            <div class="field-header">
                <input type="text" class="label-input ${isMatch ? 'search-label-hit' : ''}"
                   data-index="${index}" value="${field.key}" ${readonlyAttr} placeholder="Label">
                <div class="field-actions">
                    ${sessionState.isEditable ?
                        `<button class="icon-btn delete-field-btn" data-index="${index}">🗑️</button>` :
                        `<button class="icon-btn copy-btn" data-val="${field.val}">📋</button>`
                    }
                </div>
            </div>`;

        if (field.type === 'secure') {
            html += `<div class="input-wrap"><input type="${sessionState.showSecure ? 'text' : 'password'}" class="field-input" data-index="${index}" value="${field.val}" ${readonlyAttr} spellcheck="false"></div>`;
        } else if (field.type === 'note') {
            html += `<textarea class="field-input" data-index="${index}" ${readonlyAttr} rows="4">${field.val}</textarea>`;
        } else {
            html += `<div class="input-wrap"><input type="text" class="field-input" data-index="${index}" value="${field.val}" ${readonlyAttr}></div>`;
        }

        fieldBox.innerHTML = html;
        detailEl.appendChild(fieldBox);
    });

    // 3. NEW: Render Attachments Section
    if (item.attachments && item.attachments.length > 0) {
        const attachmentSection = document.createElement('div');
        attachmentSection.id = `attachments_${item.id}`;
        attachmentSection.className = 'attachment-section';
        attachmentSection.innerHTML = `<div class="section-label">Attachments</div>`;

        // EVENT DELEGATION: One listener for the whole box
        attachmentSection.onclick = (e) => {
            // Handle Download
            const link = e.target.closest('.file-link');
            if (link) {
                e.preventDefault();
                const fileId = link.getAttribute('data-id');
                const fileObj = item.attachments.find(a => a.val === fileId);
                if (fileObj) handleDownloadAttachment(fileObj);
                return;
            }

            // Handle Delete
            const deleteBtn = e.target.closest('.delete-attachment-btn');
            if (deleteBtn) {
                // 1. STOP the click from traveling up to the main vault listeners
                e.stopPropagation();
                e.preventDefault();

                const index = deleteBtn.getAttribute('data-index');
                handleDeleteAttachment(item, index);
            }
        };

        item.attachments.forEach((file, index) => {
            const sizeKB = Math.round(file.meta.size / 1024);

            // 💡 HIGHLIGHT LOGIC: Construct the ID used in filter.js
            const attachmentMatchID = `${item.id}-attachment-${file.val}`;
            const isMatch = currentFilterMap?.highlighted.has(attachmentMatchID);

            const fileRow = document.createElement('div');
            fileRow.className = `attachment-row ${isMatch ? 'filter-match' : ''}`;

            fileRow.innerHTML = `
            <a href="#" class="file-link" data-id="${file.val}">📄 ${file.key} (${sizeKB} KB)</a>
            <div class="field-actions">
                ${sessionState.isEditable ?
                    `<button class="icon-btn delete-attachment-btn" data-index="${index}">🗑️</button>` : ''}
            </div>
        `;
            attachmentSection.appendChild(fileRow);
        });

        detailEl.appendChild(attachmentSection);
    }

    // 4. Field Template (Existing)
    if (sessionState.isEditable) {
        addNewFieldTemplate(detailEl, item);
    }

    container.appendChild(detailEl);
    attachDetailListeners(container, item); // Pass item to handle file actions
}

function addNewFieldTemplate(targetElement, itemObject) {
    const addTemplate = document.createElement('div');
    addTemplate.className = 'field-box add-template';

    addTemplate.innerHTML = `
        <div class="add-field-row">
            <input type="text" id="newField_label" placeholder="Label" class="add-label-input">
            <select id="newField_type" class="add-type-select">
                <option value="text">Text</option>
                <option value="secure">Secure</option>
                <option value="note">Note</option>
                <option value="file">File</option>
            </select>
            <input type="file" id="file_uploader" style="display:none">
            <button id="newField_confirmBtn" class="add-icon-btn">➕</button>
        </div>
    `;

    const confirmBtn = addTemplate.querySelector('#newField_confirmBtn');
    const typeSelect = addTemplate.querySelector('#newField_type');
    const fileInput = addTemplate.querySelector('#file_uploader');

    confirmBtn.onclick = () => {
        const label = document.getElementById('newField_label').value.trim();
        const type = typeSelect.value;

        if (type === 'file') {
            fileInput.click(); // Open system file picker
        } else {
            if (!label) {
                return showOverlayAlertUI({
                    title: "Error",
                    message: "Label is mandatory!"
                });
            }

            itemObject.fields.push({ key: label, val: "", type: type });
            itemObject.modified = new Date().toISOString();
            renderVaultExplorer();
        }
    };

    fileInput.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const label = document.getElementById('newField_label').value.trim();

        await handleUploadAttachment(file, label, itemObject);

        renderVaultExplorer();
    };

    typeSelect.onchange = () => {
        const labelInput = document.getElementById('newField_label');
        if (typeSelect.value === 'file') {
            labelInput.placeholder = "Optional File Label...";
        } else {
            labelInput.placeholder = "Label (e.g. Username)";
        }
    };

    targetElement.appendChild(addTemplate);
}

async function handleUploadAttachment(file, label, itemObject) {
    // 1. Create a temporary ID to find this specific UI row later
    const tempId = "up_" + Date.now();
    const fileName = label || file.name;

    try {
        log("vaultUI.handleUploadAttachment", `Starting upload for: ${fileName}`);

        // 1. Find the container
        let container = document.querySelector('.attachment-section');

        // SAFETY: If the section doesn't exist yet (first upload for this item),
        // find the main detail container and inject it.
        if (!container) {
            const detailView = document.getElementById('vault_explorer'); // Or your specific detail ID
            container = document.createElement('div');
            container.className = 'attachment-section';
            detailView.appendChild(container);
        }

        // 2. Now append the spinner
        const loadingRow = document.createElement('div');
        loadingRow.className = 'attachment-row uploading-row';
        loadingRow.id = tempId;
        loadingRow.innerHTML = `
            <div class="field-actions">
                <span><div class="spinner"></div> &nbsp; Encrypting ${fileName}...</span>
            </div>
        `;
        container.appendChild(loadingRow);

        // 3. Perform the actual work
        const arrayBuffer = await file.arrayBuffer();
        const binary = new Uint8Array(arrayBuffer);

        let mimeType = file.type;

        log("vaultUI.handleUploadAttachment", "mimeType:", mimeType);

        if (!mimeType && file.name.endsWith('.zip')) {
            mimeType = 'application/zip';
        }

        const attachmentEntry = await E.saveAttachment(
            fileName,
            binary,
            file.type
        );

        // 4. Update memory
        if (!itemObject.attachments) itemObject.attachments = [];
        itemObject.attachments.push(attachmentEntry);
        itemObject.modified = new Date().toISOString();

        // 5. Success! The full render will now replace our temp row
        renderVaultExplorer();
        info("vaultUI.handleUploadAttachment", "Upload complete.");

    } catch (err) {
        // Remove the failed spinner if it exists
        document.getElementById(tempId)?.remove();

        console.error("Upload Error:", err);
        alert("Upload failed. Check console for details.");
    }
}

async function handleDownloadAttachment(attachment) {
    try {
        log("vaultUI.handleDownloadAttachment", `Opening: ${attachment.key}`);

        // 1. Get the decrypted bytes from the Envelope layer
        const plaintext = await E.openAttachment(attachment);

        // 2. Trigger the actual browser download
        const blob = new Blob([plaintext], { type: attachment.meta.mime });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = attachment.key;
        document.body.appendChild(a);
        a.click();

        // Cleanup memory
        setTimeout(() => {
            URL.revokeObjectURL(url);
            a.remove();
        }, 100);

        info("vaultUI.handleDownloadAttachment", "File delivered.");

    } catch (err) {
        // Now vault.js only handles UI-level reporting
        error("vaultUI.handleDownloadAttachment", "Failed to open file", err);
        alert("Failed to download or decrypt file.");
    }
}

async function handleDeleteAttachment(item, index) {
    const attachment = item.attachments[index];

    showOverlayConfirmUI({
        title: `Delete ${attachment.key}?`,
        message: `Are you sure you want to permanently delete this attachment? This cannot be undone.`,
        okText: "Delete",
        onConfirm: async () => {

            if (!attachment) return; // to account for accidental double clicks on mobile deivces

            try {
                // 1. Attempt Drive Deletion
                // Even if this fails with a 404, our updated engine returns 'true'
                await E.deleteAttachmentFile(attachment);

            } catch (err) {
                error("vaultUI.handleDeleteAttachment", "Critical Delete Error", err);
                alert("Could not communicate with Google Drive. Check your connection.");
                return; // Only stop here if it's a network/auth error
            }

            // 2. ALWAYS remove from the local JSON if we got this far
            // This clears the "ghost" entry that was bothering you
            log("vaultUI.handleDeleteAttachment", "Removing metadata entry.");
            item.attachments.splice(index, 1);
            item.modified = new Date().toISOString();

            // 3. Re-render and Sync to Drive
            renderVaultExplorer();

            info("vaultUI.handleDeleteAttachment", "Ghost attachment cleared.");
        }
    });
}

function attachDetailListeners(container) {
    const item = getCurrentItem();
    if (!item) return;

    // 1. Toggle Password Visibility
    // Redraws the UI to switch between dots (••••) and plain text
    container.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.onclick = () => {
            sessionState.showSecure = !sessionState.showSecure;
            renderVaultExplorer();
        };
    });

    // 2. Copy to Clipboard
    container.querySelectorAll('.copy-btn').forEach(btn => {
        btn.onclick = () => {
            navigator.clipboard.writeText(btn.dataset.val);
            const original = btn.innerText;
            btn.innerText = "✅";
            setTimeout(() => btn.innerText = original, 1500);
        };
    });

    // 3. Update Field Values (Text/Password/Notes)
    // Updates the JavaScript object only. No UI refresh to avoid cursor jumping.
    container.querySelectorAll('.field-input').forEach(input => {
        input.oninput = (e) => {
            const index = e.target.dataset.index;
            item.fields[index].val = e.target.value;
        };
    });

    // 4. Update Field Labels (Keys)
    container.querySelectorAll('.label-input').forEach(input => {
        input.oninput = (e) => {
            const index = e.target.dataset.index;
            item.fields[index].key = e.target.value;
        };
    });

    // 5. Delete Field Logic
    // Structural change: requires a full re-render to remove the row.
    container.querySelectorAll('.delete-field-btn').forEach(btn => {
        btn.onclick = (e) => {
            // SAFEGUARD 1: Stop the click from bleeding into the background
            e.stopPropagation();

            const index = parseInt(btn.dataset.index);
            const fieldName = item.fields[index].key || "unnamed";

            showOverlayConfirmUI({
                title: "Delete Field",
                message: `Are you sure you want to delete the <b>${fieldName}</b> field?`,
                okText: "Delete",
                onConfirm: () => {
                    // This code only runs if the user clicks the red "Delete" button
                    item.fields.splice(index, 1);

                    // SAFEGUARD 2: Flag the item as changed for the sync logic
                    item.modified = new Date().toISOString();

                    // Refresh the UI to remove the row
                    renderVaultExplorer();
                }
            });
        };
    });
}

/**
 * Finds the currently active item based on the sessionState.path
 */
function getCurrentItem() {
    const groupId = sessionState.path[1];
    const itemId = sessionState.path[2];
    if (!groupId || !itemId) return null;

    const group = vaultData.groups.find(g => g.id === groupId);
    return group?.items.find(i => i.id === itemId) || null;
}

function refreshRawDisplay() {
    log("vaultUI.refreshRawDisplay", "called");
    if (vaultRawDataUI.content && vaultData) {
        vaultRawDataUI.content.setText(U.format(vaultData));
    }
}

// --- Main Render Entry Point ---
async function renderVaultExplorer() {
    log("vaultUI.renderVaultExplorer", "called");

    // 1. Wipe transient keys/envelope before any rendering starts
    E.flushAttachmentTransients();

    // Safety check: if we still don't have data, stop here.
    if (!vaultData) {
        warn("vaultUI.renderVaultExplorer", "No data available to render.");
        return;
    }

    // IMPORTANT: Let refreshMenuUI handle the title/breadcrumbs logic
    // instead of calling renderBreadcrumbs() directly here.
    // 1. Update Menu (Title, Cut/Paste visibility)
    refreshMenuUI();

    // 2. Update Toolbar (Add/Rename/Delete visibility)
    // Moving this here ensures it runs on EVERY re-render (Paste, Undo, Nav, etc.)
    refreshAddRenDelBtnVisibility();

    const explorer = vaultUI.explorer;
    if (!explorer) return;
    explorer.innerHTML = "";

    const depth = sessionState.path.length;

    // View Routing
    if (depth === 1) {
        renderGroupList(explorer);
    } else if (depth === 2) {
        renderItemList(explorer, sessionState.path[1]);
    } else if (depth === 3) {
        // We'll build the detail renderer in Phase 4
        renderItemDetails(explorer, sessionState.path[1], sessionState.path[2]);
    }
}

function handleReadonlyState(readOnly) {
    if (readOnly)
        warn("vaultUI.handleReadonlyState", "Read-Only mode, app will be limited to view info only!");
    manageActionableItems(readOnly);
    applyReadOnlyTheme(readOnly);
}

function manageActionableItems(readOnly) {
    log("vaultUI.manageActionableItems", "called");

    const visible = !readOnly;
    const admin = AU.isAdmin();

    // These only care about read-only/admin status, not depth
    vaultUI.saveMenu.setVisible(visible);
    vaultUI.toggleEditMenu.setVisible(visible);
    vaultUI.rawDataMenu.setVisible(visible && admin);
    vaultUI.runBackupMenu.setVisible(admin);
    vaultUI.recoveryRotationMenu.setVisible(visible && admin);

    // NOTE: addBtn, renameBtn, and deleteBtn are intentionally removed from here
    // as they are handled by the render loop.
}

/**
 * Updates the visual theme of the vault based on read-only status.
 */
function applyReadOnlyTheme(readOnly) {
    log("vaultUI.applyReadOnlyTheme", "called readOnly:", readOnly);

    const mainHeader = document.querySelector('header'); // Or vaultUI.header if defined
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

/**
 * EXPORTED FUNCTIONS
 */
export async function loadVault(pwd, data, options) {

    init();

    vaultData = data;
    originalVaultData = structuredClone(data);

    if (AU.isAdmin()) {
        await runAdminBackup(pwd, vaultData, true, () => refreshCleanupPill(), () => refreshCleanupPill());
    }
    pwd = null;

    await renderVaultExplorer();
    await showVaultUI(options);
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
