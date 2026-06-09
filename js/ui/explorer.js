import { C, G, SV, AT, CR, BM, log, trace, debug, info, warn, error} from '@/shared/exports.js';
import { vaultUI, vaultNavBarUI, vaultMenuBar, vaultMenu } from '@/ui/loader.js';
import { hideFilterUI, sortVaultData } from '@/ui/search-and-sort.js';
import { showOverlayConfirmUI, showOverlayAlertUI } from '@/ui/modal.js';
import { showSilentToast } from '@/ui/uihelper.js';
import { toggleVaultMode, resetToRoot, navigateToPath, handlePrivateVaultGenesis, handlePrivateVaultUnlock, showStatusMessage } from '@/ui/vault.js';
import { promptPrivateVaultPassword, showCreatePrivateVaultUI, lockPrivateVault, isPrivateVaultUnlocked } from "@/ui/private-vault.js";
import { showAddNewUI, showRenameUI, showDeleteUI } from '@/ui/add-rename-delete.js';

let _vaultCtx = null;

export async function loadExplorer(onShowCb) {

    _vaultCtx = G.vaultContext;
    const screenKey = window.ScreenManager.EXPLORER_SCREENKEY;

    window.ScreenManager.register(screenKey, vaultUI.mainSection, {
        onShow: async () => _load(onShowCb),
        onHide: _unload
    });

    window.ScreenManager.switchView(screenKey);
}

export async function renderVaultExplorer() {
    log("explorer.renderVaultExplorer", "called");

    // 1. Wipe transient keys/envelope before any rendering starts
    SV.flushCachedTransients();

    _renderBreadcrumbs();

    const { activeData, depth, groupId } = _vaultCtx();

    // Safety check: if we still don't have data, stop here.
    if (!activeData) {
        warn("explorer.renderVaultExplorer", "No data available to render.");
        return;
    }

    if (!vaultUI.explorer) return;

    vaultUI.explorer.innerHTML = "";

    // View Routing
    if (depth === 1) {
        _renderGroupList(vaultUI.explorer);
    } else if (depth === 2) {
        _renderItemList(vaultUI.explorer, groupId);
    } else if (depth === 3) {
        // We'll build the detail renderer in Phase 4
        _renderItemDetails(vaultUI.explorer);
    }
}

/**
 * Finds the currently active item based on the sessionState.path
 */
export function getCurrentItem() {
    const { findActiveGroup, findActiveItem } = _vaultCtx();
    return findActiveItem(findActiveGroup()) || null;
}

/** INTERNAL FUNCTIONS **/
async function _load(onShowCb) {
    log("explorer._load", "called");

    vaultMenu.toggleEditMenu.onClick(_doToggleEditClick);
    vaultMenuBar.addBtn.onClick(_doAddClick);
    vaultMenuBar.renameBtn.onClick(_doRenameClick);
    vaultMenuBar.deleteBtn.onClick(_doDeleteClick);

    vaultMenu.selectMenu.onClick(_doSelectClick);
    vaultMenu.cutMenu.onClick(_doCutClick);
    vaultMenu.pasteMenu.onClick(_doPasteClick);

    vaultMenu.privateVaultMenu.onClick(_doPrivateVaultClick);

    if (onShowCb) onShowCb();
    else warn("explorer._load", "Missing required onShow callback to explorer")    ;
}

function _unload() {
    log("explorer._unload", "called");

    vaultMenuBar.addBtn.setVisible(false);
    vaultMenuBar.renameBtn.setVisible(false);
    vaultMenuBar.deleteBtn.setVisible(false);
    return true;
}

function _doSelectClick() {
    log("explorer._doSelectClick", "called");

    const { vaultClipboard, isSelectionMode, setSelectionMode, cancelMove, refresh } = _vaultCtx();

    // If we were in Cut mode OR Selection mode, clicking this should RESET everything
    if (vaultClipboard.mode === 'cut' || isSelectionMode) {
        cancelMove();
    } else {
        // Otherwise, just start selection mode normally
        setSelectionMode(true);
    }

    refresh();
}

function _doCutClick() {
    log("explorer._doCutClick", "called");

    const { navigateToRoot, vaultClipboard, isPrivateMode, setSelectionMode, refresh } = _vaultCtx();
    if (vaultClipboard.items.length === 0) return;

    vaultClipboard.mode = 'cut';
    vaultClipboard.sourceVault = isPrivateMode ? 'private' : 'shared';

    // IMPORTANT: Determine type based on the items themselves, not just depth
    // This handles cases where someone might be at root but has items from subgroups selected
    const hasGroups = vaultClipboard.items.some(i => i.parentId === 'root');
    vaultClipboard.type = hasGroups ? 'groups' : 'items';

    // Turn off selection mode
    setSelectionMode(false);

    // Auto-navigate to root
    navigateToRoot();

    showStatusMessage(`${vaultClipboard.items.length} items cut. Select a group to paste.`, "info");

    // Re-render so we see the Group List now
    refresh();
}

async function _doPasteClick() {
    const { groupId, executeCrossVaultPaste, refresh } = _vaultCtx();

    // The vault does the heavy lifting and tells us if it worked
    const result = executeCrossVaultPaste(groupId);

    if (result.success) {
        showStatusMessage(`Successfully moved ${result.count} ${result.type}`, "success");
        refresh(); // UI updates to show the items now exist in the new data
    } else {
        showStatusMessage(result.message, "error");
    }
}

async function _doAddClick() {
    const { depth, path, refresh } = _vaultCtx();
    log("explorer._doAddClick", "called - depth:", depth);

    if (depth < 3) {
        showAddNewUI(path[depth-1], {
            onAdd: (name, archived) => {
                if (depth === 1) _executeAddGroup(name, archived);
                else if (depth === 2) _executeAddItem(name);
            },
            onCancel: () => {
                refresh();
            }
        });
    }
}

async function _doRenameClick() {
    const { depth, refresh } = _vaultCtx();
    log("explorer._doRenameClick", "called - depth:", depth);

    // We only rename things we are currently "inside" or looking at
    if (depth < 2) return;

    showRenameUI({
        onRename: (newName, prevArchived, newArchived) => {
            if (depth === 2) _executeRenameGroup(newName, prevArchived, newArchived);
            else if (depth === 3) _executeRenameItem(newName);
        },
        onCancel: () => {
            refresh();
        }
    });
}

async function _doDeleteClick() {
    const { depth, refresh } = _vaultCtx();

    log("explorer._doDeleteClick", "called - depth:", depth);

    if (depth < 2) {
        warn("explorer._doDeleteClick", "Nothing selected to delete, ignoring delete");
        return; // Can't delete the root vault
    }

    showDeleteUI({
        onConfirm: () => {
            _executeDeletion();
        },
        onCancel: () => {
            refresh();
        }
    });
}

async function _doToggleEditClick() {
    const { isEditable, toggleEditable } = _vaultCtx();
    
    if (isEditable) {
        // We are EXITING edit mode.
        // Update the timestamp now.
        const item = getCurrentItem();
        if (item) item.modified = new Date().toISOString();
    }
    // Internally refreshes vault
    toggleEditable();
}

async function _doPrivateVaultClick() {
    log("explorer._doPrivateVaultClick", "called");

    const { hasPrivateVaultData, isPrivateMode, privateDataPointer } = _vaultCtx();

    if (isPrivateVaultUnlocked()) {
        if (hasPrivateVaultData() && !isPrivateMode)
            toggleVaultMode('private');
        else {
            lockPrivateVault();
            toggleVaultMode('shared');
        }
        return
    }

    // 2. Check if a private vault pointer exists in the main vault extensions
    const emailHash = await CR.hashString(G.userEmail);
    const pointer = privateDataPointer(emailHash);

    if (!pointer) {
        // CASE A: GENESIS (No vault found for this email)
        await showCreatePrivateVaultUI(async (result) => handlePrivateVaultGenesis(result));
    } else {
        // CASE B: UNLOCK (Vault exists, need password)
        await promptPrivateVaultPassword(pointer, emailHash, async (pwd, data) => handlePrivateVaultUnlock(pwd, data));
    }
}

function _executeAddGroup(name, archived = false) {
    log("explorer._executeAddGroup", `called - name:${name} archived: ${archived}`);

    const { activeData, path, refresh, isArchiveModeActive, navigateToRoot } = _vaultCtx();
    const newId = 'g-' + CR.generateUUID();

    const newGroup = { id: newId, name: name, items: [] };

    if (archived) {
        activeData.archived.push(newGroup);
        log("explorer._executeAddGroup", "Group moved to ARCHIVED array");
    } else {
        activeData.groups.push(newGroup);
        log("explorer._executeAddGroup", "Group moved to ACTIVE groups array");
    }

    // 4. Auto-navigate into the new group
    if (isArchiveModeActive !== archived) navigateToRoot()
    else path.push(newId);
    refresh();
}

function _executeAddItem(name) {
    log("explorer._executeAddItem", "called - name:", name);
    const { findActiveGroup, refresh } = _vaultCtx();

    const group = findActiveGroup();
    const now = new Date().toISOString();
    const newItem = {
        id: 'i-' + CR.generateUUID(),
        label: name,
        created: now, modified: now,
        fields: [{ type: 'text', key: 'Username', val: '' }, { type: 'secure', key: 'Password', val: '' }, { type: 'note', key: 'Notes', val: '' }]
    };
    group.items.push(newItem);
    refresh();
}

function _executeRenameGroup(newName, prevArchived = false, newArchived = false) {
    log("explorer._executeRenameGroup", `called - newName:${newName} prevArchived:${prevArchived} newArchived:${newArchived}`);

    const { activeData, groupId, navigateToRoot, refresh } = _vaultCtx();

    const currentBucket = prevArchived ? activeData.archived : activeData.groups;
    const groupIdx = currentBucket?.findIndex(g => g.id === groupId);

    if (groupIdx !== -1) {
        const group = currentBucket[groupIdx];
        group.name = newName;

        // if switched buckets (active to archived or vice versa)
        if (prevArchived !== newArchived) {
            log("explorer._executeRenameGroup", "Transferring group between buckets");
            // Remove from current and push to target
            const [movedGroup] = currentBucket.splice(groupIdx, 1);
            const targetBucket = newArchived ? activeData.archived : activeData.groups;
            targetBucket.push(movedGroup);
            navigateToRoot();
        }
    } else warn("explorer._executeRenameGroup", "no group to rename, skipping");

    refresh();
}

function _executeRenameItem(newName) {
    log("explorer._executeRenameItem", `called - newName:${newName}`);

    const { findActiveGroup, findActiveItem, refresh } = _vaultCtx();

    const item = findActiveItem(findActiveGroup());
    if (item) {
        item.label = newName;
        item.modified = new Date().toISOString();
    } else warn("explorer._executeRenameItem", "no item to rename, skipping");

    refresh();
}

function _executeDeletion() {
    log("explorer._executeDeletion", "called");

    const { activeData, depth, path, groupId, itemId, isArchiveModeActive, navigateToRoot, refresh } = _vaultCtx();

    const bucket = isArchiveModeActive ? activeData.archived : activeData.groups;

    if (depth === 2) {
        // --- DELETE GROUP ---
        const index = bucket?.findIndex(g => g.id === groupId);

        if (index > -1) {
            bucket.splice(index, 1);
            // After deleting a group, we must go back to the root
            navigateToRoot();
        }
    }
    else if (depth === 3) {
        // --- DELETE ITEM ---
        const group = bucket?.find(g => g.id === groupId);

        if (group) {
            const index = group.items.findIndex(i => i.id === itemId);
            if (index > -1) {
                group.items.splice(index, 1);
                // After deleting an item, go back to the group list
                path.pop();
            }
        }
    }

    refresh();
}

/**
 * Resolves an ID to a human-readable name for the breadcrumb
 */
function _getNameFromId(id, index) {

    const { findActiveGroup, findActiveItem, isPrivateMode, isArchiveModeActive } = _vaultCtx();

    if (id === 'root') {
        // Archive mode takes visual precedence for the root icon
        if (isArchiveModeActive) return "📦";
        return isPrivateMode ? "🛡️" : "🏠";
    }

    if (index === 1) { // It's a Group ID
        const group = findActiveGroup();
        return group ? group.name : "Unknown Group";
    }
    if (index === 2) { // It's an Item ID
        const item = findActiveItem(findActiveGroup());
        return item ? item.label : "Unknown Item";
    }
    return id;
}

async function _handlePrivateVaultBiometricAction() {
    log("explorer._handlePrivateVaultBiometricAction", "Initializing biometric pipeline run...");

    const { isPrivateMode, privateDataPointer } = _vaultCtx();
    const emailHash = await CR.hashString(G.userEmail);
    const pointer = privateDataPointer(emailHash);

    if (!pointer) {
        showSilentToast("Create a private vault first before enabling biometrics.");
        return;
    }

    // 1. Check registration using the exact function name exported in your module
    const isRegistered = await BM.isBiometricRegistered('private');

    if (isRegistered) {
        if (isPrivateVaultUnlocked() && !isPrivateMode) {
            log("explorer.biometric", "Private Vault already hot in memory. Fast-tracking transition.");
            showSilentToast("Switching to Private Vault... 🛡️");

            // Explicitly call your framework's view switcher
            toggleVaultMode('private');
            return;
        }

        try {
            showSilentToast("Scanning biometrics...");

            // 2. Trigger the WebAuthn Assertion pipeline for the 'private' workspace boundary
            await BM.attemptBiometricUnlock('private', async (retrievedPassword) => {
                log("explorer.biometric", "Hardware keys verified. Executing structural decryption pass...");

                // 3. Bypass UI modal prompts and inject credentials straight into the engine
                await promptPrivateVaultPassword(pointer, emailHash, async (pwd, data) => {
                    // This mirrors your standard _doPrivateVaultClick logic flow
                    handlePrivateVaultUnlock(pwd, data);
                    showSilentToast("Unlocked with Biometrics! 🛡️");
                }, retrievedPassword);
            });

        } catch (err) {
            error("explorer.biometric.failure", "Biometric processing flow broke:", err);
            showOverlayAlertUI({
                title: "Biometric Authentication Failed",
                message: "Could not verify device credentials. Tap the home icon normally to fall back to your Master Password."
            });
        }
    } else {
        // ─── REGISTRATION PASS ───
        showOverlayAlertUI({
            title: "Setup Quick Biometric Access",
            message: "To link your biometric profile, you must first verify your access configuration with your Private Password. Click OK to authenticate.",
            okText: "Continue",
            onConfirm: async () => {
                // Force traditional password prompt pass first
                await promptPrivateVaultPassword(pointer, emailHash, async (verifiedPassword, decryptedData) => {
                    // This block fires ONLY if their manually entered password was 100% correct
                    handlePrivateVaultUnlock(verifiedPassword, decryptedData);

                    try {
                        showSilentToast("Enrolling biometric hardware...");

                        // 4. Call your internal enrollment engine to bind the verified secret to WebAuthn
                        await BM.enrollBiometric(verifiedPassword, 'private');

                        showOverlayAlertUI({
                            title: "Success",
                            message: "Biometrics successfully linked! You can now hold down the Home button to fast-track unlock this vault."
                        });
                    } catch (regErr) {
                        error("explorer.biometric.registration", "Hardware enrollment failed:", regErr);
                        showOverlayAlertUI({ title: "Enrollment Failed", message: "Device biometric enrollment was cancelled or rejected." });
                    }
                });
            }
        });
    }
}

function _renderBreadcrumbs() {
    const breadcrumbs = vaultNavBarUI.breadcrumbs;
    if (!breadcrumbs) return;

    breadcrumbs.innerHTML = "";

    const { atRoot, path, isPrivateMode, isArchiveModeActive } = _vaultCtx();

    // Determine if the user is currently looking at the root of the active vault
    const isCurrentlyAtRoot = atRoot();

    path.forEach((id, index) => {
        const isRootNode = (id === 'root');
        const isLast = index === path.length - 1;
        const label = _getNameFromId(id, index);

        const span = document.createElement('span');

        // We make the root node ALWAYS look like a link if we are at root
        // so the user knows they can click it to switch vaults.
        const canSwitch = isRootNode && isCurrentlyAtRoot;

        let classList = ['breadcrumb-item'];
        classList.push((isLast && !canSwitch) ? 'active' : 'link');

        // Add a specific hook for Archive styling if active
        if (isRootNode && isArchiveModeActive) classList.push('archive-root');

        span.className = classList.join(' ');
        span.innerText = label;

        if (isRootNode) {

            let pressTimer = null;
            let isLongPress = false;

            // 🟢 SAFARI / MOBILE FIX: Kill the native OS pop-up magnifier/preview bubble
            span.style.webkitTouchCallout = 'none'; // iOS Safari
            span.style.userSelect = 'none';         // Standard modern fallback

            // Local helper to evaluate the full dynamic rule snapshot instantly
            const checkBiometricIntentValid = () => {
                return isCurrentlyAtRoot &&
                    !isArchiveModeActive &&
                    !isPrivateMode;
            };

            // 🟢 UNIVERSAL MOBILE FIX: Prevent mobile OS long-press menu from appearing
            span.oncontextmenu = (e) => {
                if (checkBiometricIntentValid()) {
                    e.preventDefault();
                    e.stopPropagation();
                    return false;
                }
            };

            // ─── BIOMETRIC LONG-PRESS HOOK WITH CONTEXTUAL GUARDS ───
            span.onpointerdown = (e) => {
                if (e.button !== 0) return; // Ignore right-clicks

                if (!checkBiometricIntentValid()) {
                    // Log the reason why the hold engine is bypassed for transparency
                    trace("explorer.root.onpointerdown", "Long-press ignored: Context does not meet biometric criteria.", {
                        isCurrentlyAtRoot,
                        isArchiveModeActive,
                        isPrivateMode,
                        isPrivateVaultUnlocked: isPrivateVaultUnlocked()
                    });
                    return;
                }
                isLongPress = false;

                // Arm the countdown timer
                pressTimer = setTimeout(() => {
                    isLongPress = true;
                    log("explorer.root.onlongpress", "Biometric Long Press Verified!");
                    _handlePrivateVaultBiometricAction();
                }, C.PRIVATE_VAULT_BIO_DELAY_MS);
            };

            // Teardown the ticking timer if the user releases or slides off early
            span.onpointerup = () => { if (pressTimer) clearTimeout(pressTimer); };
            span.onpointercancel = () => { if (pressTimer) clearTimeout(pressTimer); };

            // ─── CLICK HANDLER: FALLBACK PASS-THROUGH ───
            span.onclick = async (e) => {

                if (isLongPress) {
                    log("explorer.root.onclick", "Bypassing standard sub-click routing. Long press intercept active.");
                    isLongPress = false; // Reset tracking flag
                    return;
                }

                // Standard navigation flows are safely preserved here
                if (isCurrentlyAtRoot) {
                    // --- CONTEXT SWITCHER ---
                    // Triggered by clicking the icon while already at the top level.
                    if (isArchiveModeActive) {
                        // 1. If in Archive, clicking 📦 exits back to the Active Vault
                        log("explorer.root.onclick", "Exiting Archive Mode");
                        toggleVaultMode(isPrivateMode ? 'private' : 'shared');
                    } else {
                        // 2. Otherwise, standard toggle between Shared (🏠) and Private (🛡️)
                        log("explorer.root.onclick", "Toggling Shared/Private Vaults");
                        if (isPrivateMode) {
                            toggleVaultMode('shared');
                        } else {
                            await _doPrivateVaultClick();
                        }
                    }

                } else {
                    // --- RESET TO ROOT ---
                    // Triggered by clicking the icon while deep in a group or item.
                    log("explorer.nonroot.onclick", "Resetting to current vault root");
                    resetToRoot();
                }
            };

        } else {
            // Standard back-navigation click for regular group breadcrumbs
            // Navigating to a specific Group in the path.
            span.onclick = () => {
                if (!isLast) navigateToPath(index + 1);
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

function _renderGroupList(container) {
    log("explorer._renderGroupList", "called");

    const { activeData, currentFilterMap, currentSearchQuery, vaultClipboard, isArchiveModeActive } = _vaultCtx();

    container.innerHTML = ""; // Clear existing

    // 1. SELECT THE SOURCE ARRAY
    // This is the O(1) optimization: we pick the bucket based on the mode.
    const bucket = isArchiveModeActive ? (activeData.archived || []) : (activeData.groups || []);

    if (bucket.length === 0) {
        const emptyMsg = isArchiveModeActive ? "No archived groups." : "No groups found.";
        container.innerHTML = `<div class="empty-state">${emptyMsg}</div>`;
        return;
    }

    // 2. Sort the selected source
    const sortedGroups = sortVaultData(bucket, 'group');
    sortedGroups.forEach(group => {

        // FILTER CHECK: Skip if not visible in search
        if (currentFilterMap && !currentFilterMap.visible.has(group.id)) {
            return;
        }

        let matchDensity = 0;
        if (currentFilterMap) {
            const hits = currentFilterMap.highlighted;

            // 1. Check if the Group name itself matched
            if (hits.has(group.id)) matchDensity++;

            // 2. Check Items and their Fields
            group.items.forEach(item => {
                // Did the Item label match?
                if (hits.has(item.id)) matchDensity++;

                // Check split tracking suffixes independently to calculate accurate match densities
                if (item.fields) {
                    item.fields.forEach(f => {
                        if (hits.has(`${item.id}-field-${f.key}-label`)) matchDensity++;
                        if (hits.has(`${item.id}-field-${f.key}-value`)) matchDensity++;
                    });
                }
            });
        }

        // 1. Check if the GROUP ITSELF is selected (the root-level move)
        const isGroupSelected = vaultClipboard.items.some(i => i.id === group.id && i.parentId === 'root');

        // 2. Check if ITEMS INSIDE this group are selected (the item-level move)
        const hasSelectedItems = vaultClipboard.items.some(i => i.parentId === group.id);

        // 3. Determine the CSS classes
        let classList = ['list-row'];
        if (isGroupSelected) classList.push(vaultClipboard.mode === 'cut' ? 'to-be-moved' : 'selected');
        if (hasSelectedItems) classList.push('source-group-active'); // Children are moving

        // --- ARCHIVE LOGIC: Ghostly styling for items in Archive view ---
        if (isArchiveModeActive) classList.push('archive-mode-item');

        if (currentFilterMap?.highlighted.has(group.id)) classList.push('search-highlight');

        const div = document.createElement('div');
        div.className = classList.join(' ');

        // Only show badge if density > 0
        const matchBadge = (currentFilterMap && matchDensity > 0)
            ? `<span class="match-count-badge">${matchDensity}</span>`
            : '';

        div.innerHTML = `
            <span class="row-label">📁 ${group.name}</span>
            <div class="row-status-area">
                ${matchBadge}
                <span class="count">${group.items.length}</span>
            </div>
        `;

        div.onclick = () => {
            const { isSelectionMode, depth, vaultClipboard, onNavigate } = _vaultCtx();

            // Check: Are we already "cherry-picking" items?
            // If we have items in the clipboard that AREN'T groups, we are in Item-Mode.
            const isPickingItems = vaultClipboard.items.some(i => i.parentId !== 'root');

            if (isSelectionMode && depth === 1 && !isPickingItems) {
                _toggleGroupSelection(group.id, div);
            } else {
                // Otherwise: Navigate (even if selection mode is ON).
                // This allows you to go inside groups to cherry-pick items.
                hideFilterUI();
                onNavigate(group.id);
            }
        };
        container.appendChild(div);
    });

    // Handle empty state for the specific mode
    if (container.children.length === 0) {
        const msg = currentSearchQuery
            ? `No data matching "${currentSearchQuery}" in ${isArchiveModeActive ? 'archive' : 'vault'}.`
            : `No ${isArchiveModeActive ? 'archived' : 'active'} groups.`;
        container.innerHTML = `<div class="empty-state">${msg}</div>`;
    }
}

function _toggleGroupSelection(id, element) {
    const { vaultClipboard, refresh } = _vaultCtx();

    const index = vaultClipboard.items.findIndex(i => i.id === id);

    // Use a consistent class name based on the mode
    const activeClass = vaultClipboard.mode === 'cut' ? 'to-be-moved' : 'selected';

    if (index > -1) {
        vaultClipboard.items.splice(index, 1);
        element.classList.remove('selected', 'to-be-moved');
    } else {
        // Parent is 'root' because these are top-level groups
        vaultClipboard.items.push({ id: id, parentId: 'root' });
        element.classList.add(activeClass);
    }

    refresh();
}

function _renderItemList(container, groupId) {
    log("explorer._renderItemList", "called");
    const { isSelectionMode, currentFilterMap, vaultClipboard, findActiveGroup, isArchiveModeActive } = _vaultCtx();

    container.innerHTML = "";

    const group = findActiveGroup();

    if (!group) {
        warn("explorer._renderItemList", `Group ${groupId} not found in ${isArchiveModeActive ? 'archive' : 'active'} bucket.`);
        container.innerHTML = `<div class="empty-state">This group is no longer in this view.</div>`;
        return;
    }

    // 💡 EMPTY STATE TWEAK:
    if (group.items.length === 0) {
        container.innerHTML = `<div class="empty-state">This group is empty.</div>`;
        return;
    }

    const sortedItems = sortVaultData(group.items, 'item');
    sortedItems.forEach(item => {

        // FILTER CHECK: Skip if item is hidden by filter
        if (currentFilterMap && !currentFilterMap.visible.has(item.id)) {
            return;
        }

        let matchDensity = 0;
        if (currentFilterMap) {
            const hits = currentFilterMap.highlighted;

            // 1. Did the Item label itself match?
            if (hits.has(item.id)) matchDensity++;

            // 2. Account for multi-hits where label text and values match criteria simultaneously
            if (item.fields) {
                item.fields.forEach(f => {
                    if (hits.has(`${item.id}-field-${f.key}-label`)) matchDensity++;
                    if (hits.has(`${item.id}-field-${f.key}-value`)) matchDensity++;
                });
            }
        }

        const div = document.createElement('div');

        // 1. Check if item is in the clipboard (works for both Selection and Cut modes)
        const isSelected = vaultClipboard.items.some(i => i.id === item.id);

        // 💡 HIGHLIGHT CHECK: Is this item title a match?
        const isMatch = currentFilterMap?.highlighted.has(item.id);

        let classList = ['list-row'];
        if (isSelected) classList.push(vaultClipboard.mode === 'cut' ? 'to-be-moved' : 'selected');
        if (isMatch) classList.push('search-highlight');
        if (isArchiveModeActive) classList.push('archive-mode-item'); // Ghostly styling

        div.className = classList.join(' ');

        // 💡 THE TOGGLE LOGIC:
        // If we have a match, show the badge. If not, show the standard arrow.
        const rightIndicator = (currentFilterMap && matchDensity > 0)
            ? `<span class="match-count-badge">${matchDensity}</span>`
            : `<span class="arrow">›</span>`;

        div.innerHTML = `
            <span class="row-label">📄 ${item.label}</span>
            <div class="row-status-area">
                ${rightIndicator}
            </div>
        `;

        div.onclick = () => {
            // 2. If we are selecting OR if the item is already "Cut",
            // clicking should only toggle selection/do nothing, not navigate.
            if (isSelectionMode || vaultClipboard.mode === 'cut') {
                _toggleItemSelection(item.id, div, groupId);
            } else {
                // Normal navigation
                hideFilterUI();
                const { onNavigate } = _vaultCtx();
                onNavigate(item.id);
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

function _toggleItemSelection(id, element, groupId) {
    const { vaultClipboard, refresh } = _vaultCtx();

    // Safety: If user accidentally has groups selected, clear them to prevent mixed-type move
    if (vaultClipboard.items.some(i => i.parentId === 'root')) {
        vaultClipboard.items = [];
    }

    const index = vaultClipboard.items.findIndex(i => i.id === id);

    if (index > -1) {
        vaultClipboard.items.splice(index, 1);
        element.classList.remove('selected', 'to-be-moved');
    } else {
        // WE MUST STORE THE PARENT ID HERE
        vaultClipboard.items.push({ id: id, parentId: groupId });

        const { vaultClipboard: clipboardState } = _vaultCtx();
        const activeClass = clipboardState.mode === 'cut' ? 'to-be-moved' : 'selected';
        element.classList.add(activeClass);
    }
    refresh();
}

function _renderItemDetails(container) {
    log("explorer._renderItemDetails", "called");
    const { currentFilterMap, isEditable, showSecure, findActiveGroup, findActiveItem } = _vaultCtx();

    const item = findActiveItem(findActiveGroup());

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
    const createdStr = item.created ? new Date(item.created).toLocaleString(undefined, dateOpts) : "";
    const modifiedStr = item.modified ? new Date(item.modified).toLocaleString(undefined, dateOpts) : "";
    const isModified = item.created !== "" && item.created !== item.modified;
    metaBar.innerHTML = `
        <span class="meta-left">${createdStr}</span>
        ${isModified ? `<span class="meta-right">${modifiedStr}</span>` : ''}
    `;
    detailEl.appendChild(metaBar);

    const readonlyAttr = isEditable ? "" : "readonly";

    // 2. Render Standard Fields (Text, Secure, Note)
    item.fields.forEach((field, index) => {
        // Build independent tracking IDs matching the search-and-sort architecture updates
        const labelMatchID = `${item.id}-field-${field.key}-label`;
        const valueMatchID = `${item.id}-field-${field.key}-value`;

        const isLabelMatch = currentFilterMap?.highlighted.has(labelMatchID);
        const isValueMatch = currentFilterMap?.highlighted.has(valueMatchID);

        const fieldBox = document.createElement('div');
        fieldBox.className = `field-box ${isEditable ? 'editable' : ''}`;

        // Add the expand icon ONLY if it's a note
        const expandBtnHtml = (field.type === 'note') ?
            `<button class="icon-btn expand-note-btn" data-index="${index}" title="Expand Note">⛶</button>` : '';

        // 🔼 🔽 Dynamically calculate boundaries so we can hide or disable unneeded actions
        const isFirst = index === 0;
        const isLast = index === item.fields.length - 1;

        const moveButtonsHtml = isEditable ? `
            <button class="icon-btn move-up-btn" data-index="${index}" ${isFirst ? 'disabled style="opacity:0.3; cursor:default;"' : ''} title="Move Up">🔼</button>
            <button class="icon-btn move-down-btn" data-index="${index}" ${isLast ? 'disabled style="opacity:0.3; cursor:default;"' : ''} title="Move Down">🔽</button>
        ` : '';

        // Label input gets the '.search-label-hit' class ONLY if the label string matched the search criteria
        let html = `
            <div class="field-header">
                <input type="text" class="label-input ${isLabelMatch ? 'search-label-hit' : ''}"
                   data-index="${index}" value="${field.key}" ${readonlyAttr} placeholder="Label">
                <div class="field-actions">
                    ${expandBtnHtml}
                    ${isEditable ?
                        `<button class="icon-btn delete-field-btn" data-index="${index}">🗑️</button>` :
                        `<button class="icon-btn copy-btn" data-val="${field.val}">📋</button>`
                    }
                    ${moveButtonsHtml}
                </div>
            </div>`;

        // If the data input matched, apply a highlighted style flag to the target input node wrapper
        const highlightedInputClass = isValueMatch ? 'search-highlight' : '';

        if (field.type === 'secure') {
            html += `<div class="input-wrap ${highlightedInputClass}"><input type="${showSecure ? 'text' : 'password'}" class="field-input" data-index="${index}" value="${field.val}" ${readonlyAttr} spellcheck="false"></div>`;
        } else if (field.type === 'note') {
            html += `<textarea class="field-input note-field ${highlightedInputClass}" data-index="${index}" ${readonlyAttr} rows="4">${field.val}</textarea>`;
        } else {
            html += `<div class="input-wrap ${highlightedInputClass}"><input type="text" class="field-input" data-index="${index}" value="${field.val}" ${readonlyAttr}></div>`;
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
                if (fileObj) _handleDownloadAttachment(fileObj);
                return;
            }

            // Handle Delete
            const deleteBtn = e.target.closest('.delete-attachment-btn');
            if (deleteBtn) {
                // 1. STOP the click from traveling up to the main vault listeners
                e.stopPropagation();
                e.preventDefault();

                const index = deleteBtn.getAttribute('data-index');
                _handleDeleteAttachment(item, index);
            }
        };

        item.attachments.forEach((file, index) => {
            const sizeKB = Math.round(file.meta.size / 1024);

            // 💡 HIGHLIGHT LOGIC: Construct the ID used in search-and-sort.js
            const attachmentMatchID = `${item.id}-attachment-${file.val}`;
            const isMatch = currentFilterMap?.highlighted.has(attachmentMatchID);

            const fileRow = document.createElement('div');
            fileRow.className = `attachment-row ${isMatch ? 'filter-match' : ''}`;

            fileRow.innerHTML = `
            <a href="#" class="file-link" data-id="${file.val}">📄 ${file.key} (${sizeKB} KB)</a>
            <div class="field-actions">
                ${isEditable ?
                `<button class="icon-btn delete-attachment-btn" data-index="${index}">🗑️</button>` : ''}
            </div>
        `;
            attachmentSection.appendChild(fileRow);
        });

        detailEl.appendChild(attachmentSection);
    }

    // 4. Field Template (Existing)
    if (isEditable) {
        _addNewFieldTemplate(detailEl, item);
    }

    container.appendChild(detailEl);
    _attachDetailListeners(container, item); // Pass item to handle file actions
}

function _expandNote(index, itemObject, isEditable) {
    const field = itemObject.fields[index];
    const overlay = document.createElement('div');
    overlay.className = 'full-screen-note-overlay';

    const readonlyAttr = isEditable ? "" : "readonly";

    overlay.innerHTML = `
        <div class="note-overlay-header">
            <span>${isEditable ? 'Edit ' : ''}${field.key}</span>
            <button class="close-x-btn">✕</button>
        </div>
        <textarea class="note-overlay-content" ${readonlyAttr}>${field.val}</textarea>
    `;

    document.body.appendChild(overlay);

    const textarea = overlay.querySelector('.note-overlay-content');
    const closeBtn = overlay.querySelector('.close-x-btn');

    textarea.focus();

    const closeAndSync = () => {
        if (isEditable) {
            field.val = textarea.value;
            itemObject.modified = new Date().toISOString();
            const { refresh } = _vaultCtx();
            refresh();
        }
        overlay.remove();
    };

    closeBtn.onclick = closeAndSync;

    // Optional: Close on Escape key
    overlay.onkeydown = (e) => { if(e.key === 'Escape') closeAndSync(); };
}

async function _handleDownloadAttachment(attachment) {
    try {
        log("explorer._handleDownloadAttachment", `Opening: ${attachment.key}`);

        // 1. Get the decrypted bytes from the Envelope layer
        const plaintext = await AT.openAttachment(attachment);

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

        info("explorer._handleDownloadAttachment", "File delivered.");

    } catch (err) {
        error("explorer._handleDownloadAttachment", "Failed to open file", err);
        showOverlayAlertUI({
            title: "Attachment Error",
            message: "Failed to download or decrypt file."
        });
    }
}

async function _handleDeleteAttachment(item, index) {
    const attachment = item.attachments[index];
    if (!attachment) return;

    showOverlayConfirmUI({
        title: `Remove ${attachment.key}?`,
        message: `This will remove the attachment from the vault. Changes are pending until you click 'Save'.`,
        okText: "Remove",
        onConfirm: async () => {

            const { onAttachmentDelete, refresh } = _vaultCtx();

            // 1. Add the Drive File ID to our "Hit List"
            if (attachment.val) onAttachmentDelete(attachment.val);

            // 2. Remove from the local vaultData array immediately
            item.attachments.splice(index, 1);
            item.modified = new Date().toISOString();

            // 3. Refresh the UI - the file disappears instantly!
            refresh();

            showSilentToast("Removed. Remember to Save changes.");
        }
    });
}

function _addNewFieldTemplate(targetElement, itemObject) {
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
    const { refresh } = _vaultCtx();

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
            refresh();
        }
    };

    fileInput.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const label = document.getElementById('newField_label').value.trim();
        await _handleUploadAttachment(file, label, itemObject);

        refresh();
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

async function _handleUploadAttachment(file, label, itemObject) {
    // 1. Create a temporary ID to find this specific UI row later
    const tempId = "up_" + Date.now();
    const fileName = label || file.name;

    try {
        log("explorer._handleUploadAttachment", `Starting upload for: ${fileName}`);

        // 1. Find the container
        let container = document.querySelector('.attachment-section');

        // SAFETY: If the section doesn't exist yet (first upload for this item),
        // find the main detail container and inject it.
        if (!container) {
            container = document.createElement('div');
            container.className = 'attachment-section';
            vaultUI.explorer.appendChild(container);
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

        let mimeType = file.type || (file.name.endsWith('.zip') ? 'application/zip' : '');
        log("explorer._handleUploadAttachment", "mimeType:", mimeType);

        const { isPrivateMode, onAttachmentUpload, refresh } = _vaultCtx();

        const attachmentEntry = await AT.saveAttachment(isPrivateMode ? C.PRIVATE_ATTACHMENTS_FOLDER_NAME : C.ATTACHMENTS_FOLDER_NAME,
            fileName, binary, file.type);

        // attachmentEntry.val is the Google Drive File ID.
        // We add it to our 'pendingFileUploads' so we can nuke it if they hit Discard.
        if (attachmentEntry && attachmentEntry.val) {
            onAttachmentUpload(attachmentEntry.val);
        }

        // 4. Update memory
        if (!itemObject.attachments) itemObject.attachments = [];
        itemObject.attachments.push(attachmentEntry);
        itemObject.modified = new Date().toISOString();

        // 5. Success! The full render will now replace our temp row
        refresh();
        info("explorer._handleUploadAttachment", "Upload complete.");

    } catch (err) {
        // Remove the failed spinner if it exists
        document.getElementById(tempId)?.remove();
        error("explorer._handleUploadAttachment", "Upload Error:", err);
        showOverlayAlertUI({
            title: "Upload Error",
            message: "Failed to upload attachment. Check logs for details."
        });
    }
}

function _attachDetailListeners(container) {
    const item = getCurrentItem();
    if (!item) return;

    const { toggleShowSecure, isEditable, refresh } = _vaultCtx();

    // 1. Toggle Password Visibility
    // Redraws the UI to switch between dots (••••) and plain text
    container.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.onclick = () => toggleShowSecure();
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

    container.querySelectorAll('.expand-note-btn').forEach(btn => {
        btn.onclick = () => {
            const index = btn.dataset.index;
            _expandNote(index, item, isEditable);
        };
    });

    container.querySelectorAll('.move-up-btn').forEach(btn => {
        btn.onclick = (e) => {
            e.stopPropagation();
            const index = parseInt(btn.dataset.index, 10);
            if (index > 0) {
                log("explorer.fields.moveUp", `Moving field from index ${index} to ${index - 1}`);

                // Swap in-place
                const temp = item.fields[index];
                item.fields[index] = item.fields[index - 1];
                item.fields[index - 1] = temp;

                // Flag modification timeline and redraw
                item.modified = new Date().toISOString();
                refresh();
            }
        };
    });

    // ─── NEW: Move Field Down Logic ───
    container.querySelectorAll('.move-down-btn').forEach(btn => {
        btn.onclick = (e) => {
            e.stopPropagation();
            const index = parseInt(btn.dataset.index, 10);
            if (index < item.fields.length - 1) {
                log("explorer.fields.moveDown", `Moving field from index ${index} to ${index + 1}`);

                // Swap in-place
                const temp = item.fields[index];
                item.fields[index] = item.fields[index + 1];
                item.fields[index + 1] = temp;

                // Flag modification timeline and redraw
                item.modified = new Date().toISOString();
                refresh();
            }
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
                    refresh();
                }
            });
        };
    });
}
