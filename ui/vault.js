import { C, G, inReadOnlyMode, AU, E, U, log, trace, debug, info, warn, error } from '../exports.js';

import { logout } from '../app.js';
import { loadUI, swapVisibility } from './uihelper.js';

import { rootUI, vaultUI, vaultRawDataUI, copyLogsToClipboard } from './loader.js';
import { showRecoveryRotationUI, hideRecoveryRotation } from './recovery-rotation.js';
import { showAddNewUI, showRenameUI, showDeleteUI, hideAddDelete } from './add-rename-delete.js';

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

let vaultData = null;

let sessionState = {
    path: ['root'],       // The navigation stack
    isEditable: false,    // Global toggle for Phase 5
    showSecure: false     // Global toggle for Requirement 1
};

async function init() {
    log("vaultUI.init", "called");

    sessionState.path = ['root'];

    swapVisibility(rootUI.loginView, vaultUI.mainSection);

    // Don't need this IF swapVisibility uses vaultUI.mainSection instead of rootUI.vaultView
    //vaultUI.mainSection.setVisible(true);

    vaultRawDataUI.mainSection.setVisible(false);
    hideRecoveryRotation();
    hideAddDelete();

    vaultUI.logoutMenu.onClick(() => doLogout());

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
    vaultUI.recoveryRotationMenu.onClick(showRecoveryRotationUI);

    vaultUI.title.onClick(doToggleSecureClick);
    vaultUI.toggleSecureBtn.onClick(doToggleSecureClick);
    vaultUI.addBtn.onClick(doAddClick);
    vaultUI.renameBtn.onClick(doRenameClick);
    vaultUI.deleteBtn.onClick(doDeleteClick);

    // temporary menu
    vaultUI.copyLogsMenu.onClick(copyLogsToClipboard);
    vaultUI.toggleLogsMenu.onClick(toggleLogs);

    // Ensure these containers always use flex when shown
    //vaultRawDataUI.mainSection.setFlex();
    //vaultUI.mainSection.setFlex();
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
    sessionState.path = ['root']; // Reset breadcrumbs to root

    // 3. Clear the DOM (Prevents seeing old data for a split second on re-login)
    vaultUI.breadcrumbs.clear();
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
    log("vaultUI.doSaveClick", "called - depth:", depth);

    if (depth < 3) {
        vaultUI.mainSection.setVisible(false);
        showAddNewUI(depth, sessionState.path[depth-1], vaultData, {
            onAdd: (name) => {
                if (depth === 1) executeAddGroup(name);
                else if (depth === 2) executeAddItem(name);

                vaultUI.mainSection.setVisible(true);
                refreshAddDeleteBtnVisibility();
            },
            onCancel: () => {
                vaultUI.mainSection.setVisible(true);
                refreshAddDeleteBtnVisibility();
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
            refreshAddDeleteBtnVisibility();
        },
        onCancel: () => {
            vaultUI.mainSection.setVisible(true);
            refreshAddDeleteBtnVisibility();
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
            refreshAddDeleteBtnVisibility();
        },
        onCancel: () => {
            vaultUI.mainSection.setVisible(true);
            refreshAddDeleteBtnVisibility();
        }
    });
}

function refreshAddDeleteBtnVisibility() {

    const writeable = !inReadOnlyMode();
    const depth = sessionState.path.length;

    let a = true, b = true;
    if (depth === 1) b = false;
    else if (depth === 3) a = false;

    vaultUI.addBtn.setVisible(a && writeable);
    vaultUI.renameBtn.setVisible(b && writeable);
    vaultUI.deleteBtn.setVisible(b && writeable);

    //log("vaultUI.refreshAddDeleteBtnVisibility", `depth:${depth} a:${a} b:${b}`);
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
        log("vaultUI.doSaveClick", "Save successful.");
        showStatusMessage(`Saved changes at ${U.getCurrentTime()}`, "success");
    } catch (err) {
        error("vaultUI.doSaveClick", "Encryption/Persistence failed:", err);
        showStatusMessage(`Save failed: ${err.message || err}`, "error");
    }
    //alert("Saved!");
}

export function executeAddGroup(name) {
    log("vaultUI.executeAddGroup", "called - name:", name);

    const newId = 'g-' + Date.now();
    const newGroup = { id: newId, name: name, items: [] };
    vaultData.groups.push(newGroup);

    // Auto-navigate into the new group
    sessionState.path.push(newId);
    renderVaultExplorer();
}

export function executeAddItem(name) {
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

export function executeDeletion() {
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
    const nav = document.getElementById('vault_breadcrumbs');
    if (!nav) return;

    nav.innerHTML = "";
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

        nav.appendChild(span);
        if (!isLast) {
            const sep = document.createElement('span');
            sep.className = 'sep';
            sep.innerText = ' › ';
            nav.appendChild(sep);
        }
    });
}

// --- Phase 3: UI Renderers ---

function renderGroupList(container) {
    log("vaultUI.renderGroupList", "called");

    refreshAddDeleteBtnVisibility();

    if (!vaultData.groups || vaultData.groups.length === 0) {
        container.innerHTML = `<div class="empty-state">No groups found.</div>`;
        return;
    }

    vaultData.groups.forEach(group => {
        const div = document.createElement('div');
        div.className = 'list-row';
        div.innerHTML = `
            <span>📁 ${group.name}</span>
            <span class="count">${group.items.length}</span>
        `;
        div.onclick = () => {
            sessionState.path.push(group.id);
            renderVaultExplorer();
        };
        container.appendChild(div);
    });
}

function renderItemList(container, groupId) {
    log("vaultUI.renderItemList", "called");

    refreshAddDeleteBtnVisibility();

    const group = vaultData.groups.find(g => g.id === groupId);
    if (!group) return;

    if (group.items.length === 0) {
        container.innerHTML = `<div class="empty-state">This group is empty.</div>`;
        return;
    }

    group.items.forEach(item => {
        const div = document.createElement('div');
        div.className = 'list-row';
        div.innerHTML = `<span>📄 ${item.label}</span><span class="arrow">›</span>`;
        div.onclick = () => {
            sessionState.path.push(item.id);
            renderVaultExplorer(vaultData);
        };
        container.appendChild(div);
    });
}

function renderItemDetails(container, groupId, itemId) {

    log("vaultUI.renderItemDetails", "called");

    refreshAddDeleteBtnVisibility();

    const group = vaultData.groups.find(g => g.id === groupId);
    const item = group?.items.find(i => i.id === itemId);

    if (!item) {
        container.innerHTML = `<div class="empty-state">Item not found.</div>`;
        return;
    }

    // Create the Detail Container
    const detailEl = document.createElement('div');
    detailEl.className = 'detail-view';

    // NEW: Audit Meta Bar at the top
    const metaBar = document.createElement('div');
    metaBar.className = 'item-meta-bar';

    const dateOpts = { dateStyle: 'short', timeStyle: 'short' };
    const createdStr = new Date(item.created).toLocaleString(undefined, dateOpts);
    const modifiedStr = new Date(item.modified).toLocaleString(undefined, dateOpts);

    // Compare the raw ISO strings (or timestamps)
    const isModified = item.created !== item.modified;

    metaBar.innerHTML = `
        <span class="meta-left">${createdStr}</span>
        ${isModified ? `<span class="meta-right">${modifiedStr}</span>` : ''}
    `;
    detailEl.appendChild(metaBar);

    // Determine if fields should be interactive
    const readonlyAttr = sessionState.isEditable ? "" : "readonly";
    const editClass = sessionState.isEditable ? "editable-mode" : "";

    item.fields.forEach((field, index) => {
        const fieldBox = document.createElement('div');
        fieldBox.className = `field-box ${sessionState.isEditable ? 'editable' : ''}`;
        const readonlyAttr = sessionState.isEditable ? "" : "readonly";

        // Header now contains: [Label Input] + [Action Buttons (Copy or Trash)]
        let html = `
        <div class="field-header">
            <input type="text" class="label-input" data-index="${index}"
                   value="${field.key}" ${readonlyAttr} placeholder="Label">
            <div class="field-actions">
                ${sessionState.isEditable ?
                    `<button class="icon-btn delete-field-btn" data-index="${index}">🗑️</button>` :
                    `<button class="icon-btn copy-btn" data-val="${field.val}">📋</button>`
                }
            </div>
        </div>`;

        if (field.type === 'secure') {
            html += `
            <div class="input-wrap">
                <input type="${sessionState.showSecure ? 'text' : 'password'}"
                       class="field-input" data-index="${index}"
                       value="${field.val}" ${readonlyAttr} spellcheck="false">
            </div>`;
        } else if (field.type === 'note') {
            html += `<textarea class="field-input" data-index="${index}" ${readonlyAttr} rows="4">${field.val}</textarea>`;
        } else {
            html += `
            <div class="input-wrap">
                <input type="text" class="field-input" data-index="${index}" value="${field.val}" ${readonlyAttr}>
            </div>`;
        }

        fieldBox.innerHTML = html;
        detailEl.appendChild(fieldBox);
    });

    // Pass the 'item' object directly to the template function
    if (sessionState.isEditable) {
        addNewFieldTemplate(detailEl, item);
    }

    container.appendChild(detailEl);

    // Attach Event Listeners for Copy/Toggle
    attachDetailListeners(container);
}

function addNewFieldTemplate(targetElement, itemObject) {
    const addTemplate = document.createElement('div');
    addTemplate.className = 'field-box add-template';

    addTemplate.innerHTML = `
        <div class="add-field-row">
            <input type="text" id="newField_label" placeholder="Label (e.g. Pin)" class="add-label-input">
            <select id="newField_type" class="add-type-select">
                <option value="text">Text</option>
                <option value="secure">Secure</option>
                <option value="note">Note</option>
            </select>
            <button id="newField_confirmBtn" class="add-icon-btn">➕</button>
        </div>
    `;

    addTemplate.querySelector('#newField_confirmBtn').onclick = () => {
        const labelInput = document.getElementById('newField_label');
        const typeSelect = document.getElementById('newField_type');

        const label = labelInput.value.trim();
        const type = typeSelect.value;

        if (!label) {
            alert("Label is mandatory!");
            return;
        }

        // FIX: Use the passed itemObject instead of the undefined 'currentItem'
        itemObject.fields.push({ key: label, val: "", type: type });

        // Update the modified timestamp since the data changed
        itemObject.modified = new Date().toISOString();

        // Refresh UI
        renderVaultExplorer();
    };

    targetElement.appendChild(addTemplate);
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

            if (confirm(`Delete the "${fieldName}" field?`)) {
                item.fields.splice(index, 1);

                // SAFEGUARD 2: Flag the item as changed for the sync logic
                item.modified = new Date().toISOString();

                renderVaultExplorer();
            }
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

    // Safety check: if we still don't have data, stop here.
    if (!vaultData) {
        warn("vaultUI.renderVaultExplorer", "No data available to render.");
        return;
    }

    renderBreadcrumbs();

    const explorer = document.getElementById('vault_explorer');
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
    warn("vaultUI.showVaultUI", "Read-Only mode, app will be limited to view info only!");
    manageActionableItems(readOnly);
    applyReadOnlyTheme(readOnly);
}

function manageActionableItems(readOnly) {
    log("vaultUI.manageActionableItems", "called");

    const visible = !readOnly;
    const admin = AU.isAdmin();

    vaultUI.saveMenu.setVisible(visible);
    vaultUI.toggleEditMenu.setVisible(visible);
    vaultUI.rawDataMenu.setVisible(visible && admin);
    vaultUI.recoveryRotationMenu.setVisible(visible && admin);
    vaultUI.addBtn.setVisible(visible);
    vaultUI.renameBtn.setVisible(visible);
    vaultUI.deleteBtn.setVisible(visible);
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
export async function loadVault(data, options) {

    init();

    vaultData = data;
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
