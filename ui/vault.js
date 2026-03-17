import { C, G, AU, E, U, log, trace, debug, info, warn, error } from '../exports.js';

import { logout } from '../app.js';
import { loadUI, swapVisibility } from './uihelper.js';

import { rootUI, vaultUI, vaultRawDataUI, copyLogsToClipboard } from './loader.js';
import { showRecoveryRotationUI } from './recovery-rotation.js';
import { showAddNewUI, showDeleteUI } from './add-delete.js';

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

async function showVaultUI({ readOnly = false, onIdle = () => { logout() } } = {}) {

    log("vaultUI.showVaultUI", "called");

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
        vaultRawDataUI.content.readOnly = true;
        //vaultUI.title.setText("Unlocked (Read-only)");
    } else {
        vaultUI.saveMenu.setEnabled(true);
        vaultRawDataUI.content.readOnly = false;
        //vaultUI.title.setText("Unlocked");
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

function doShowRawDataClick() {
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
                vaultUI.mainSection.setVisible(true);
                if (depth === 1) executeAddGroup(name);
                else if (depth === 2) executeAddItem(name);
            },
            onCancel: () => vaultUI.mainSection.setVisible(true)
        });
    } else {
        // Adding a field inside an item can still be "instant"
        // because the user is already in an editable view
        createNewField();
    }
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
        onCancel: () => vaultUI.mainSection.setVisible(true)
    });
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
    if (id === 'root') return "Vault";
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
            sep.innerText = ' > ';
            nav.appendChild(sep);
        }
    });
}

// --- Phase 3: UI Renderers ---

function renderGroupList(container) {
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
        const fieldId = `field_input_${index}`;

        // Common Header: Label is now editable too!
        let html = `<div class="field-header">
            <input type="text" class="label-input" data-index="${index}"
                   value="${field.key}" ${readonlyAttr} placeholder="Label">
        </div>`;

        if (field.type === 'secure') {
            html += `
            <div class="input-wrap">
                <input type="${sessionState.showSecure ? 'text' : 'password'}"
                       class="field-input" data-index="${index}"
                       value="${field.val}" ${readonlyAttr} spellcheck="false">
                <button class="icon-btn toggle-btn">${sessionState.showSecure ? '🔒' : '👁️'}</button>
                ${sessionState.isEditable ?
                    `<button class="icon-btn delete-field-btn" data-index="${index}">🗑️</button>` :
                    `<button class="icon-btn copy-btn" data-val="${field.val}">📋</button>`}
            </div>`;
        } else if (field.type === 'note') {
            html += `
            <textarea class="field-input" data-index="${index}"
                      ${readonlyAttr} rows="4">${field.val}</textarea>`;
        } else {
            html += `
            <div class="input-wrap">
                <input type="text" class="field-input" data-index="${index}"
                       value="${field.val}" ${readonlyAttr}>
                ${sessionState.isEditable ?
                    `<button class="icon-btn delete-field-btn" data-index="${index}">🗑️</button>` :
                    `<button class="icon-btn copy-btn" data-val="${field.val}">📋</button>`}
            </div>`;
        }

        fieldBox.innerHTML = html;
        detailEl.appendChild(fieldBox);
    });

    container.appendChild(detailEl);

    // Attach Event Listeners for Copy/Toggle
    attachDetailListeners(container);
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
        btn.onclick = () => {
            const index = parseInt(btn.dataset.index);
            const fieldName = item.fields[index].key || "unnamed";

            if (confirm(`Delete the "${fieldName}" field?`)) {
                item.fields.splice(index, 1);
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


/**
 * EXPORTED FUNCTIONS
 */
export async function loadVault(data, options) {
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
    vaultUI.toggleEditMenu.onClick(doToggleEditClick);
    vaultUI.rawDataMenu.onClick(doShowRawDataClick);

    vaultUI.addBtn.onClick(doAddClick);
    vaultUI.deleteBtn.onClick(doDeleteClick);

    // temporary menu
    vaultUI.copyLogsMenu.onClick(copyLogsToClipboard);
    vaultUI.toggleLogsMenu.onClick(toggleLogs);

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
