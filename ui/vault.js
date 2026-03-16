import { C, G, AU, E, U, log, trace, debug, info, warn, error } from '../exports.js';

import { logout } from '../app.js';
import { loadUI } from './uihelper.js';

import { rootUI, vaultUI, copyLogsToClipboard } from './loader.js';
import { showRecoveryRotationUI } from './recovery-rotation.js';

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

async function loadVault() {
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
    vaultUI.copyLogsMenu.onClick(copyLogsToClipboard);
    vaultUI.toggleLogsMenu.onClick(toggleLogs);

    vaultUI.toggleEditMenu.onClick(doToggleEditClick);
}

async function doToggleEditClick() {
    if (sessionState.isEditable) {
        // We are EXITING edit mode.
        // Update the timestamp now.
        const item = getCurrentItem();
        if (item) item.modified = new Date().toISOString();
        syncToTextarea();
    }

    sessionState.isEditable = !sessionState.isEditable;
    vaultUI.toggleEditMenu.setText(sessionState.isEditable ? "Exit Edit Mode" : "Edit Item");
    renderVault();
}

async function doSaveClick() {
    log("vaultUI.doSaveClick", "called");
    showStatusMessage("Saving...", null);

    const text = vaultUI.data.value;
    if (!text) {
        warn("vaultUIdoSaveClick] Nothing to encrypt");
        return;
    }

    try {
        await E.encryptAndPersistPlaintext(text, { onUpdate: updateLockStatusUI });
        showStatusMessage(`Saved changes at ${U.getCurrentTime()}`, "success");
        //vaultUI.data.value = "";
    } catch (err) {
        error("vaultUI.doSaveClick", "Encryption failed:" + err);
        showStatusMessage("Error while saving" + err, "error");
    }
    //alert("Saved!");
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
                renderVault(); // We will build this next
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
            renderVault();
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
            renderVault(vaultData);
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

    // 1. Toggle Password Visibility (Global)
    container.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.onclick = () => {
            sessionState.showSecure = !sessionState.showSecure;
            renderVault();
        };
    });

    // 2. Copy to Clipboard
    container.querySelectorAll('.copy-btn').forEach(btn => {
        btn.onclick = () => {
            navigator.clipboard.writeText(btn.dataset.val);
            btn.innerText = "✅";
            setTimeout(() => btn.innerText = "📋", 1500);
        };
    });

    // 3. Update Field Values (Text/Password/Notes)
    container.querySelectorAll('.field-input').forEach(input => {
        input.oninput = (e) => {
            const index = e.target.dataset.index;
            item.fields[index].val = e.target.value;
            syncToTextarea();
        };
    });

    // 4. Update Field Labels (Keys)
    container.querySelectorAll('.label-input').forEach(input => {
        input.oninput = (e) => {
            const index = e.target.dataset.index;
            item.fields[index].key = e.target.value;
            syncToTextarea();
        };
    });

    // 5. Delete Field Logic
    container.querySelectorAll('.delete-field-btn').forEach(btn => {
        btn.onclick = () => {
            const index = parseInt(btn.dataset.index);
            if (confirm(`Delete the "${item.fields[index].key}" field?`)) {
                item.fields.splice(index, 1);
                syncToTextarea();
                renderVault();
            }
        };
    });
}

// --- Main Render Entry Point ---

export function renderVault(data) {
    // 1. If data is passed as a string, parse it.
    // Otherwise, try to fallback to the textarea.
    if (data && typeof data === 'string') {
        vaultData = JSON.parse(data);
        vaultUI.data.setText(data);
    } else if (!vaultData) {
        const raw = vaultUI.data.value;
        if (raw) vaultData = JSON.parse(raw);
    }

    // Safety check: if we still don't have data, stop here.
    if (!vaultData) {
        console.warn("renderVault: No data available to render.");
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
 * Finds the currently active item based on the sessionState.path
 */
function getCurrentItem() {
    const groupId = sessionState.path[1];
    const itemId = sessionState.path[2];
    if (!groupId || !itemId) return null;

    const group = vaultData.groups.find(g => g.id === groupId);
    return group?.items.find(i => i.id === itemId) || null;
}

/**
 * Syncs the in-memory vaultData object to the hidden textarea
 * so the global Save/Encrypt process can see the changes.
 */
function syncToTextarea() {
    const textarea = document.getElementById('vault_data');
    if (textarea && vaultData) {
        // null, 2 adds pretty-printing which makes the JSON readable
        textarea.value = JSON.stringify(vaultData, null, 2);
    }
}

/**
 * EXPORTED FUNCTIONS
 */
export function showVaultUI({ readOnly = false, onIdle = () => { logout() } } = {}) {

    log("vaultUI.showVaultUI", "called");

    loadVault();

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
        vaultUI.data.readOnly = true;
        rootUI.vaultTitle.setText("Unlocked (Read-only)");
    } else {
        vaultUI.saveMenu.setEnabled(true);
        vaultUI.data.readOnly = false;
        rootUI.vaultTitle.setText("Unlocked");
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
