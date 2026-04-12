import { C, G, SV, AT, CR, log, trace, debug, info, warn, error} from '@/shared/exports.js';
import { vaultUI, vaultNavBarUI, vaultMenuBar, vaultMenu } from '@/ui/loader.js';

import { hideFilterUI } from '@/ui/search.js';

import { showOverlayConfirmUI, showOverlayAlertUI } from '@/ui/modal.js';
import { showSilentToast } from '@/ui/uihelper.js';

import { toggleVaultMode, resetToRoot, navigateToPath, handlePrivateVaultGenesis, handlePrivateVaultUnlock } from '@/ui/vault.js';
import { promptPrivateVaultPassword, showCreatePrivateVaultUI, lockPrivateVault, isPrivateVaultUnlocked } from "@/ui/private-vault.js";

let vaultCtx = null;

async function load(onShowCb) {
    log("explorer.load", "called");

    vaultMenu.privateVaultMenu.onClick(doPrivateVaultClick);

    if (onShowCb) onShowCb();
    else warn("explorer.load", "Missing required onShow callback to explorer")    ;
}

function unload() {
    log("explorer.unload", "called");

    vaultMenuBar.addBtn.setVisible(false);
    vaultMenuBar.renameBtn.setVisible(false);
    vaultMenuBar.deleteBtn.setVisible(false);
    return true;
}

export function renderBreadcrumbs() {
    const breadcrumbs = vaultNavBarUI.breadcrumbs;
    if (!breadcrumbs) return;

    breadcrumbs.innerHTML = "";

    const { atRoot, path, isPrivateMode } = vaultCtx();

    // Determine if the user is currently looking at the root of the active vault
    const isCurrentlyAtRoot = atRoot();

    path.forEach((id, index) => {
        const isRootNode = (id === 'root');
        const isLast = index === path.length - 1;
        const label = getNameFromId(id, index);

        const span = document.createElement('span');

        // We make the root node ALWAYS look like a link if we are at root
        // so the user knows they can click it to switch vaults.
        const canSwitch = isRootNode && isCurrentlyAtRoot;
        span.className = (isLast && !canSwitch) ? 'breadcrumb-item active' : 'breadcrumb-item link';
        span.innerText = label;

        span.onclick = async () => {
            if (isRootNode) {
                if (isCurrentlyAtRoot) {
                    // --- VAULT SWITCHER ---
                    // Triggered by clicking the icon (🏠/🛡️) while already at the top level.
                    log("explorer.breadcrumb", "Root-to-Root click: Toggling Vaults");
                    if (isPrivateMode) {
                        toggleVaultMode('shared');
                    } else {
                        await doPrivateVaultClick();
                    }
                } else {
                    // --- RESET TO ROOT ---
                    // Triggered by clicking the icon while deep in a group or item.
                    log("explorer.breadcrumb", "Resetting to current vault root");
                    resetToRoot();
                }
            } else if (!isLast) {
                // --- STANDARD BACKWARD NAVIGATION ---
                // Navigating to a specific Group in the path.
                navigateToPath(index + 1);
            }
        };

        breadcrumbs.appendChild(span);
        if (!isLast) {
            const sep = document.createElement('span');
            sep.className = 'sep';
            sep.innerText = ' › ';
            breadcrumbs.appendChild(sep);
        }
    });
}

/**
 * Resolves an ID to a human-readable name for the breadcrumb
 */
function getNameFromId(id, index) {

    const { groupId, activeData, isPrivateMode } = vaultCtx();

    if (id === 'root') return isPrivateMode ? "🛡️" : "🏠";

    if (index === 1) { // It's a Group ID
        const group = activeData.groups.find(g => g.id === id);
        return group ? group.name : "Unknown Group";
    }
    if (index === 2) { // It's an Item ID
        const group = activeData.groups.find(g => g.id === groupId);
        const item = group?.items.find(i => i.id === id);
        return item ? item.label : "Unknown Item";
    }
    return id;
}

async function doPrivateVaultClick() {
    log("explorer.doPrivateVaultClick", "called");

    const { hasPrivateVaultData, isPrivateMode, privateDataPointer } = vaultCtx();

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

export async function renderVaultExplorer() {
    log("explorer.renderVaultExplorer", "called");

    // 1. Wipe transient keys/envelope before any rendering starts
    SV.flushCachedTransients();

    renderBreadcrumbs();

    const { activeData, depth, groupId, itemId } = vaultCtx();

    // Safety check: if we still don't have data, stop here.
    if (!activeData) {
        warn("explorer.renderVaultExplorer", "No data available to render.");
        return;
    }

    if (!vaultUI.explorer) return;

    vaultUI.explorer.innerHTML = "";

    // View Routing
    if (depth === 1) {
        renderGroupList(vaultUI.explorer);
    } else if (depth === 2) {
        renderItemList(vaultUI.explorer, groupId);
    } else if (depth === 3) {
        // We'll build the detail renderer in Phase 4
        renderItemDetails(vaultUI.explorer, groupId, itemId);
    }
}

function renderGroupList(container) {
    log("explorer.renderGroupList", "called");

    const { activeData, currentFilterMap, vaultClipboard } = vaultCtx();

    container.innerHTML = ""; // Clear existing

    if (!activeData.groups || activeData.groups.length === 0) {
        container.innerHTML = `<div class="empty-state">No groups found.</div>`;
        return;
    }

    activeData.groups.forEach(group => {

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

                // Did any specific fields match?
                // We check the specific ID format: `${node.id}-field-${f.key}`
                if (item.fields) {
                    item.fields.forEach(f => {
                        if (hits.has(`${item.id}-field-${f.key}`)) {
                            matchDensity++;
                        }
                    });
                }
            });
        }

        // Check if any item in the clipboard is from THIS group
        const hasCutItems = vaultClipboard.items.some(i => i.parentId === group.id);

        // HIGHLIGHT CHECK: Is this group name a match?
        const isMatch = currentFilterMap?.highlighted.has(group.id);

        const div = document.createElement('div');
        // Add 'source-group' class if items are being cut from here
        // Add 'search-highlight' class if it's a match
        div.className = `list-row ${hasCutItems ? 'source-group-active' : ''} ${isMatch ? 'search-highlight' : ''}`;

        // Only show badge if density > 0
        const matchBadge = (currentFilterMap && matchDensity > 0)
            ? `<span class="match-count-badge">${matchDensity}</span>`
            : '';

        div.innerHTML = `
            <span class="row-label">📁 ${group.name} ${hasCutItems ? '<small>(moving items...)</small>' : ''}</span>
            <div class="row-status-area">
                ${matchBadge}
                <span class="count">${group.items.length}</span>
            </div>
        `;

        div.onclick = () => {
            hideFilterUI();
            const { onNavigate } = vaultCtx();
            onNavigate(group.id);
        };
        container.appendChild(div);
    });

    // THE EMPTY CHECK: If the loop finished but added nothing
    if (container.children.length === 0 && currentFilterMap) {
        container.innerHTML = `<div class="empty-state">No data matching "${currentSearchQuery}".</div>`;
    }
}

function renderItemList(container, groupId) {
    log("explorer.renderItemList", "called");
    const { activeData, isSelectionMode, currentFilterMap, vaultClipboard } = vaultCtx();

    container.innerHTML = "";

    const group = activeData.groups.find(g => g.id === groupId);
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

        let matchDensity = 0;
        if (currentFilterMap) {
            const hits = currentFilterMap.highlighted;

            // 1. Did the Item label itself match?
            if (hits.has(item.id)) matchDensity++;

            // 2. Did any specific fields within this item match?
            if (item.fields) {
                item.fields.forEach(f => {
                    if (hits.has(`${item.id}-field-${f.key}`)) {
                        matchDensity++;
                    }
                });
            }
        }

        const div = document.createElement('div');

        // 1. Check if item is in the clipboard (works for both Selection and Cut modes)
        const isSelected = vaultClipboard.items.some(i => i.id === item.id);

        // 💡 HIGHLIGHT CHECK: Is this item title a match?
        const isMatch = currentFilterMap?.highlighted.has(item.id);

        div.className = `list-row ${isSelected ? 'to-be-moved' : ''} ${isMatch ? 'search-highlight' : ''}`;

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
                toggleItemSelection(vaultClipboard, item.id, div, groupId);
            } else {
                // Normal navigation
                hideFilterUI();
                const { onNavigate } = vaultCtx();
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

function toggleItemSelection(vaultClipboard, id, element, groupId) {
    const index = vaultClipboard.items.findIndex(i => i.id === id);

    if (index > -1) {
        vaultClipboard.items.splice(index, 1);
        element.classList.remove('to-be-moved');
    } else {
        // WE MUST STORE THE PARENT ID HERE
        vaultClipboard.items.push({ id: id, parentId: groupId });
        element.classList.add('to-be-moved');
    }

    const { refreshMenu } = vaultCtx();
    refreshMenu();
}

function renderItemDetails(container, groupId, itemId) {
    log("explorer.renderItemDetails", "called");
    const { activeData, currentFilterMap, isEditable, showSecure } = vaultCtx();

    const group = activeData.groups.find(g => g.id === groupId);
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

    const readonlyAttr = isEditable ? "" : "readonly";

    // 2. Render Standard Fields (Text, Secure, Note)
    item.fields.forEach((field, index) => {
        const fieldMatchID = `${item.id}-field-${field.key}`;
        const isMatch = currentFilterMap?.highlighted.has(fieldMatchID);
        const fieldBox = document.createElement('div');
        fieldBox.className = `field-box ${isEditable ? 'editable' : ''}`;

        let html = `
            <div class="field-header">
                <input type="text" class="label-input ${isMatch ? 'search-label-hit' : ''}"
                   data-index="${index}" value="${field.key}" ${readonlyAttr} placeholder="Label">
                <div class="field-actions">
                    ${isEditable ?
            `<button class="icon-btn delete-field-btn" data-index="${index}">🗑️</button>` :
            `<button class="icon-btn copy-btn" data-val="${field.val}">📋</button>`
        }
                </div>
            </div>`;

        if (field.type === 'secure') {
            html += `<div class="input-wrap"><input type="${showSecure ? 'text' : 'password'}" class="field-input" data-index="${index}" value="${field.val}" ${readonlyAttr} spellcheck="false"></div>`;
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

            // 💡 HIGHLIGHT LOGIC: Construct the ID used in search.js
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
        addNewFieldTemplate(detailEl, item);
    }

    container.appendChild(detailEl);
    attachDetailListeners(container, item); // Pass item to handle file actions
}

async function handleDownloadAttachment(attachment) {
    try {
        log("explorer.handleDownloadAttachment", `Opening: ${attachment.key}`);

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

        info("explorer.handleDownloadAttachment", "File delivered.");

    } catch (err) {
        error("explorer.handleDownloadAttachment", "Failed to open file", err);
        showOverlayAlertUI({
            title: "Attachment Error",
            message: "Failed to download or decrypt file."
        });
    }
}

async function handleDeleteAttachment(item, index) {
    const attachment = item.attachments[index];
    if (!attachment) return;

    showOverlayConfirmUI({
        title: `Remove ${attachment.key}?`,
        message: `This will remove the attachment from the vault. Changes are pending until you click 'Save'.`,
        okText: "Remove",
        onConfirm: async () => {

            const { onAttachmentDelete, refresh } = vaultCtx();

            // 1. Add the Drive File ID to our "Hit List"
            if (attachment.val) onAttachmentDeletion(attachment.val);

            // 2. Remove from the local vaultData array immediately
            item.attachments.splice(index, 1);
            item.modified = new Date().toISOString();

            // 3. Refresh the UI - the file disappears instantly!
            refresh();

            showSilentToast("Removed. Remember to Save changes.");
        }
    });
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
    const { refresh } = vaultCtx();

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
        await handleUploadAttachment(file, label, itemObject);

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

async function handleUploadAttachment(file, label, itemObject) {
    // 1. Create a temporary ID to find this specific UI row later
    const tempId = "up_" + Date.now();
    const fileName = label || file.name;

    try {
        log("explorer.handleUploadAttachment", `Starting upload for: ${fileName}`);

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
        log("explorer.handleUploadAttachment", "mimeType:", mimeType);

        const { isPrivateMode, onAttachmentUpload, refresh } = vaultCtx();

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
        info("explorer.handleUploadAttachment", "Upload complete.");

    } catch (err) {
        // Remove the failed spinner if it exists
        document.getElementById(tempId)?.remove();
        error("explorer.handleUploadAttachment", "Upload Error:", err);
        showOverlayAlertUI({
            title: "Upload Error",
            message: "Failed to upload attachment. Check logs for details."
        });
    }
}

function attachDetailListeners(container) {
    const item = getCurrentItem();
    if (!item) return;

    const { toggleShowSecure, refresh } = vaultCtx();

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

/**
 * Finds the currently active item based on the sessionState.path
 */
export function getCurrentItem() {
    const { activeData, groupId, itemId } = vaultCtx();
    if (!groupId || !itemId) return null;

    const group = activeData.groups.find(g => g.id === groupId);
    return group?.items.find(i => i.id === itemId) || null;
}

export async function loadExplorer(vaultContext, onShowCb) {

    vaultCtx = vaultContext;
    const screenKey = window.ScreenManager.EXPLORER_SCREENKEY;

    window.ScreenManager.register(screenKey, vaultUI.mainSection, {
        onShow: async () => load(onShowCb),
        onHide: unload
    });

    window.ScreenManager.switchView(screenKey);
}