import { log, trace, debug, info, warn, error } from '../exports.js';

import { vaultUI, vaultAddNewUI } from './loader.js';

import { showConfirmUI, hideConfirmUI } from './confirm.js';

// Function to handle the Add Button click in the header
export function showAddNewUI(depth, toParentId, vaultData, {onAdd = () => {},  onCancel = () => {}} = {}) {
    log("vaultAddRenDel.showAddNewUI", "called - depth:", depth);

    vaultUI.addBtn.setVisible(false);
    vaultUI.renameBtn.setVisible(false);
    vaultUI.deleteBtn.setVisible(false);

    const title = vaultAddNewUI.title;
    const input = vaultAddNewUI.input;

    // Clear previous input
    input.clear();
    vaultAddNewUI.mainSection.setVisible(true);
    input.focus();

    vaultAddNewUI.addBtn.setText("Add");
    let hdr = "Add Group";
    if (depth === 1) {
        vaultAddNewUI.title.classList.remove('data-title'); // Standard grey
    } else if (depth === 2) {
        const group = vaultData.groups.find(g => g.id === toParentId);
        hdr = group ? group.name : "Add Item";

        if (group)
            vaultAddNewUI.addBtn.setText("Add Item");

        vaultAddNewUI.title.classList.add('data-title'); // Turns Blue
    }
    title.setText(hdr);

    // Handle Add
    vaultAddNewUI.addBtn.onClick(() => {
        const val = input.value.trim();
        if (!val) return showAddNewStatusMessage("Name cannot be empty");

        onAdd(val);
        vaultAddNewUI.mainSection.setVisible(false);
    });

    // Handle Cancel
    vaultAddNewUI.cancelBtn.onClick(() => {
        vaultAddNewUI.mainSection.setVisible(false);
        onCancel();
    });

    function showAddNewStatusMessage(msg, type = "error") {
        if (!vaultAddNewUI.statusMsg) return;

        vaultAddNewUI.statusMsg.textContent = msg;
        vaultAddNewUI.statusMsg.className = `status-message ${type}`;
    }
}

export function showRenameUI(depth, vaultData, path, {onRename = () => {}, onCancel = () => {}} = {}) {
    log("vaultAddRenDel.showRenameUI", "called - depth:", depth);

    vaultUI.addBtn.setVisible(false);
    vaultUI.renameBtn.setVisible(false);
    vaultUI.deleteBtn.setVisible(false);

    const title = vaultAddNewUI.title;
    const input = vaultAddNewUI.input;
    const saveBtn = vaultAddNewUI.addBtn;

    // 1. Identify what we are renaming
    let currentName = "";
    let headerText = "Rename";

    if (depth === 2) {
        const groupId = path[1];
        const group = vaultData.groups.find(g => g.id === groupId);
        currentName = group ? group.name : "";
        headerText = "Rename Group";
    } else if (depth === 3) {
        const groupId = path[1];
        const itemId = path[2];
        const group = vaultData.groups.find(g => g.id === groupId);
        const item = group?.items.find(i => i.id === itemId);
        currentName = item ? item.label : "";
        headerText = "Rename Item";
    }

    // 2. Setup UI
    input.value = currentName;
    title.setText(headerText);
    saveBtn.setText("Save");
    vaultAddNewUI.mainSection.setVisible(true);
    input.focus();

    // 3. Handle Save
    saveBtn.onClick(() => {
        const newVal = input.value.trim();
        if (!newVal) return; // Add status msg if needed

        onRename(newVal);
        vaultAddNewUI.mainSection.setVisible(false);
    });

    // 4. Handle Cancel
    vaultAddNewUI.cancelBtn.onClick(() => {
        vaultAddNewUI.mainSection.setVisible(false);
        onCancel();
    });
}

export function showDeleteUI(depth, groupId, itemId, vaultData, {onConfirm = () => {}, onCancel = () => {}} = {}) {
    log("vaultAddRenDel.showDeleteUI", "transitioned to showConfirmUI - depth:", depth);

    vaultUI.addBtn.setVisible(false);
    vaultUI.renameBtn.setVisible(false);
    vaultUI.deleteBtn.setVisible(false);

    const group = vaultData.groups.find(g => g.id === groupId);
    const groupName = group ? group.name : "this group";

    let title, msg, okBtnText;

    if (depth === 2) {
        // --- DELETE GROUP CASE ---
        title = groupName;
        msg = `This will delete the selected group and all its child items. Continue?`;
        okBtnText = "Delete Group";
    } else {
        // --- DELETE ITEM CASE ---
        const item = group?.items.find(i => i.id === itemId);
        const itemName = item ? item.label : "this item";
        title = itemName;
        msg = `Delete selected item from group <b>${groupName}</b> permanently?`;
        okBtnText = "Delete Item";
    }

    // Call the generic UI
    showConfirmUI({
        title: title,
        message: msg,
        okText: okBtnText,
        onConfirm: () => {
            onConfirm();
            // showConfirmUI handles the visibility swap back to main
        }
    });
}

export function hideAddRenDel() {
    vaultAddNewUI.mainSection.setVisible(false);
    hideConfirmUI();
}

