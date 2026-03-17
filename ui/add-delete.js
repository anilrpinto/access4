import { log, trace, debug, info, warn, error } from '../exports.js';

import { vaultAddNewUI, vaultDeleteUI } from './loader.js';

// Function to handle the Add Button click in the header
export function showAddNewUI(depth, toParentId, vaultData, {onAdd = () => {},  onCancel = () => {}} = {}) {

    log("vaultAddDelete.showAddNewUI", "called - depth:", depth);

    const title = vaultAddNewUI.title;
    const input = vaultAddNewUI.input;

    // Clear previous input
    input.clear();
    vaultAddNewUI.mainSection.setVisible(true);
    input.focus();

    let hdr = "Add Group";
    if (depth === 2) {
        const group = vaultData.groups.find(g => g.id === toParentId);
        hdr = group ? group.name : "Add Item";

        if (group)
            vaultAddNewUI.addBtn.setText("Add Item");
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

export function showDeleteUI(depth, groupId, itemId, vaultData, {onConfirm = () => {}, onCancel = () => {}} = {}) {
    log("vaultAddDelete.showDeleteUI", "called - depth:", depth);

    const group = vaultData.groups.find(g => g.id === groupId);
    const groupName = group ? group.name : "this group";

    let msg;
    if (depth === 2) {
        msg = `This will delete <b>${groupName}</b> and all its child items. Continue?`;
        vaultDeleteUI.title.setText("Group Deletion");
        vaultDeleteUI.confirmBtn.setText("Delete Group");
    } else {
        const item = group?.items.find(i => i.id === itemId);
        const itemName = item ? item.label : "this item";
        msg = `Delete <b>${itemName}</b> from group <b>${groupName}</b> permanently?`;
        vaultDeleteUI.title.setText("Item deletion");
        vaultDeleteUI.confirmBtn.setText("Delete Item");
    }

    vaultDeleteUI.message.innerHTML = msg;
    vaultDeleteUI.mainSection.setVisible(true);

    vaultDeleteUI.confirmBtn.onClick(() => {
        vaultDeleteUI.mainSection.setVisible(false);
        onConfirm();
    });

    vaultDeleteUI.cancelBtn.onClick(() => {
        vaultDeleteUI.mainSection.setVisible(false);
        onCancel();
    });
}



