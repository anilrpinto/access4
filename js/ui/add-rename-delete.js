import { G, log, trace, debug, info, warn, error } from '@/shared/exports.js';
import { vaultAddNewUI } from '@/ui/loader.js';
import { showConfirmUI } from '@/ui/confirm.js';

export function showAddNewUI(toParentId, {onAdd = () => {},  onCancel = () => {}} = {}) {
    const { depth, findActiveGroup, isArchiveModeActive } = G.vaultContext();
    log("vaultAddRenDel.showAddNewUI", "called - depth:", depth);

    // 1. Ensure registration (Happens only once per session/reload)
    _ensureEditorRegistered();
    window.ScreenManager.switchView(window.ScreenManager.EDITOR_SCREENKEY);

    const { title, input, archiveSection, archiveCheck, addBtn, cancelBtn } = vaultAddNewUI;

    // Clear previous input
    input.clear();
    archiveCheck.checked = isArchiveModeActive;
    input.focus();

    addBtn.setText("Add");
    let hdr = "Add Group";
    if (depth === 1) {
        title.classList.remove('data-title');
        archiveSection.setVisible(true);
        archiveSection.setFlex();
    } else if (depth === 2) {

        const group = findActiveGroup(toParentId);
        hdr = group ? group.name : "Add Item";

        if (group)
            addBtn.setText("Add Item");

        title.classList.add('data-title');
        archiveSection.setVisible(false);
        archiveSection.setFlex();
    }
    title.setText(hdr);

    // Handle Add
    addBtn.onClick(() => {
        const val = input.value.trim();
        if (!val) return showAddNewStatusMessage("Name cannot be empty");

        window.ScreenManager.goHome();
        onAdd(val, archiveCheck.checked);
    });

    // Handle Cancel
    cancelBtn.onClick(() => {
        window.ScreenManager.goHome();
        onCancel();
    });

    function showAddNewStatusMessage(msg, type = "error") {
        if (!vaultAddNewUI.statusMsg) return;

        vaultAddNewUI.statusMsg.textContent = msg;
        vaultAddNewUI.statusMsg.className = `status-message ${type}`;
    }
}

export function showRenameUI({onRename = () => {}, onCancel = () => {}} = {}) {
    const { depth, isArchiveModeActive, findActiveGroup, findActiveItem } = G.vaultContext();
    log("vaultAddRenDel.showRenameUI", "called - depth:", depth);

    // 1. Ensure registration (Happens only once per session/reload)
    _ensureEditorRegistered();
    window.ScreenManager.switchView(window.ScreenManager.EDITOR_SCREENKEY);

    const { title, input, archiveSection, archiveCheck, addBtn: saveBtn, cancelBtn } = vaultAddNewUI;

    // 1. Identify what we are renaming
    let currentName = "";
    let headerText = "Rename";

    const group = findActiveGroup();

    if (depth === 2) {
        currentName = group ? group.name : "";
        headerText = "Rename Group";
        archiveSection.setVisible(true);
        archiveSection.setFlex();
    } else if (depth === 3) {
        const item = findActiveItem(group);
        currentName = item ? item.label : "";
        headerText = "Rename Item";
        archiveSection.setVisible(false);
        archiveSection.setFlex();
    }

    // 2. Setup UI
    input.value = currentName;
    archiveCheck.checked = isArchiveModeActive;
    title.setText(headerText);
    saveBtn.setText("Save");
    input.focus();

    // 3. Handle Save
    saveBtn.onClick(() => {
        const newVal = input.value.trim();
        if (!newVal) return; // Add status msg if needed

        window.ScreenManager.goHome();
        onRename(newVal, isArchiveModeActive, archiveCheck.checked);
    });

    // 4. Handle Cancel
    cancelBtn.onClick(() => {
        window.ScreenManager.goHome();
        onCancel();
    });
}

export function showDeleteUI({onConfirm = () => {}, onCancel = () => {}} = {}) {

    const { depth, findActiveGroup, findActiveItem } = G.vaultContext();
    log("vaultAddRenDel.showDeleteUI", "transitioned to showConfirmUI - depth:", depth);

    const group = findActiveGroup();
    const groupName = group ? group.name : "Group";

    let title, msg, okBtnText;

    if (depth === 2) {
        // --- DELETE GROUP CASE ---
        title = groupName;
        msg = `Delete group and all items?`;
        okBtnText = "Delete Group";
    } else {
        // --- DELETE ITEM CASE ---
        const item = findActiveItem(group);
        title = item ? item.label : "Item";
        msg = `Delete item from group <b>${groupName}</b>?`;
        okBtnText = "Delete Item";
    }

    // Call the generic UI
    showConfirmUI({
        title: title,
        message: msg,
        okText: okBtnText,
        onConfirm: onConfirm,
        onCancel: onCancel
    });
}

/** INTERNAL FUNCTIONS **/
function _ensureEditorRegistered() {
    // ScreenManager.register already handles the "if exists" check,
    // so we can just call it safely.
    window.ScreenManager.register(window.ScreenManager.EDITOR_SCREENKEY, vaultAddNewUI.mainSection, {
        onShow: () => {
            log("vaultAddRenDel._ensureEditorRegistered", "Focusing input.");
            vaultAddNewUI.input.focus();
        },
        onHide: () => {
            vaultAddNewUI.input.clear();
            return true;
        }
    });
}
