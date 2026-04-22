import { log, trace, debug, info, warn, error } from '@/shared/log.js';

import { loadUI } from '@/ui/uihelper.js';

export const rootUI = loadUI(['loginView', 'vaultView', 'restoreBackupView', 'log']);

export const loginUI = loadUI(['title', 'signinBtn', 'signinStatus', 'welcomeSpan', 'authorizedNameSpan', 'signoutLnk',
    'authMsg', 'pwdSection', 'confirmPwdSection', 'pwdInput', 'confirmPwdInput',
    'unlockBtn', 'recoverBtn', 'recoveryLnk', 'statusMsg', 'restoreBackupLnk'], 'login_', 'loginView');

export const vaultUI = loadUI(['header', 'headerLeftSide', 'title', 'toggleSecureBtn', 'mainSection', 'headerRightSide', 'explorer', 'statusMsg'], 'vault_', 'vaultView');

export const vaultRawDataUI = loadUI(['mainSection', 'textContent', 'treeContent', 'toggleViewBtn', 'closeBtn'], 'vaultRawData_', 'vaultView');

export const vaultRecoveryKeyUI = loadUI(['mainSection', 'currentPwdSection', 'currentPwdInput', 'pwdInput',
    'confirmPwdInput', 'rotateBtn', 'cancelBtn', 'statusMsg'], 'vaultRecoveryKey_', 'vaultBody');

export const vaultCreatePrivateUI = loadUI(['mainSection', 'pwdInput', 'confirmPwdInput', 'createBtn', 'cancelBtn', 'statusMsg'],
    'vaultCreatePrivate_', 'vaultBody');

export const vaultAddNewUI = loadUI(['mainSection', 'title', 'label', 'input', 'archiveSection', 'archiveCheck', 'cancelBtn', 'addBtn'], 'vaultAddNew_', 'vaultBody');

export const confirmUI = loadUI(['mainSection', 'title', 'message', 'cancelBtn', 'okBtn'], 'vaultConfirm_', 'vaultBody');

export const backupRestoreUI = loadUI(['title' , 'closeBtn', 'inputSection', 'encInput', 'pwdInput', 'decryptBtn', 'outputSection', 'outputTxa', 'copyBtn'],
    'restoreBackup_', 'restoreBackup_mainSection');

export const vaultNavBarUI = loadUI(['mainSection', 'breadcrumbs', 'filterSection', 'filterInput', 'filterToggle', 'sortToggle'], 'vaultNavBar_', 'vault_mainSection');

export const vaultUsersUI = loadUI(['mainSection', 'title', 'closeBtn', 'userSelect', 'formFields', 'roleSelect', 'readonlyCheck',
        'attachmentsCheck', 'forcePwdCheck', 'cancelBtn', 'saveBtn', 'removeBtn'], 'vaultUsers_', 'vaultBody');
//vaultUsersUI.formFields.setFlex();

export const vaultMenuBar = loadUI(['addBtn', 'renameBtn', 'deleteBtn'], 'vaultMenuBar_', 'vault_headerRightSide');

export const vaultMenu = loadUI(['menuBtn', 'menuDropdown', 'saveMenu', 'toggleEditMenu', 'archivedMenu', 'rawDataMenu',
    'discardChangesMenu', 'copyLogsMenu', 'toggleLogsMenu', 'usersMenu', 'syncAccessMenu', 'runBackupMenu',
    'recoveryRotationMenu', 'privateVaultMenu', 'selectMenu', 'cutMenu', 'pasteMenu', 'logoutMenu'],
    'vaultMenu_', 'vault_headerRightSide');

export const systemModalUI = loadUI(['mainSection', 'title', 'message', 'cancelBtn', 'okBtn'], 'systemModal_');

export const advSearchUI = loadUI(['mainSection', 'close', 'scope', 'dynamicLabels', 'attach', 'case',
        'dateType', 'dateVal', 'dateUnit', 'logic', 'reset', 'run'], 'advSearch_', 'vaultBody');

export async function copyLogsToClipboard() {
    if (!logEl) return;

    try {
        await navigator.clipboard.writeText(logEl.innerText);
        alert("Logs copied to clipboard");
    } catch (err) {
        error("UI.copyLogsToClipboard", "Failed to copy logs:", err);
    }
}

export function enterVaultMode() {
    rootUI.loginView.setVisible(false);
    rootUI.vaultView.setVisible(true);
}

rootUI.vaultView.setFlex();
vaultUI.mainSection.setFlex();

rootUI.log.onClick(copyLogsToClipboard);