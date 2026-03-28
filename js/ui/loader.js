import { log, trace, debug, info, warn, error } from '@/shared/log.js';

import { loadUI } from '@/ui/uihelper.js';

export const rootUI = loadUI(['loginView', 'vaultView', 'restoreBackupView', 'log']);

export const loginUI = loadUI(['title', 'signinBtn', 'signinStatus', 'welcomeSpan', 'authorizedNameSpan', 'signoutLnk',
    'authMsg', 'pwdSection', 'confirmPwdSection', 'pwdInput', 'confirmPwdInput',
    'unlockBtn', 'recoverBtn', 'recoveryLnk', 'statusMsg', 'restoreBackupLnk'], 'login_', 'loginView');

export const vaultUI = loadUI(['title', 'toggleSecureBtn', 'mainSection', 'headerRightSide', 'addBtn', 'renameBtn',
    'deleteBtn', 'menuBtn', 'menuDropdown', 'saveMenu', 'toggleEditMenu', 'rawDataMenu',
    'discardChangesMenu', 'copyLogsMenu', 'toggleLogsMenu', 'syncAccessMenu', 'runBackupMenu', 'recoveryRotationMenu',
    'selectMenu', 'cutMenu', 'pasteMenu', 'logoutMenu', 'explorer', 'statusMsg'], 'vault_', 'vaultView');

export const vaultRawDataUI = loadUI(['mainSection', 'content', 'closeBtn'], 'vaultRawData_', 'vaultView');

export const vaultRecoveryKeyUI = loadUI(['mainSection', 'currentPwdSection', 'currentPwdInput', 'pwdInput',
    'confirmPwdInput', 'rotateBtn', 'cancelBtn', 'statusMsg'], 'vaultRecoveryKey_', 'vaultBody');

export const vaultAddNewUI = loadUI(['mainSection', 'title', 'label', 'input', 'cancelBtn', 'addBtn'], 'vaultAddNew_', 'vaultBody');

export const confirmUI = loadUI(['mainSection', 'title', 'message', 'cancelBtn', 'okBtn'], 'vaultConfirm_', 'vaultBody');

export const backupRestoreUI = loadUI(['title' , 'closeBtn', 'inputSection', 'encInput', 'pwdInput', 'decryptBtn', 'outputSection', 'outputTxa', 'copyBtn'],
    'restoreBackup_', 'restoreBackup_mainSection');

export const vaultNavBarUI = loadUI(['mainSection', 'breadcrumbs', 'filterSection', 'filterInput', 'filterToggle'], 'vaultNavBar_', 'vault_mainSection');

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