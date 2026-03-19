import { log, trace, debug, info, warn, error } from '../log.js';

import { loadUI } from './uihelper.js';

export const rootUI = loadUI(['loginView', 'vaultView', 'log']);

export const loginUI = loadUI(['title', 'signinBtn', 'signinStatus', 'welcomeSpan', 'authorizedNameSpan', 'signoutLnk',
    'authMsg', 'pwdSection', 'confirmPwdSection', 'pwdInput', 'confirmPwdInput',
    'unlockBtn', 'recoverBtn', 'recoveryLnk', 'statusMsg'], 'login_', 'loginView');

export const vaultUI = loadUI(['title', 'toggleSecureBtn', 'mainSection', 'addBtn', 'renameBtn', 'deleteBtn', 'menuBtn',
    'menuDropdown', 'saveMenu', 'toggleEditMenu', 'rawDataMenu', 'copyLogsMenu', 'toggleLogsMenu',
    'recoveryRotationMenu', 'selectMenu', 'cutMenu', 'pasteMenu', 'logoutMenu', 'breadcrumbs', 'explorer', 'statusMsg'],
    'vault_', 'vaultView');

export const vaultRawDataUI = loadUI(['mainSection', 'content', 'closeBtn'], 'vaultRawData_', 'vaultView');

export const vaultRecoveryKeyUI = loadUI(['mainSection', 'currentPwdSection', 'currentPwdInput', 'pwdInput',
    'confirmPwdInput', 'rotateBtn', 'cancelBtn', 'statusMsg'], 'vaultRecoveryKey_', 'vaultBody');

export const vaultAddNewUI = loadUI(['mainSection', 'title', 'label', 'input', 'cancelBtn', 'addBtn'], 'vaultAddNew_', 'vaultBody');

export const vaultDeleteUI = loadUI(['mainSection', 'title', 'message', 'cancelBtn', 'confirmBtn'], 'vaultDelete_', 'vaultBody');

export let logEl = rootUI.log;

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