import { U, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { restoreFromRawString } from '@/core/backup.js';

import { rootUI, backupRestoreUI } from '@/ui/loader.js';
import { swapVisibility, showSilentToast, copyToClipboard } from '@/ui/uihelper.js';

/**
 * Reset and show the recovery modal
 */
export function openRecoveryModal() {

    log("backupRestoreUI.openRecoveryModal", "called");

    const step1 = backupRestoreUI.inputSection;
    const step2 = backupRestoreUI.outputSection;
    const title = backupRestoreUI.title;

    // Reset visibility
    rootUI.restoreBackupView.style.display = 'flex';
    //rootUI.restoreBackupView.setVisible();
    //rootUI.restoreBackupView.setFlex()

    swapVisibility(backupRestoreUI.outputSection, backupRestoreUI.inputSection);

    title.setText("Restore Vault");

    // Clear fields
    backupRestoreUI.encInput.setText('');
    backupRestoreUI.pwdInput.setText('');
    backupRestoreUI.outputTxa.setText('');
}

async function doDecryptClick() {
    log("backupRestoreUI.decrypt", "called");

    // 1. Capture and Deep Clean the string
    const rawString = backupRestoreUI.encInput.value.trim();
    const password = backupRestoreUI.pwdInput.value;

    if (!rawString || !password) {
        showSilentToast("Please provide both fields.");
        return;
    }

    try {
        const decryptedData = await restoreFromRawString(rawString, password);

        // Show the results in a standard textarea (easier for mobile select-all)
        backupRestoreUI.outputTxa.setText(U.format(decryptedData));

        swapVisibility(backupRestoreUI.inputSection, backupRestoreUI.outputSection);
        backupRestoreUI.title.setText("Data Extracted");
    } catch (e) {
        error("backupRestoreUI.decrypt", "Recovery failed:", e);
        showSilentToast("Failed. Check string or password.");
    }
}

async function doCopyToClipboardClick() {
    backupRestoreUI.outputTxa.select();
    backupRestoreUI.outputTxa.setSelectionRange(0, 99999); // For mobile
    copyToClipboard(backupRestoreUI.outputTxa.getText());
}

// 1. Decrypt Action
backupRestoreUI.decryptBtn.onClick(doDecryptClick);

// 2. Copy Action
backupRestoreUI.copyBtn.onClick(doCopyToClipboardClick);

// 3. Close Action
backupRestoreUI.closeBtn.onClick(() => {
    rootUI.restoreBackupView.setVisible(false);
});