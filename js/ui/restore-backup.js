import { U, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { restoreFromRawString } from '@/core/backup.js';

import { rootUI, backupRestoreUI } from '@/ui/loader.js';
import { swapVisibility, showSilentToast } from '@/ui/uihelper.js';

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

async function decrypt() {
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

async function copyToClipboard() {
    backupRestoreUI.outputTxa.select();
    backupRestoreUI.outputTxa.setSelectionRange(0, 99999); // For mobile

    try {
        navigator.clipboard.writeText(backupRestoreUI.outputTxa.value);
        showSilentToast("JSON copied to clipboard!");
    } catch (err) {
        // Fallback for older browsers
        document.execCommand('copy');
        showSilentToast("Copied to clipboard");
    }
}

// 1. Decrypt Action
backupRestoreUI.decryptBtn.onClick(decrypt);

// 2. Copy Action
backupRestoreUI.copyBtn.onClick(copyToClipboard);

// 3. Close Action
backupRestoreUI.closeBtn.onClick(() => {
    rootUI.restoreBackupView.setVisible(false);
});