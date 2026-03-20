import { vaultUI, confirmUI } from './loader.js';

import { swapVisibility } from './uihelper.js';

export function showConfirmUI({title = "Confirm", message = "Are you sure?", okText = "Confirm", cancelText = "Cancel", onConfirm, onCancel }) {

    confirmUI.title.setText(title);

    //confirmUI.message.setText(message);
    confirmUI.message.innerHTML = message;   // Supports embedded html tags

    confirmUI.okBtn.setText(okText);
    confirmUI.cancelBtn.setText(cancelText);

    // Clear previous listeners to avoid "Double Triggering"
    confirmUI.okBtn.onClick(null);
    confirmUI.cancelBtn.onClick(null);

    // Setup New Listeners
    confirmUI.okBtn.onClick(() => {
        hideConfirmUI();
        if (onConfirm) onConfirm();
    });

    confirmUI.cancelBtn.onClick(() => {
        hideConfirmUI();
    });

    swapVisibility(vaultUI.mainSection, confirmUI.mainSection);
}

export function showOverlayConfirmUI({ title, message, okText = "Delete", onConfirm }) {
    const section = confirmUI.mainSection;

    // 1. Setup Content
    confirmUI.title.setText(title);
    confirmUI.message.innerHTML = message;
    confirmUI.okBtn.setText(okText);
    confirmUI.okBtn.classList.remove('success-btn'); // Remove green if present
    confirmUI.okBtn.classList.add('danger-btn');

    // 2. Apply Overlay Style
    section.classList.add('confirm-floating-overlay');
    section.setVisible(true);

    // 3. Setup Listeners
    confirmUI.okBtn.onClick(() => {
        section.setVisible(false);
        section.classList.remove('confirm-floating-overlay');
        if (onConfirm) onConfirm();
    });

    confirmUI.cancelBtn.onClick(() => {
        section.setVisible(false);
        section.classList.remove('confirm-floating-overlay');
    });

    const handleEsc = (e) => {
        if (e.key === 'Escape') {
            section.setVisible(false);
            section.classList.remove('confirm-floating-overlay');
            window.removeEventListener('keydown', handleEsc);
        }
    };
    window.addEventListener('keydown', handleEsc);
}

export function showOverlayAlertUI({ title = "Success", message, okText = "OK", onConfirm }) {
    const section = confirmUI.mainSection;

    // 1. Setup Content
    confirmUI.title.setText(title);
    confirmUI.message.innerHTML = message;

    // 2. Hide the Cancel button and update the OK button
    confirmUI.cancelBtn.setVisible(false);
    confirmUI.okBtn.setText(okText);
    confirmUI.okBtn.classList.remove('danger-btn'); // Remove red if present
    confirmUI.okBtn.classList.add('success-btn');   // Add a green/primary style

    // 3. Apply the Overlay Style
    section.classList.add('confirm-floating-overlay');
    section.setVisible(true);

    // 4. Setup Listener
    confirmUI.okBtn.onClick(() => {
        section.setVisible(false);
        section.classList.remove('confirm-floating-overlay');
        confirmUI.cancelBtn.setVisible(true); // Reset for the next use
        if (onConfirm) onConfirm();
    });
}

export function hideConfirmUI() {
    swapVisibility(confirmUI.mainSection, vaultUI.mainSection);
}
