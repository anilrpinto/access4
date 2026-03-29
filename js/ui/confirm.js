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
        if (onCancel) onCancel();
    });

    swapVisibility(vaultUI.mainSection, confirmUI.mainSection);
}

export function showOverlayChoiceUI({ title, message, okText = "Choice 1", cancelText = "Choice 2", onConfirm, onCancel }) {
    showOverlayConfirmUI({ title,message, okText, cancelText, onConfirm, onCancel });
}

export function showOverlayConfirmUI({ title, message, okText = "Delete", cancelText = "Cancel", onConfirm, onCancel }) {
    const section = confirmUI.mainSection;

    // 1. Setup Content
    confirmUI.title.setText(title);
    confirmUI.message.innerHTML = message;

    confirmUI.okBtn.setText(okText);
    confirmUI.cancelBtn.setText(cancelText);

    confirmUI.okBtn.classList.remove('success-btn'); // Remove green if present
    confirmUI.okBtn.classList.add('danger-btn');

    // 2. Apply Overlay Style
    section.classList.add('confirm-floating-overlay');
    section.setVisible(true);

    confirmUI.okBtn.onClick(null);
    confirmUI.cancelBtn.onClick(null);

    // 3. Setup Listeners
    confirmUI.okBtn.onClick(() => {
        section.setVisible(false);
        section.classList.remove('confirm-floating-overlay');
        if (onConfirm) onConfirm();
    });

    confirmUI.cancelBtn.onClick(() => {
        section.setVisible(false);
        section.classList.remove('confirm-floating-overlay');

        if (onCancel) onCancel();
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

/**
 * A reusable Password Prompt using the existing Confirm UI Overlay
 */
export function showOverlayPasswordUI({ title = "Security Check", message = "Please enter your password:", okText = "Proceed" }) {
    const section = confirmUI.mainSection;

    return new Promise((resolve) => {
        // 1. Setup Content
        confirmUI.title.setText(title);

        // Inject the message and a password input field
        confirmUI.message.innerHTML = `
            <div class="password-prompt-container">
                <p style="margin-bottom: 15px;">${message}</p>
                <input type="password" id="confirm_password_input"
                       class="full-width-input"
                       placeholder="Master Password"
                       style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px;"
                       autocomplete="current-password">
            </div>
        `;

        confirmUI.okBtn.setText(okText);
        confirmUI.okBtn.classList.remove('danger-btn');
        confirmUI.okBtn.classList.add('success-btn');

        // 2. Apply Overlay Style
        section.classList.add('confirm-floating-overlay');
        section.setVisible(true);

        // Auto-focus the input for UX
        setTimeout(() => document.getElementById('confirm_password_input')?.focus(), 50);

        // 3. Setup Listeners
        const cleanup = (value) => {
            section.setVisible(false);
            section.classList.remove('confirm-floating-overlay');
            resolve(value);
        };

        confirmUI.okBtn.onClick(() => {
            const val = document.getElementById('confirm_password_input').value;
            cleanup(val);
        });

        confirmUI.cancelBtn.onClick(() => {
            cleanup(null);
        });

        // Allow "Enter" key to submit
        const handleEnter = (e) => {
            if (e.key === 'Enter') {
                const val = document.getElementById('confirm_password_input').value;
                cleanup(val);
                window.removeEventListener('keydown', handleEnter);
            }
        };
        window.addEventListener('keydown', handleEnter);
    });
}

export function hideConfirmUI() {
    swapVisibility(confirmUI.mainSection, vaultUI.mainSection);
}
