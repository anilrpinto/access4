import { systemModalUI } from "@/ui/loader.js";

export function showOverlayChoiceUI({ title, message, okText = "Choice 1", cancelText = "Choice 2", onConfirm, onCancel }) {
    showOverlayConfirmUI({ title,message, okText, cancelText, onConfirm, onCancel });
}

export function showOverlayConfirmUI({ title, message, okText = "Delete", cancelText = "Cancel", onConfirm, onCancel }) {
    const section = systemModalUI.mainSection;

    // 1. Setup Content
    systemModalUI.title.setText(title);
    systemModalUI.message.innerHTML = message;

    systemModalUI.okBtn.setText(okText);
    systemModalUI.cancelBtn.setText(cancelText);

    systemModalUI.okBtn.classList.remove('success-btn'); // Remove green if present
    systemModalUI.okBtn.classList.add('danger-btn');

    // 2. Apply Overlay Style
    section.classList.add('confirm-floating-overlay');
    section.setVisible(true);

    systemModalUI.okBtn.onClick(null);
    systemModalUI.cancelBtn.onClick(null);

    // 3. Setup Listeners
    systemModalUI.okBtn.onClick(() => {
        section.setVisible(false);
        section.classList.remove('confirm-floating-overlay');
        if (onConfirm) onConfirm();
    });

    systemModalUI.cancelBtn.onClick(() => {
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
    const section = systemModalUI.mainSection;

    // 1. Setup Content
    systemModalUI.title.setText(title);
    systemModalUI.message.innerHTML = message;

    // 2. Hide the Cancel button and update the OK button
    systemModalUI.cancelBtn.setVisible(false);
    systemModalUI.okBtn.setText(okText);
    systemModalUI.okBtn.classList.remove('danger-btn'); // Remove red if present
    systemModalUI.okBtn.classList.add('success-btn');   // Add a green/primary style

    // 3. Apply the Overlay Style
    section.classList.add('confirm-floating-overlay');
    section.setVisible(true);

    // 4. Setup Listener
    systemModalUI.okBtn.onClick(() => {
        section.setVisible(false);
        section.classList.remove('confirm-floating-overlay');
        systemModalUI.cancelBtn.setVisible(true); // Reset for the next use
        if (onConfirm) onConfirm();
    });
}

/**
 * A reusable Password Prompt using the existing Confirm UI Overlay
 */
export function showOverlayPasswordUI({ title = "Security Check", message = "Please enter your password:", okText = "Proceed", cancelText = "Cancel" }) {
    const section = systemModalUI.mainSection;

    return new Promise((resolve) => {
        // 1. Setup Content
        systemModalUI.title.setText(title);

        // Inject the message and a password input field
        systemModalUI.message.innerHTML = `
            <div class="password-prompt-container">
                <p style="margin-bottom: 15px;">${message}</p>
                <input type="password" id="confirm_password_input"
                       class="full-width-input"
                       placeholder="Master Password"
                       style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px;"
                       autocomplete="current-password">
            </div>
        `;

        systemModalUI.okBtn.setText(okText);
        systemModalUI.okBtn.classList.remove('danger-btn');
        systemModalUI.okBtn.classList.add('success-btn');

        systemModalUI.cancelBtn.setText(cancelText);

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

        systemModalUI.okBtn.onClick(() => {
            const val = document.getElementById('confirm_password_input').value;
            cleanup(val);
        });

        systemModalUI.cancelBtn.onClick(() => {
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
