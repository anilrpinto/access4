import { log, trace, debug, info, warn, error } from '@/shared/exports.js';
import { confirmUI } from '@/ui/loader.js';

function ensureConfirmRegistered() {
    window.ScreenManager.register(window.ScreenManager.CONFIRM_SCREENKEY, confirmUI.mainSection, {
        onShow: () => {
            log("Confirm", "Confirmation screen active.");
        },
        onHide: () => {
            // Optional: reset colors if you use danger-btn/success-btn
            confirmUI.okBtn.classList.remove('danger-btn', 'success-btn');
            return true;
        }
    });
}

export function showConfirmUI({title = "Confirm", message = "Are you sure?", okText = "Confirm", cancelText = "Cancel", onConfirm, onCancel }) {

    // 1. Ensure it's in the Manager
    ensureConfirmRegistered();
    window.ScreenManager.switchView(window.ScreenManager.CONFIRM_SCREENKEY);

    confirmUI.title.setText(title);

    //confirmUI.message.setText(message);
    confirmUI.message.innerHTML = message;   // Supports embedded html tags

    confirmUI.okBtn.setText(okText);
    confirmUI.cancelBtn.setText(cancelText);

    confirmUI.okBtn.classList.remove('success-btn'); // Remove green if present
    confirmUI.okBtn.classList.add('danger-btn');

    // Clear previous listeners to avoid "Double Triggering"
    confirmUI.okBtn.onClick(null);
    confirmUI.cancelBtn.onClick(null);

    // Setup New Listeners
    confirmUI.okBtn.onClick(() => {
        window.ScreenManager.goHome();
        if (onConfirm) onConfirm();
    });

    confirmUI.cancelBtn.onClick(() => {
        window.ScreenManager.goHome();
        if (onCancel) onCancel();
    });
}
