import { log, trace, debug, info, warn, error } from '@/shared/log.js';

/**
 * @param {string[]} names - Elements to find
 * @param {string} prefix - ID prefix
 * @param {HTMLElement|string} scope - Container element or ID (optional)
 */
export function loadUI(names, prefix = "", scope = document) {
    const ui = {};

    // FIX: Robust scope detection
    let root;
    if (typeof scope === "string") {
        root = document.getElementById(scope);
    } else if (scope && !scope.querySelector && typeof scope === "object") {
        // If scope is a UI object from a previous loadUI call, find the first actual element
        root = Object.values(scope).find(el => el instanceof HTMLElement);
    } else {
        root = scope;
    }

    const searchArea = root || document;

    // Internal helper to attach the method to individual DOM elements
    const attachMethods = (el) => {
        if (!el) return;

        // Default visibility behavior
        el.setVisible = function(show) {
            // Using inline-block as per your layout preference
            this.style.display = show ? "inline-block" : "none";

            // This doesn't work as expected
            //this.style.display = show ? "" : "none";
            return this; // Allow chaining
        };

        // This redefines setVisible for this specific element to use 'flex'
        el.setFlex = function() {
            this.setVisible = function(show) {
                this.style.display = show ? "flex" : "none";
                return this;
            };
            // If it's currently visible, switch it to flex immediately
            if (this.style.display !== "none") this.style.display = "flex";
            return this;
        };

        el.toggleVisibility = function() {
            const isHidden = this.style.display === "none" || getComputedStyle(this).display === "none";
            // Use the element's own setVisible to respect whether it's 'flex' or 'inline-block'
            this.setVisible(isHidden);
            return this;
        };

        el.setText = function(text) {
            if ("value" in this && (this.tagName === "INPUT" || this.tagName === "TEXTAREA")) {
                this.value = text ?? "";
            } else {
                this.textContent = text ?? "";
            }
            return this;
        };

        el.setValue = function(val) {
            if ("value" in this) {
                this.value = val ?? "";
            }
            return this;
        };

        el.setEnabled = function(enabled) {
            this.disabled = !enabled;
            return this;
        };

        el.setReadOnly = function(isReadOnly) {
            // Only inputs and textareas support the readOnly property
            if ("readOnly" in this) {
                this.readOnly = isReadOnly;
            }
            return this;
        };

        el.clear = function() {
            if ("value" in this) {
                this.value = "";
            } else {
                this.textContent = "";
            }
            return this;
        }

        el.onClick = function(handler) {
            this.onclick = handler;

            // this will stack and removing event listeners is messy if anonymous functions are used,
            // which is a high probability
            //this.addEventListener("click", handler);
            return this;
        };
    };

    names.forEach(name => {
        const id = prefix + name;
        const element = searchArea.querySelector(`#${id}`);

        if (element) {
            attachMethods(element); // Attach .setVisible() to the element itself
            ui[name] = element;
        } else {
            const msg = `UI Loader: "${id}" not found.`;
            try { warn(msg); } catch (err) { console.warn(msg); }
        }
    });

    // --- GROUP HELPERS ---
    // Added safety checks to ensure we only loop over HTMLElements, not the helper functions

    // NEW: Set all elements in this group to use 'flex' for setVisible
    ui.setFlex = function() {
        Object.values(ui).forEach(el => {
            if (el instanceof HTMLElement) el.setFlex?.();
        });
        return ui; // Allow chaining
    };

    ui.toggleVisibility = function() {
        Object.values(ui).forEach(el => {
            if (el instanceof HTMLElement) el.toggleVisibility?.();
        });
        return ui;
    };

    ui.setVisible = (show) => {
        Object.values(ui).forEach(el => {
         if (el instanceof HTMLElement) el.setVisible?.(show);
        });
        return ui;
    };

    ui.setText = (text) => {
        Object.values(ui).forEach(el => {
            if (el instanceof HTMLElement) el.setText?.(text);
        });
    };

    ui.setEnabled = (enabled) => {
        Object.values(ui).forEach(el => {
            if (el instanceof HTMLElement) el.setEnabled?.(enabled);
        });
    };

    ui.setReadOnly = (isReadOnly) => {
        Object.values(ui).forEach(el => {
            if (el instanceof HTMLElement) el.setReadOnly?.(isReadOnly);
        });
        return ui;
    };

    ui.clear = function() {
        Object.values(ui).forEach(el => {
            if (el instanceof HTMLElement) el.clear?.();
        });
    };

    // FIXED: Added check for 'el.classList' to prevent "Cannot read properties of undefined"
    ui.onClick = (handler) => {
        Object.values(ui).forEach(el => {
            if (el instanceof HTMLElement && el.tagName) {
                const isButton = el.tagName === "BUTTON";
                const isLink = el.classList?.contains("link-button");
                if (isButton || isLink) {
                    el.onClick(handler);
                }
            }
        });
    };

    return ui;
}

export function swapVisibility(hide, show) {
    if (hide)
        hide.setVisible(false);

    if (show)
        show.setVisible(true);
}

export function showSilentToast(msg) {
    let toast = document.getElementById('vault_silentToast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'vault_silentToast';
        toast.className = 'silent-toast';
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 4000);
}

export async function copyToClipboard(text) {
    try {
        navigator.clipboard.writeText(text);
        showSilentToast("Copied to clipboard!");
    } catch (err) {
        // Fallback for older browsers
        document.execCommand('copy');
        showSilentToast("Copied to clipboard");
    }
}

/*
    //Pro-Tip on setVisible
    //If you find that your div containers (like mainSection) look weird with inline-block, you can always override just that one after loading:
    const vaultRecoveryKeyUI = loadUI([...], 'vaultRecoveryKeyUI_', 'vaultBody');

    // Force the main container to use standard block layout
    vaultRecoveryKeyUI.mainSection.setVisible = function(show) {
        this.style.display = show ? "block" : "none";
    };
*/