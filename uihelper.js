"use strict";

import { log, trace, debug, info, warn, error } from './log.js';

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
        el.setVisible = function(show) {
            // Using inline-block as per your layout preference
            this.style.display = show ? "inline-block" : "none";

            // This doesn't work as expected
            //this.style.display = show ? "" : "none";
            return this; // Allow chaining
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

    ui.setVisible = (show) => {
        Object.values(ui).forEach(el => {
            if (el instanceof HTMLElement) el.setVisible?.(show);
        });
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

/*
    //Pro-Tip on setVisible
    //If you find that your div containers (like mainSection) look weird with inline-block, you can always override just that one after loading:
    const vaultRecoveryKey = loadUI([...], 'vaultRecoveryKey_', 'vaultBody');

    // Force the main container to use standard block layout
    vaultRecoveryKey.mainSection.setVisible = function(show) {
        this.style.display = show ? "block" : "none";
    };
*/