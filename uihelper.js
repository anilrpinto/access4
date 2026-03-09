"use strict";

import { log, trace, debug, info, warn, error } from './log.js';

/**
 * @param {string[]} names - Elements to find
 * @param {string} prefix - ID prefix
 * @param {HTMLElement|string} scope - Container element or ID (optional)
 */
export function loadUI(names, prefix = "", scope = document) {
    const ui = {};
    const root = typeof scope === "string" ? document.getElementById(scope) : scope;
    const searchArea = root || document;

    // Internal helper to attach the method to individual DOM elements
    const attachMethods = (el) => {
        if (!el) return;
        el.setVisible = function(show) {
            // Using inline-block as per your layout preference
            this.style.display = show ? "inline-block" : "none";

            // This doesn't work as expected
            //this.style.display = show ? "" : "none";
        };

        el.setText = function(text) {
            if ("value" in this && (this.tagName === "INPUT" || this.tagName === "TEXTAREA")) {
                this.value = text ?? "";
            } else {
                this.textContent = text ?? "";
            }
        };

        el.setValue = function(val) {
            if ("value" in this) {
                this.value = val ?? "";
            }
        };

        el.setEnabled = function(enabled) {
            this.disabled = !enabled;
        };

        el.clear = function() {
            if ("value" in this) {
                this.value = "";
            } else {
                this.textContent = "";
            }
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
            try {
                warn(`UI Loader: "${id}" not found.`);
            } catch (err) {
                console.log(`UI Loader: "${id}" not found.`);
            }
        }
    });

    // Group helpers
    ui.setVisible = (show) => {
        Object.values(ui).forEach(el => el.setVisible?.(show));
    };

    ui.setText = (text) => {
        Object.values(ui).forEach(el => el.setText?.(text));
    };

    ui.setEnabled = (enabled) => {
        Object.values(ui).forEach(el => el.setEnabled?.(enabled));
    };

    ui.clear = function() {
        names.forEach(function(name) {
            if (ui[name] && ui[name].clear) ui[name].clear();
        });
    };

    // FIXED: Added check for 'el.classList' to prevent "Cannot read properties of undefined"
    ui.onClick = (handler) => {
        Object.values(ui).forEach(el => {
            // Check: Is it a DOM element? Does it have a tagName? Does it have classList?
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