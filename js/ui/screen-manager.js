import { log, debug, info, warn, error } from '@/shared/exports.js';

export const ScreenManager = {
    screens: {},
    hooks: {}, // Stores { onShow: fn, onHide: fn } for each key
    activeScreenKey: null, // Start null so the first switch always works

    EXPLORER_SCREENKEY: 'explorer',
    USERS_SCREENKEY: 'users',
    RECOVERY_KEY_ROTATION_SCREENKEY: 'recovery-key-rotation',
    RAW_DATA_SCREENKEY: 'raw-data',
    EDITOR_SCREENKEY: 'editor',
    CONFIRM_SCREENKEY: 'confirm',

    isRegistered(key) {
        // Centralized logic for "What defines a registered screen?"
        return !!this.hooks[key] && !!this.screens[key];
    },

    /**
     * @param {string} key - Unique ID
     * @param {HTMLElement} screen - The DOM node
     * @param {Object} lifecycle - { onShow: Function, onHide: Function }
     */
    register(key, screen, lifecycle = {}) {
        if (this.isRegistered(key)) {
            log("ScreenManager", `'${key}' already registered. Skipping.`);
            return;
        }
        log("ScreenManager", `Registering: '${key}'`);

        this.screens[key] = screen;
        this.hooks[key] = lifecycle;

        if (screen) screen.setVisible(false);
    },

    switchView(screenKey) {

        // ✅ Use the helper here too for safety!
        if (!this.isRegistered(screenKey)) {
            warn("ScreenManager", `Cannot switch to '${screenKey}'. Not registered.`);
            if (screenKey !== 'explorer') this.switchView('explorer');
            return;
        }

        // ✅ 1. GUARD: If we are already there, do nothing.
        if (this.activeScreenKey === screenKey) {
            log("ScreenManager", `Already on '${screenKey}', ignoring switch.`);
            return;
        }

        log("ScreenManager", `Switching from '${this.activeScreenKey}' to '${screenKey}'`);

        // 2. EXIT CURRENT SCREEN
        if (this.activeScreenKey) {
            const currentHook = this.hooks[this.activeScreenKey];

            // Run onHide ONCE. If it returns false, stop everything.
            if (currentHook?.onHide && typeof currentHook.onHide === 'function') {
                if (currentHook.onHide() === false) {
                    log("ScreenManager", `Switch blocked by '${this.activeScreenKey}'`);
                    return;
                }
            }

            // Hide the old screen
            const fromScreen = this.screens[this.activeScreenKey];
            if (fromScreen) fromScreen.setVisible(false);
        }

        // 3. ENTRY LOGIC: Show the target screen
        const toScreen = this.screens[screenKey];
        if (toScreen) {
            this.activeScreenKey = screenKey;
            toScreen.setVisible(true);

            const targetHook = this.hooks[screenKey];
            if (targetHook?.onShow && typeof targetHook.onShow === 'function') {
                // Use Promise.resolve to handle both async and sync hooks
                Promise.resolve(targetHook.onShow()).catch(err => {
                    error("ScreenManager", `Error in '${screenKey}' onShow:`, err);
                });
            }
        } else {
            warn("ScreenManager", `Screen '${screenKey}' not found! Falling back to explorer.`);
            if (screenKey !== 'explorer') this.switchView('explorer');
        }
    },

    /**
     * If you ever pass ScreenManager.switchToMainView as a callback (e.g., to an addEventListener),
     * the 'this' context might break. If you plan to do that, define it as an arrow function instead:
     * then use ScreenManager.switchView(ScreenManager.EXPLORER_SCREENKEY)
     */
    goHome() {
        this.switchView(this.EXPLORER_SCREENKEY);
    },

    isActive(screenKey) {
        return (this.activeScreenKey === screenKey);
    },

    sync() {
        const key = this.activeScreenKey;
        if (!key || !this.screens[key]) return;

        log("ScreenManager", `Syncing active screen: '${key}'`);

        // Force visibility just in case a manual style change broke it
        this.hideAll();
        this.screens[key].setVisible(true);

        // Re-run the show hook to refresh the UI (like renderVaultExplorer)
        if (this.hooks[key]?.onShow) {
            this.hooks[key].onShow();
        }
    },

    /**
     * Call this on Logout or before loadVault to ensure
     * the next switchView isn't blocked by old state.
     */
    reset() {
        log("ScreenManager", "Resetting session state.");
        this.activeScreenKey = null;

        // Optional: Hide all registered screens to ensure a clean slate
        this.hideAll();
    },

    hideAll() {
        Object.values(this.screens).forEach(s => {
            if (s && s.setVisible) s.setVisible(false);
        });
    }
};

// Force it onto the window for absolute certainty
window.ScreenManager = ScreenManager;