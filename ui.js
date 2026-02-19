"use strict";

import { C } from './constants.js';
import { G } from './global.js';
import { log, trace, debug, info, warn, error } from './log.js';

export let signinBtn;
export let passwordSection;
export let confirmPasswordSection;
export let unlockBtn;

export let titleUnlocked;
export let plaintextInput;
export let saveBtn;

export let loginView;
export let unlockedView;
export let passwordInput;
export let confirmPasswordInput;

export let logoutBtn;

export let logEl;

let userEmailSpan;
let unlockMessage;
let idleTimer;
let idleCallback = null;

const idleEvents = ['mousedown', 'mousemove', 'keydown', 'keypress', 'click', 'scroll', 'touchstart'];

const resetTimer = () => {
    clearTimeout(idleTimer);

    if (!idleCallback) return;

    idleTimer = setTimeout(async () => {
        if (typeof idleCallback === 'function') {
            await idleCallback('idle.timeout');
        }
    }, C.IDLE_TIMEOUT_MS);
};

export function init() {

    // Cache DOM
    userEmailSpan = document.getElementById("userEmailSpan");
    signinBtn = document.getElementById("signinBtn");
    passwordSection = document.getElementById("passwordSection");
    confirmPasswordSection = document.getElementById("confirmPasswordSection");
    unlockBtn = document.getElementById("unlockBtn");
    unlockMessage = document.getElementById("unlockMessage");

    logoutBtn = document.getElementById("logoutBtn");

    loginView = document.getElementById("loginView");
    unlockedView = document.getElementById("unlockedView");
    passwordInput = document.getElementById("passwordInput");
    confirmPasswordInput = document.getElementById("confirmPasswordInput");
    logEl = document.getElementById("log");

    titleUnlocked = document.getElementById("titleUnlocked");
    plaintextInput = document.getElementById("plaintextInput");
    saveBtn = document.getElementById("saveBtn");

    // Initial UI state
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";
    unlockedView.style.display = "none";

    setupTitleGesture();
    initLoginUI();
}

export function showUnlockMessage(msg, type = "error") {
    if (!unlockMessage) return;

    unlockMessage.textContent = msg;
    unlockMessage.className = `unlock-message ${type}`;
}

export function bindClick(el, callback, options = {}) {
    if (!el) {
        // Use your new logger!
        warn("[bindClick] Attempted to bind click to a null element.");
        return;
    }

    el.addEventListener('click', (e) => {
        callback(e);
    }, options);
}

export function promptUnlockPasword() {
    logEl.textContent = "";
    signinBtn.disabled = true;
    logoutBtn.disabled = false;
    passwordSection.style.display = "block";
}

export function showAuthorizedEmail(email) {
    userEmailSpan.textContent = email;
}

// attach gesture logic
function setupTitleGesture() {
    const t = document.getElementById("titleGesture");
    if (!t) return;

    let timer = null;

    t.addEventListener("pointerdown", () => {
        timer = setTimeout(armBiometric, 5000);
    });

    ["pointerup", "pointerleave", "pointercancel"].forEach(e =>
        t.addEventListener(e, () => clearTimeout(timer))
    );

    t.addEventListener("click", async () => {
        if (!G.biometricRegistered) return;
        await biometricAuthenticateFromGesture();
    });
}

function initLoginUI() {
    // Always show login view
    loginView.style.display = "block";
    unlockedView.style.display = "none";

    // Hide password input sections until needed
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";

    signinBtn.disabled = false;

    // Reset any messages
    showUnlockMessage("");

    // Disable save button initially
    saveBtn.disabled = true;
}

export function resetUnlockUi() {

    // 3️⃣ Clear UI state
    unlockedView.style.display = "none";
    loginView.style.display = "block";

    // Clear password inputs
    passwordInput.value = "";
    confirmPasswordInput.value = "";

    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";

    // Reset button state
    unlockBtn.disabled = false;
    unlockBtn.textContent = "Unlock";

    // Clear messages
    showUnlockMessage("");

    idleEvents.forEach(evt => {
        document.removeEventListener(evt, resetTimer);
    });

    clearTimeout(idleTimer);
    idleCallback = null;

    showAuthorizedEmail(null);
    signinBtn.disabled = false;
}

export function showVaultUI({ readOnly = false, onIdle = () => { warn('idle timeout fired') } } = {}) {

    log("[showVaultUI] entered");

    // Hide login / password sections
    loginView.style.display = "none";
    passwordSection.style.display = "none";
    confirmPasswordSection.style.display = "none";

    // Show main unlocked view
    unlockedView.style.display = "block";

    // Update UI for read-only mode
    if (readOnly) {
        warn("[showVaultUI] Unlocked UI in read-only mode: disabling save button");
        saveBtn.disabled = true;
        saveBtn.title = "Read-only mode: cannot save";
        plaintextInput.readOnly = true;
        titleUnlocked.textContent = "Unlocked (Read-only)";
    } else {
        saveBtn.disabled = false;
        saveBtn.title = "";
        plaintextInput.readOnly = false;
        titleUnlocked.textContent = "Unlocked";
    }

    // Events that "wake up" the timer
    // Clean up old listeners to prevent memory leaks/duplicate triggers
    idleEvents.forEach(evt => {
        document.removeEventListener(evt, resetTimer);
        document.addEventListener(evt, resetTimer, { passive: true });
    });

    idleCallback = onIdle;
    resetTimer();
}

export function promptRecoverySetupUI() {
    log("[promptRecoverySetupUI] called");

    return new Promise(resolve => {
        // reuse existing inputs
        resetUnlockUi();

        passwordSection.style.display = "block";
        confirmPasswordSection.style.display = "block";

        unlockBtn.textContent = "Create Recovery Password";
        unlockBtn.disabled = false;

        showUnlockMessage(
            "Create a recovery password. This allows account recovery if all devices are lost.",
            "unlock-message"
        );

        unlockBtn.onclick = async () => {
            try {
                await handleCreateRecoveryClick();
                resolve();
            } catch (e) {
                unlockBtn.disabled = false;
                showUnlockMessage(e.message || "Recovery setup failed", "unlock-message error");
            }
        };
    });
}

export function updateLockStatusUI() {
    if (!G.driveLockState) return;

    const { expiresAt } = G.driveLockState.lock;
    trace(`[updateLockStatusUI] You hold the envelope lock (expires ${expiresAt})`);
}
