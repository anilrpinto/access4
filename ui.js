"use strict";

import { G } from './global.js';
import { log, debug, info, warn, error, setLogLevel, DEBUG, INFO, WARN, ERROR } from './log.js';

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

    initIdleTimer();
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

export function signInSuccess() {
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

function initIdleTimer() {
    const resetTimer = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(async () => {
            log("[initIdleTimer] Inactivity timeout — releasing Drive lock");
            await releaseDriveLock();
        }, 10 * 60 * 1000); // 10 minutes
    };

    // Events that "wake up" the timer
    ['mousedown', 'mousemove', 'keydown', 'keypress', 'click',' scroll', 'touchstart'].forEach(evt => {
        document.addEventListener(evt, resetTimer, { passive: true });
    });

    resetTimer(); // Start it immediately
}

async function releaseDriveLock() {
    if (!G.driveLockState?.fileId) return;

    G.driveLockState.heartbeat?.stop();

    const cleared = {
        ...G.driveLockState.lock,
        expiresAt: new Date(0).toISOString()
    };

    await writeLockToDrive(
        G.driveLockState.envelopeName,
        cleared,
        G.driveLockState.fileId
    );

    log("[releaseDriveLock] Drive lock released");
    G.driveLockState = null;
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

    signinBtn.disabled = false;
}