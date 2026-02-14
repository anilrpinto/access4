"use strict";

export let userEmailSpan;
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

export function load() {

    // Cache DOM
    userEmailSpan = document.getElementById("userEmailSpan");
    signinBtn = document.getElementById("signinBtn");
    passwordSection = document.getElementById("passwordSection");
    confirmPasswordSection = document.getElementById("confirmPasswordSection");
    unlockBtn = document.getElementById("unlockBtn");
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
}

export function signInSuccess() {
    logEl.textContent = "";
    signinBtn.disabled = true;
    logoutBtn.disabled = false;
    passwordSection.style.display = "block";
}