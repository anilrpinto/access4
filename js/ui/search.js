import { log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { vaultNavBarUI, advSearchUI } from '@/ui/loader.js';
import { handleSearchInput, getActiveVaultData } from '@/ui/vault.js';

// This holds the state from your modal
export const ADVANCED_FILTER_STATE = {
    active: false,
    searchIn: "",       // Default: All fields
    attachment: "",     // Default: Any (don't care)
    caseSensitive: false,
    tokenLogic: "contains" // Default: Partial match
};

/**
 * THE ENGINE: Generates visibility and highlight instructions
 */
/**
 * Creates a Map of IDs that should be visible and/or highlighted.
 * @param {Object} vaultData - Your main vault object.
 * @param {string} query - The search text.
 */
export function generateFilterMap(vaultData, query) {
    //log("filter.generateFilterMap", "called - query:", query);

    const s = ADVANCED_FILTER_STATE;
    const q = query.trim();

    // If query is empty and we aren't doing an "Attachment Only/None" search, exit
    if (!q && !s.attachment) return null;

    const map = {
        visible: new Set(),
        highlighted: new Set()
    };

    function walk(node, type = 'group', parentMatch = false) {
        let nodeHasMatch = false;

        // --- A. PRE-FILTER: Attachment Status ---
        if (type === 'item') {
            const hasAttach = node.attachments && node.attachments.length > 0;
            if (s.attachment === 'only' && !hasAttach) return false;
            if (s.attachment === 'none' && hasAttach) return false;
        }

        // --- B. MATCHING LOGIC: Respecting "searchIn" ---
        const scope = s.searchIn;

        // 1. Check current node name (Groups or Items)
        if (!scope || scope === 'groups' || scope === 'items') {
            const name = (type === 'group' ? node.name : node.label) || "";
            if (smartMatch(name, q, s)) {
                map.highlighted.add(node.id);
                nodeHasMatch = true;
            }
        }

        // 2. Check Fields (Item Details)
        if (type === 'item' && node.fields) {
            node.fields.forEach(f => {
                // 1. Normalize the field key from the JSON to Uppercase for the comparison
                const fieldKeyUpper = (f.key || "").trim().toUpperCase();

                // 2. Scope check: blank, 'details', or exact match to the ALL CAPS scope
                const isInScope = !scope || scope === 'details' || scope === fieldKeyUpper;

                if (isInScope) {
                    // If we are scoped to a specific label (e.g. "PIN"), we only match the VALUE.
                    // Otherwise, we match label OR value.
                    const labelMatch = (scope !== fieldKeyUpper) && smartMatch(f.key, q, s);
                    const valueMatch = smartMatch(f.val, q, s);

                    if (labelMatch || valueMatch) {
                        map.highlighted.add(`${node.id}-field-${f.key}`);
                        nodeHasMatch = true;
                    }
                }
            });
        }

        // 3. Check Attachments
        if (type === 'item' && node.attachments) {
            if (!scope || scope === 'attachments') {
                node.attachments.forEach(a => {
                    if (smartMatch(a.key, q, s)) {
                        map.highlighted.add(`${node.id}-attachment-${a.val}`);
                        nodeHasMatch = true;
                    }
                });
            }
        }

        // --- C. RECURSION (Preserving your original behavior) ---
        const isVisibleByInheritance = parentMatch || nodeHasMatch;
        let childrenHaveMatch = false;

        if (node.groups) {
            node.groups.forEach(g => {
                if (walk(g, 'group', isVisibleByInheritance)) childrenHaveMatch = true;
            });
        }

        if (node.items) {
            node.items.forEach(i => {
                if (walk(i, 'item', isVisibleByInheritance)) childrenHaveMatch = true;
            });
        }

        // FINAL VISIBILITY CHECK
        if (nodeHasMatch || childrenHaveMatch || parentMatch) {
            map.visible.add(node.id);
            return true;
        }

        return false;
    }

    if (vaultData.groups) {
        vaultData.groups.forEach(g => walk(g));
    }

    return map;
}

/**
 * HELPER: The logic core that replaces .includes()
 */
function smartMatch(target, query, settings) {
    if (!target) return false;
    // Standardize Case
    let t = settings.caseSensitive ? String(target) : String(target).toLowerCase();
    let q = settings.caseSensitive ? String(query) : String(query).toLowerCase();

    // Standardize Logic
    switch (settings.tokenLogic) {
        case 'exact':
            return t === q;
        case 'or':
            return q.split(/\s+/).some(token => token && t.includes(token));
        case 'and':
            return q.split(/\s+/).every(token => token && t.includes(token));
        case 'contains':
        default:
            return t.includes(q);
    }
}

let clickCount = 0;
let clickTimer = null;
let autoHideTimer = null;

const filterToggle = vaultNavBarUI.filterToggle;
const filterWrapper = vaultNavBarUI.filterSection;
const filterInput = vaultNavBarUI.filterInput;
const breadcrumbs = vaultNavBarUI.breadcrumbs;
const navBar = vaultNavBarUI.mainSection;

// --- 1. THE QUIET HIDE (UI ONLY) ---

/**
 * Tucks the filter input away to show breadcrumbs.
 * Does NOT clear the text or the green navbar state.
 */
export function hideFilterUI() {
    if (!filterWrapper.classList.contains('hidden')) {
        filterWrapper.classList.add('hidden');
        breadcrumbs.classList.remove('hidden');
    }
    stopAutoHideTimer();
}

function startAutoHideTimer() {
    stopAutoHideTimer();
    autoHideTimer = setTimeout(() => {
        // We only auto-hide if the user isn't actively typing
        hideFilterUI();
    }, 5000);
}

function stopAutoHideTimer() {
    if (autoHideTimer) {
        clearTimeout(autoHideTimer);
        autoHideTimer = null;
    }
}

// --- 2. TOGGLE & MULTI-CLICK LOGIC ---
filterToggle.onclick = () => {
    clickCount++;

    if (clickTimer) clearTimeout(clickTimer);

    clickTimer = setTimeout(() => {
        if (clickCount === 1) {
            // --- SINGLE CLICK: Toggle UI ---
            const isNowHidden = filterWrapper.classList.toggle('hidden');
            breadcrumbs.classList.toggle('hidden');

            if (!isNowHidden) {
                setTimeout(() => filterInput.focus(), 10);
                startAutoHideTimer(); // Start 5s countdown
            } else {
                stopAutoHideTimer();
            }

        } else if (clickCount === 2) {
            // --- DOUBLE CLICK: Advanced Modal ---
            log("filter.filterToggle", "Double Click: Opening Advanced Modal...");
            showAdvancedSearchModal(getActiveVaultData());
        } else if (clickCount >= 3) {
            // --- TRIPLE CLICK: Full Reset ---
            log("filter.filterToggle", "Triple Click: Clearing search and resetting UI");
            resetAdvancedSettings();
            resetFilter();
        }

        clickCount = 0;
    }, 250);
};

// --- 3. INPUT & DEBOUNCE ---
filterInput.oninput = (e) => {
    const query = e.target.value;

    // Reset the 5s timer every time the user types
    startAutoHideTimer();

    // Emerald green theme if filter is active
    if (query.trim().length > 0) {
        navBar.classList.add('filter-mode-active');
    } else {
        navBar.classList.remove('filter-mode-active');
    }

    handleSearchInput(query);
};

function resetFilter() {
    filterInput.value = "";
    navBar.classList.remove('filter-mode-active');
    filterWrapper.classList.add('hidden');
    breadcrumbs.classList.remove('hidden');
    handleSearchInput("");
}

function resetAdvancedSettings() {
    ADVANCED_FILTER_STATE.active = false;
    ADVANCED_FILTER_STATE.searchIn = "";
    ADVANCED_FILTER_STATE.attachment = "";
    ADVANCED_FILTER_STATE.caseSensitive = false;
    ADVANCED_FILTER_STATE.tokenLogic = "contains";
}

function applyAdvancedSearch() {
    // 1. Read values from your modal HTML elements
    ADVANCED_FILTER_STATE.searchIn = advSearchUI.scope.value;
    ADVANCED_FILTER_STATE.attachment = currentToggleVal; // From your triple-toggle
    ADVANCED_FILTER_STATE.caseSensitive = advSearchUI.case.checked;
    ADVANCED_FILTER_STATE.tokenLogic = advSearchUI.logic.value;

    // 2. Trigger the existing search flow with the current input text
    const currentQuery = vaultNavBarUI.filterInput.value;
    handleSearchInput(currentQuery);

    // 3. Close Modal
    hideModal('advSearch_modal');
}

/**
 * SCRAPER: Iterates through the vault to find all unique Detail Labels.
 */
function getUniqueFieldLabels(vaultData) {
    const labels = new Set();

    const walk = (node) => {
        if (node.fields) {
            node.fields.forEach(f => {
                if (f.key && f.key.trim()) {
                    // Force to Uppercase to match the Details screen
                    labels.add(f.key.trim().toUpperCase());
                }
            });
        }
        // Recursively walk through groups and items
        if (node.groups) node.groups.forEach(g => walk(g));
        if (node.items) node.items.forEach(i => walk(i));
    };

    walk(vaultData);

    // Return sorted alphabetically (A-Z)
    return Array.from(labels).sort((a, b) => a.localeCompare(b));
}

/**
 * UI CONTROLLER: Shows the modal and wires up the logic.
 */
export function showAdvancedSearchModal(vaultData) {
    if (!vaultData) {
        warn("filter.showAdvancedSearchModal", "No vault data.");
        return;
    }

    // 1. CLEAR AND RE-POPULATE DYNAMIC LABELS
    advSearchUI.dynamicLabels.innerHTML = '';
    const uniqueLabels = getUniqueFieldLabels(vaultData);

    uniqueLabels.forEach(label => {
        const opt = document.createElement('option');
        opt.value = label;
        opt.textContent = label;
        advSearchUI.dynamicLabels.appendChild(opt);
    });

    // 2. SYNC UI WITH CURRENT STATE
    const s = ADVANCED_FILTER_STATE;
    advSearchUI.scope.value = s.searchIn;
    advSearchUI.case.checked = s.caseSensitive;
    advSearchUI.logic.value = s.tokenLogic;

    // NEW: Sync the Attachment select dropdown instead of buttons
    advSearchUI.attach.value = s.attachment;

    // 3. SHOW MODAL
    advSearchUI.mainSection.classList.remove('hidden');

    // 4. BUTTON LISTENERS
    advSearchUI.run.onclick = () => {
        // Update the state object with the latest UI values
        s.searchIn = advSearchUI.scope.value;
        s.caseSensitive = advSearchUI.case.checked;
        s.tokenLogic = advSearchUI.logic.value;
        s.attachment = advSearchUI.attach.value; // Read from the new select

        // Trigger the search engine
        const currentQuery = vaultNavBarUI.filterInput.value;
        handleSearchInput(currentQuery);

        advSearchUI.mainSection.classList.add('hidden');
    };

    advSearchUI.reset.onclick = () => {
        resetAdvancedSettings();
        resetFilter();
        // Re-run the modal setup to refresh the UI elements to default
        showAdvancedSearchModal(vaultData);
        advSearchUI.mainSection.classList.add('hidden');
    };

    advSearchUI.close.onclick = () => {
        advSearchUI.mainSection.classList.add('hidden');
    };
}
