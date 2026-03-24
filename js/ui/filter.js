import { log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { vaultNavBarUI } from '@/ui/loader.js';
import { handleSearchInput } from '@/ui/vault.js';

/**
 * THE ENGINE: Generates visibility and highlight instructions
 */
/**
 * Creates a Map of IDs that should be visible and/or highlighted.
 * @param {Object} vaultData - Your main vault object.
 * @param {string} query - The search text.
 */
export function generateFilterMap(vaultData, query) {
    const q = query.toLowerCase().trim();
    if (!q) return null; // No filter applied

    const map = {
        visible: new Set(),
        highlighted: new Set()
    };

    function walk(node, type = 'group', parentMatch = false) {
        let nodeHasMatch = false;

        // 1. Check current node name
        const name = (type === 'group' ? node.name : node.label) || "";
        if (name.toLowerCase().includes(q)) {
            map.highlighted.add(node.id);
            nodeHasMatch = true;
        }

        // 2. Check Fields
        if (type === 'item' && node.fields) {
            node.fields.forEach(f => {
                if (f.key.toLowerCase().includes(q) || f.val.toLowerCase().includes(q)) {
                    map.highlighted.add(`${node.id}-field-${f.key}`);
                    nodeHasMatch = true;
                }
            });
        }

        // 💡 THE FIX: If the parent matched OR this node matched,
        // we tell the children they are in a "matched branch"
        const isVisibleByInheritance = parentMatch || nodeHasMatch;

        let childrenHaveMatch = false;

        // 3. Recurse into SUB-GROUPS
        if (node.groups) {
            node.groups.forEach(g => {
                if (walk(g, 'group', isVisibleByInheritance)) childrenHaveMatch = true;
            });
        }

        // 4. Recurse into ITEMS
        if (node.items) {
            node.items.forEach(i => {
                if (walk(i, 'item', isVisibleByInheritance)) childrenHaveMatch = true;
            });
        }

        // FINAL VISIBILITY CHECK:
        // A node is visible if:
        // - It matched
        // - Any child matched
        // - OR its parent matched (inheritance)
        if (nodeHasMatch || childrenHaveMatch || parentMatch) {
            map.visible.add(node.id);
            return true; // Tells parent "hey, I (or my kids) have a match"
        }

        return false;
    }

    // Start walking from the root groups
    if (vaultData.groups) {
        vaultData.groups.forEach(g => walk(g));
    }

    return map;
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
            // --- DOUBLE CLICK: Full Reset ---
            console.log("Double Click: Clearing search and resetting UI");
            resetFilter();

        } else if (clickCount >= 3) {
            // --- TRIPLE CLICK: Advanced Modal ---
            console.log("Triple Click: Opening Advanced Modal...");
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