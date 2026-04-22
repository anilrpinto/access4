import { log, trace, debug, info, warn, error } from '@/shared/exports.js';
import { vaultNavBarUI, advSearchUI } from '@/ui/loader.js';
import { handleSearchInput, getActiveVaultData, refreshVault } from '@/ui/vault.js';

let _clickCount = 0;
let _clickTimer = null;
let _autoHideTimer = null;

// This holds the state from the modal
const ADVANCED_FILTER_STATE = {
    active: false,
    searchIn: "",       // Default: All fields
    attachment: "",     // Default: Any (don't care)
    caseSensitive: false,
    tokenLogic: "contains", // Default: Partial match
    dateType: "",   // "created", "modified", or ""
    dateValue: 7,
    dateUnit: "days"
};

// Add to the top of search-and-sort.js
const SORT_STATE = {
    mode: 2,
    // A↓ (A-Z), Z↓ (Z-A), 🕙↓ (Newest), 🕙↑ (Oldest)
    icons: ["A↑", "Z↓", "🕙↓", "🕙↑"],
    labels: ["Name (A-Z)", "Name (Z-A)", "Modified (Newest)", "Modified (Oldest)"]
};

/**
 * THE SORTER: Sorts arrays based on the current mode
 */
/**
 * High-Performance Sorter for Access4
 * Uses direct string operators for ISO-8601 dates to ensure
 * maximum speed and zero object overhead.
 */
export function sortVaultData(dataArray, type = 'item') {
    if (!dataArray || !Array.isArray(dataArray)) return [];

    const mode = SORT_STATE.mode;

    return [...dataArray].sort((a, b) => {
        // --- 1. NAME RESOLUTION ---
        const nameA = (type === 'group' ? a.name : a.label || "").toLowerCase();
        const nameB = (type === 'group' ? b.name : b.label || "").toLowerCase();

        // --- 2. DATE RESOLUTION (Direct String Comparison) ---
        let dateA, dateB;

        if (type === 'group') {
            // Find the "latest" ISO string in the group items
            const getMaxDateStr = (group) => {
                if (!group.items || group.items.length === 0) return "";
                let max = "";
                for (let i = 0; i < group.items.length; i++) {
                    const current = group.items[i].modified || group.items[i].created || "";
                    if (current > max) max = current;
                }
                return max;
            };
            dateA = getMaxDateStr(a);
            dateB = getMaxDateStr(b);
        } else {
            // Standard item ISO strings
            dateA = a.modified || a.created || "";
            dateB = b.modified || b.created || "";
        }

        // --- 3. THE SORT SWITCH ---
        switch (mode) {
            case 0: // Name A-Z
                return nameA.localeCompare(nameB);

            case 1: // Name Z-A
                return nameB.localeCompare(nameA);

            case 2: // Newest First (🕙↓)
                if (dateA === dateB) return nameA.localeCompare(nameB);
                return dateB > dateA ? 1 : -1;

            case 3: // Oldest First (🕙↑)
                if (dateA === dateB) return nameA.localeCompare(nameB);
                return dateA > dateB ? 1 : -1;

            default:
                return 0;
        }
    });
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
    const uniqueLabels = _getUniqueFieldLabels(vaultData);

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

    advSearchUI.dateType.value = s.dateType;
    advSearchUI.dateVal.value = s.dateValue;
    advSearchUI.dateUnit.value = s.dateUnit;

    // 3. SHOW MODAL
    advSearchUI.mainSection.classList.remove('hidden');

    advSearchUI.dateType.onchange = updateDateUIState;

    // 4. BUTTON LISTENERS
    advSearchUI.run.onclick = () => {
        // Update the state object with the latest UI values
        s.searchIn = advSearchUI.scope.value;
        s.caseSensitive = advSearchUI.case.checked;
        s.tokenLogic = advSearchUI.logic.value;
        s.attachment = advSearchUI.attach.value; // Read from the new select

        // Sync Date State
        s.dateType = advSearchUI.dateType.value;
        s.dateValue = parseInt(advSearchUI.dateVal.value) || 0;
        s.dateUnit = advSearchUI.dateUnit.value;

        const isAdvanced = (s.dateType !== "" || s.attachment !== "");

        // Trigger the search engine
        const currentQuery = vaultNavBarUI.filterInput.value;

        // 💡 ADD THIS: Force the green shade if advanced filters are on
        if (currentQuery.trim().length > 0 || isAdvanced) {
            vaultNavBarUI.mainSection.classList.add('filter-mode-active');
        } else {
            vaultNavBarUI.mainSection.classList.remove('filter-mode-active');
        }

        handleSearchInput(currentQuery, isAdvanced);

        advSearchUI.mainSection.classList.add('hidden');
    };

    advSearchUI.reset.onclick = () => {
        _resetAdvancedSettings();
        _resetFilter();
        // Re-run the modal setup to refresh the UI elements to default
        showAdvancedSearchModal(vaultData);
        advSearchUI.mainSection.classList.add('hidden');
    };

    advSearchUI.close.onclick = () => {
        advSearchUI.mainSection.classList.add('hidden');
    };

    updateDateUIState();
}

/**
 * THE ENGINE: Generates visibility and highlight instructions
 *
 * Creates a Map of IDs that should be visible and/or highlighted.
 * @param {Object} vaultData - Your main vault object.
 * @param {string} query - The search text.
 */
export function generateFilterMap(vaultData, query) {
    //log("filter.generateFilterMap", "called - query:", query);

    const s = ADVANCED_FILTER_STATE;
    const q = query.trim();

    // If EVERYTHING is empty/off, then and ONLY then do we return null
    const isDateActive = s.dateType !== ""; // Explicit check
    const isAttachActive = s.attachment !== "";

    if (!q && !isAttachActive && !isDateActive) return null;

    const map = {
        visible: new Set(),
        highlighted: new Set()
    };

    // Calculate ONCE per search
    const cutoffDate = isDateActive ? _calculateCutoff(s.dateValue, s.dateUnit) : null;
    const cutoffTime = cutoffDate ? cutoffDate.getTime() : 0;

    function walk(node, type = 'group', parentMatch = false) {
        let nodeHasMatch = false;
        const nodeName = type === 'group' ? node.name : node.label;

        // --- A. PRE-FILTER: Attachment Status ---
        if (type === 'item') {
            // 1. Attachment Check
            const hasAttach = node.attachments && node.attachments.length > 0;
            if (s.attachment === 'only' && !hasAttach) return false;

            if (s.attachment === 'none' && hasAttach) return false;

            // 2. Date Check
            if (isDateActive) {
                const itemDateStr = s.dateType === 'created' ? node.created : node.modified;
                if (!itemDateStr) return false;

                // Convert item date to milliseconds for a perfect numerical comparison
                const itemTime = new Date(itemDateStr).getTime();

                if (itemTime < cutoffTime) return false;
            }
        }

        // --- B. MATCHING LOGIC: Respecting "searchIn" ---
        const scope = s.searchIn;

        // 1. Check current node name (Groups or Items)
        if (!scope || scope === 'groups' || scope === 'items') {
            const name = (type === 'group' ? node.name : node.label) || "";
            if (q && _smartMatch(name, q, s)) {
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
                    const labelMatch = (scope !== fieldKeyUpper) && _smartMatch(f.key, q, s);
                    const valueMatch = _smartMatch(f.val, q, s);

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
                    if (_smartMatch(a.key, q, s)) {
                        map.highlighted.add(`${node.id}-attachment-${a.val}`);
                        nodeHasMatch = true;
                    }
                });
            }
        }

        // --- C. RECURSION (Preserving your original behavior) ---
        const isVisibleByInheritance = (!q || parentMatch || nodeHasMatch);
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

        // --- D. THE "HARD GATE" FILTER LOGIC ---

        // If a Date or Attachment filter is active, we change the rules for Groups:
        // A group is ONLY visible if it has at least one matching child.
        const isFiltering = s.dateType || s.attachment === 'only' || s.attachment === 'none';

        if (isFiltering && type === 'group') {
            if (childrenHaveMatch) {
                map.visible.add(node.id);
                return true;
            }
            return false; // This kills the "Genesis" group if Access4 is filtered out
        }

        // FINAL VISIBILITY CHECK
        if ((!q && type === 'item') || nodeHasMatch || childrenHaveMatch || parentMatch) {
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
 * Tucks the filter input away to show breadcrumbs.
 * Does NOT clear the text or the green navbar state.
 */
export function hideFilterUI() {
    if (!vaultNavBarUI.filterSection.classList.contains('hidden')) {
        vaultNavBarUI.filterSection.classList.add('hidden');
        vaultNavBarUI.breadcrumbs.classList.remove('hidden');
    }
    _stopAutoHideTimer();
}

/** INTERNAL FUNCTIONS **/
function _calculateCutoff(value, unit) {
    const d = new Date();
    switch (unit) {
        case 'days':   d.setDate(d.getDate() - value); break;
        case 'weeks':  d.setDate(d.getDate() - (value * 7)); break;
        case 'months': d.setMonth(d.getMonth() - value); break;
        case 'years':  d.setFullYear(d.getFullYear() - value); break;
    }
    return d;
}

function _startAutoHideTimer() {
    _stopAutoHideTimer();
    _autoHideTimer = setTimeout(() => {
        // We only auto-hide if the user isn't actively typing
        hideFilterUI();
    }, 5000);
}

function _stopAutoHideTimer() {
    if (_autoHideTimer) {
        clearTimeout(_autoHideTimer);
        _autoHideTimer = null;
    }
}

function _handleFilterToggleClick() {
    _clickCount++;

    if (_clickTimer) clearTimeout(_clickTimer);

    _clickTimer = setTimeout(() => {
        if (_clickCount === 1) {
            // --- SINGLE CLICK: Toggle UI ---
            const isNowHidden = vaultNavBarUI.filterSection.classList.toggle('hidden');
            vaultNavBarUI.breadcrumbs.classList.toggle('hidden');

            if (!isNowHidden) {
                setTimeout(() => vaultNavBarUI.filterInput.focus(), 10);
                _startAutoHideTimer(); // Start 5s countdown
            } else {
                _stopAutoHideTimer();
            }

        } else if (_clickCount === 2) {
            // --- DOUBLE CLICK: Advanced Modal ---
            log("filter.filterToggle", "Double Click: Opening Advanced Modal...");
            showAdvancedSearchModal(getActiveVaultData());
        } else if (_clickCount >= 3) {
            // --- TRIPLE CLICK: Full Reset ---
            log("filter.filterToggle", "Triple Click: Clearing search and resetting UI");
            _resetAdvancedSettings();
            _resetFilter();
        }

        _clickCount = 0;
    }, 250);
}

function _onFilterInput(e) {
    const query = e.target.value;
    const s = ADVANCED_FILTER_STATE;

    // Reset the 5s timer every time the user types
    _startAutoHideTimer();

    // Turn green if text is present OR an advanced filter is active
    const isAdvanced = (s.dateType !== "" || s.attachment !== "");
    if (query.trim().length > 0 || isAdvanced) {
        vaultNavBarUI.mainSection.classList.add('filter-mode-active');
    } else {
        vaultNavBarUI.mainSection.classList.remove('filter-mode-active');
    }

    handleSearchInput(query, isAdvanced);
}

function _resetFilter() {
    vaultNavBarUI.filterInput.clear();
    vaultNavBarUI.mainSection.classList.remove('filter-mode-active');
    vaultNavBarUI.filterSection.classList.add('hidden');
    vaultNavBarUI.breadcrumbs.classList.remove('hidden');

    handleSearchInput("");
}

function _resetAdvancedSettings() {
    ADVANCED_FILTER_STATE.active = false;
    ADVANCED_FILTER_STATE.searchIn = "";
    ADVANCED_FILTER_STATE.attachment = "";
    ADVANCED_FILTER_STATE.caseSensitive = false;
    ADVANCED_FILTER_STATE.tokenLogic = "contains";
    ADVANCED_FILTER_STATE.dateType = "";
    ADVANCED_FILTER_STATE.dateValue = 7;
    ADVANCED_FILTER_STATE.dateUnit = "days";
    updateDateUIState();
}

function updateDateUIState() {
    const dateType = advSearchUI.dateType;
    const dateVal = advSearchUI.dateVal;
    const dateUnit = advSearchUI.dateUnit;

    // If value is empty string (""), it's 'Off'
    const isOff = (dateType.value === "");

    // Explicitly set the boolean
    dateVal.disabled = isOff;
    dateUnit.disabled = isOff;

    // Visually show it's disabled
    dateVal.style.opacity = isOff ? "0.4" : "1";
    dateUnit.style.opacity = isOff ? "0.4" : "1";
    dateVal.style.backgroundColor = isOff ? "#f0f0f0" : "#fff";
}

function _applyAdvancedSearch() {
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
function _getUniqueFieldLabels(vaultData) {
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
 * HELPER: The logic core that replaces .includes()
 */
function _smartMatch(target, query, settings) {
    if (!target) return false;

    const qRaw = query.trim();
    if (!qRaw) return false;

    // Standardize Case
    let t = settings.caseSensitive ? String(target) : String(target).toLowerCase();
    let q = settings.caseSensitive ? String(qRaw) : String(qRaw).toLowerCase();

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

function _cycleSort() {
    SORT_STATE.mode = (SORT_STATE.mode + 1) % 4;

    // Update the button icon
    vaultNavBarUI.sortToggle.setText(SORT_STATE.icons[SORT_STATE.mode]);

    log("search-and-sort._cycleSort", `Switched to: ${SORT_STATE.labels[SORT_STATE.mode]}`);

    // Re-trigger search to force a re-render with the new sort
    //handleSearchInput(vaultNavBarUI.filterInput.value);
    refreshVault();
}

// TOGGLE & MULTI-CLICK LOGIC
vaultNavBarUI.filterToggle.onClick(_handleFilterToggleClick);

// INPUT & DEBOUNCE
vaultNavBarUI.filterInput.oninput = (e) => _onFilterInput(e);

// Initialize sort cycler
vaultNavBarUI.sortToggle.onClick(_cycleSort);
vaultNavBarUI.sortToggle.setText(SORT_STATE.icons[SORT_STATE.mode]);
