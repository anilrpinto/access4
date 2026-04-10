import { AU, U, log, trace, debug, isDebugEnabled, info, warn, error } from '@/shared/exports.js';

import { vaultRawDataUI  } from '@/ui/loader.js';
import { swapVisibility } from '@/ui/uihelper.js';

let isTreeView = false;
let lastDataFingerprint = "";

async function load(data, masked, onClose) {
    log("rawDataViewer.load", "Loading raw vault data");

    vaultRawDataUI.closeBtn.onClick((e) => doCloseViewerClick(data, onClose));
    vaultRawDataUI.toggleViewBtn.onClick((e) => doToggleViewerClick());

    const currentFingerprint = JSON.stringify(data);

    // Only re-render the tree if the data has actually changed
    if (currentFingerprint !== lastDataFingerprint) {
        log("rawDataViewer.load", "Data changed or first load, rendering tree...");
        renderJSONTree(data, masked);
        lastDataFingerprint = currentFingerprint;
    } else {
        log("rawDataViewer.load", "Data unchanged, preserving tree state.");
    }

    vaultRawDataUI.textContent.setText(U.format(data));
    vaultRawDataUI.toggleViewBtn.setText(isTreeView ? 'Text View' : 'Tree View');
}

async function unload() {
    log("rawDataViewer.unload", "called");
}

function doCloseViewerClick(data, onClose) {

    log("rawDataViewer.doCloseViewerClick", "called");

    if (AU.isGenesisUser()) {
        const activeData = JSON.parse(vaultRawDataUI.textContent.value);
        if (isDebugEnabled())
            debug("rawDataViewer.doCloseViewerClick", `prevLen:${JSON.stringify(data).length} currLen:${JSON.stringify(activeData).length}`);

        if (onClose)
            onClose(activeData);

    }
    window.ScreenManager.goHome();
}

function doToggleViewerClick() {
    isTreeView = !isTreeView;

    if (isTreeView) {
        swapVisibility(vaultRawDataUI.textContent, vaultRawDataUI.treeContent);
        vaultRawDataUI.toggleViewBtn.setText('Text View');
    } else {
        swapVisibility(vaultRawDataUI.treeContent, vaultRawDataUI.textContent);
        vaultRawDataUI.toggleViewBtn.setText('Tree View');
    }
}

function renderJSONTree(data, masked) {

    log("rawDataViewer.renderJSONTree", "masked:", masked);

    vaultRawDataUI.treeContent.innerHTML = "";
    // Start recursion at depth 0
    vaultRawDataUI.treeContent.appendChild(createTreeBranch("root", data, 0, masked));
}

function createTreeBranch(key, value, depth = 0, masked = true) {
    const li = document.createElement("li");

    if (typeof value === 'object' && value !== null) {
        const isArray = Array.isArray(value);
        const childKeys = Object.keys(value);

        // Peek to see if this is a secure object
        const isSecureField = value.type === 'secure';

        const isNumericIndex = !isNaN(key) && !isNaN(parseFloat(key));
        let displayKey = isNumericIndex ? (value.name || value.label || value.key || key) : key;

        const label = document.createElement("span");
        label.className = "caret";

        const shouldExpand = depth < 2 && key !== 'meta' && childKeys.length > 0;
        if (shouldExpand) label.classList.add("caret-down");

        label.innerHTML = `<span class="json-key">${displayKey}</span> ${isArray ? `<span class="json-meta">${childKeys.length} items</span>` : ''}`;

        if (childKeys.length > 0) {
            const ul = document.createElement("ul");
            ul.className = "nested";
            if (shouldExpand) ul.classList.add("active");

            childKeys.forEach(childKey => {
                if (isNumericIndex && ['name', 'label', 'key'].includes(childKey)) return;

                // --- BRIDGE TO SESSION STATE ---
                let childValue = value[childKey];
                if (isSecureField && childKey === 'val' && masked) {
                    childValue = "••••••••"; // Use a distinct mask
                }

                ul.appendChild(createTreeBranch(childKey, childValue, depth + 1, masked) );
            });

            label.onclick = (e) => {
                e.stopPropagation();
                label.classList.toggle("caret-down");
                ul.classList.toggle("active");
            };

            li.appendChild(label);
            li.appendChild(ul);
        } else {
            label.classList.remove("caret");
            label.innerHTML = `<span class="json-key">${displayKey}</span> <span class="json-meta">(empty)</span>`;
            li.appendChild(label);
        }
    } else {
        // Handle Leaf Nodes
        const isMasked = value === "••••••••";
        const valClass = isMasked ? "json-secure-masked" : `json-${typeof value}`;
        li.innerHTML = `<span class="json-key">${key}</span>: <span class="${valClass}">${value}</span>`;
    }
    return li;
}

/**
 * EXPORTED FUNCTIONS
 */
export async function showRawDataUI(stateProvider, onClose) {
    log("rawDataViewer.showRawDataUI", "called");

    const screenKey = window.ScreenManager.RAW_DATA_SCREENKEY;
    window.ScreenManager.register(screenKey, vaultRawDataUI.mainSection, {
        onShow: () => {
            const { data, isMasked } = stateProvider();
            load(data, isMasked, onClose)
        },
        onHide: unload
    });
    window.ScreenManager.switchView(screenKey);
}

/**
 * Force the tree to rebuild (used by vault.js toggle)
 */
export function refreshRawDataTree(data, masked) {
    if (vaultRawDataUI.mainSection?.isVisible()) {
        log("rawDataViewer.refreshRawDataTree", "Viewer is visible, refreshing tree.");
        renderJSONTree(data, masked);
    } else {
        log("rawDataViewer.refreshRawDataTree", "Viewer hidden, skipping refresh.");
        lastDataFingerprint = "";
    }
}
