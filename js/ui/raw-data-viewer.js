import { AU, U, log, trace, debug, isDebugEnabled, info, warn, error } from '@/shared/exports.js';
import { vaultRawDataUI  } from '@/ui/loader.js';
import { swapVisibility } from '@/ui/uihelper.js';

let _isTreeView = false;
let _lastDataFingerprint = "";

export async function showRawDataUI(stateProvider, onClose) {
    log("rawDataViewer.showRawDataUI", "called");

    const screenKey = window.ScreenManager.RAW_DATA_SCREENKEY;
    window.ScreenManager.register(screenKey, vaultRawDataUI.mainSection, {
        onShow: () => {
            const { data, isMasked } = stateProvider();
            _load(data, isMasked, onClose)
        },
        onHide: _unload
    });
    window.ScreenManager.switchView(screenKey);
}

/**
 * Force the tree to rebuild (used by vault.js toggle)
 */
export function refreshRawDataTree(data, masked) {
    if (vaultRawDataUI.mainSection?.isVisible()) {
        log("rawDataViewer.refreshRawDataTree", "Viewer is visible, refreshing tree.");
        _renderJSONTree(data, masked);
    } else {
        log("rawDataViewer.refreshRawDataTree", "Viewer hidden, skipping refresh.");
        _lastDataFingerprint = "";
    }
}

/** INTERNAL FUNCTIONS **/
async function _load(data, masked, onClose) {
    log("rawDataViewer._load", "Loading raw vault data");

    vaultRawDataUI.closeBtn.onClick((e) => _doCloseViewerClick(data, onClose));
    vaultRawDataUI.toggleViewBtn.onClick((e) => _doToggleViewerClick());

    const currentFingerprint = JSON.stringify(data);

    // Only re-render the tree if the data has actually changed
    if (currentFingerprint !== _lastDataFingerprint) {
        log("rawDataViewer._load", "Data changed or first _load, rendering tree...");
        _renderJSONTree(data, masked);
        _lastDataFingerprint = currentFingerprint;
    } else {
        log("rawDataViewer._load", "Data unchanged, preserving tree state.");
    }

    vaultRawDataUI.textContent.setText(U.format(data));
    vaultRawDataUI.toggleViewBtn.setText(_isTreeView ? 'Text View' : 'Tree View');
}

async function _unload() {
    log("rawDataViewer._unload", "called");
}

function _doCloseViewerClick(data, onClose) {

    log("rawDataViewer._doCloseViewerClick", "called");

    if (AU.isGenesisUser()) {
        const activeData = JSON.parse(vaultRawDataUI.textContent.value);
        if (isDebugEnabled())
            debug("rawDataViewer._doCloseViewerClick", `prevLen:${JSON.stringify(data).length} currLen:${JSON.stringify(activeData).length}`);

        if (onClose)
            onClose(activeData);

    }
    window.ScreenManager.goHome();
}

function _doToggleViewerClick() {
    _isTreeView = !_isTreeView;

    if (_isTreeView) {
        swapVisibility(vaultRawDataUI.textContent, vaultRawDataUI.treeContent);
        vaultRawDataUI.toggleViewBtn.setText('Text View');
    } else {
        swapVisibility(vaultRawDataUI.treeContent, vaultRawDataUI.textContent);
        vaultRawDataUI.toggleViewBtn.setText('Tree View');
    }
}

function _renderJSONTree(data, masked) {

    log("rawDataViewer._renderJSONTree", "masked:", masked);

    vaultRawDataUI.treeContent.innerHTML = "";
    // Start recursion at depth 0
    vaultRawDataUI.treeContent.appendChild(_createTreeBranch("root", data, 0, masked));
}

function _createTreeBranch(key, value, depth = 0, masked = true) {
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

                ul.appendChild(_createTreeBranch(childKey, childValue, depth + 1, masked) );
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
