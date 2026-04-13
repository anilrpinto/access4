import { G } from '@/shared/global.js';
import { log, trace, debug, info, warn, error } from '@/shared/log.js';

let cachedPrefix = null;

export const LS = {
    set: (key, value) => {
        localStorage.setItem(`${_keyPrefix()}${key}`, value);
    },
    get: (key) => {
        return localStorage.getItem(`${_keyPrefix()}${key}`);
    },
    remove: (key) => {
        localStorage.removeItem(`${_keyPrefix()}${key}`);
    },
    clearNamespace: () => {
        const prefix = _keyPrefix();
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith(prefix)) {
                localStorage.removeItem(key);
            }
        });
    }
};

/** INTERNAL FUNCTIONS **/
const _keyPrefix = () => {
    if (cachedPrefix && cachedPrefix.includes(G.userEmail.toLowerCase())) {
        return cachedPrefix;
    }

    if (!G.userEmail) {
        warn("LS.keyPrefix", "LS Gateway: Attempted access before G.userEmail was set.");
        throw new Error("No authorized email found (in G.userEmail).");
    }

    const pathParts = window.location.pathname.split('/');
    const envName = pathParts[pathParts.length - 2] || 'default';

    cachedPrefix = `access4::${envName}::${G.userEmail}::`.toLowerCase();
    return cachedPrefix;
};
