import { G } from '@/shared/global.js';
import { log, trace, debug, info, warn, error } from '@/shared/log.js';

let cachedPrefix = null;

export const LS = {
    set: (key, value, secured) => {
        localStorage.setItem(`${_keyPrefix(secured)}${key}`, value);
    },
    get: (key, secured) => {
        return localStorage.getItem(`${_keyPrefix(secured)}${key}`);
    },
    remove: (key, secured) => {
        localStorage.removeItem(`${_keyPrefix(secured)}${key}`);
    },
    clearNamespace: () => {
        const prefix = _keyPrefix();
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith(prefix)) {
                localStorage.removeItem(key);
            }
        });
    },
    getKeyPrefix: (secured) => _keyPrefix(secured)
};

/** INTERNAL FUNCTIONS **/
const _keyPrefix = (secured = true) => {

    if (secured && cachedPrefix && cachedPrefix.includes(G.userEmail.toLowerCase())) {
        return cachedPrefix;
    }

    if (secured && !G.userEmail) {
        warn("LS.keyPrefix", "LS Gateway: Attempted access before G.userEmail was set.");
        throw new Error("No authorized email found (in G.userEmail).");
    }

    const activeEmail = secured ? G.userEmail : 'last-access';

    const pathParts = window.location.pathname.split('/');
    const envName = pathParts[pathParts.length - 2] || 'default';

    cachedPrefix = `access4::${envName}::${activeEmail}::`.toLowerCase();

    return cachedPrefix;
};
