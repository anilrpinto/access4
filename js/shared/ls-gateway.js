import { G } from '@/shared/global.js';
import { log, trace, debug, info, warn, error } from '@/shared/log.js';

let cachedPrefix = null;

const keyPrefix = () => {
    // If we've already built it and the email matches, return it
    if (cachedPrefix && cachedPrefix.includes(G.userEmail.toLowerCase())) {
        return cachedPrefix;
    }

    // Otherwise, initialize or update it
    if (!G.userEmail) {
        // Fallback or warning if called too early
        warn("LS.getKeyPrefix", "LS Gateway: Attempted access before G.userEmail was set.");
        throw new Error("No authorized email found (in G.userEmail).");
    }

    const pathParts = window.location.pathname.split('/');
    const envName = pathParts[pathParts.length - 2] || 'default';

    cachedPrefix = `access4::${envName}::${G.userEmail}::`.toLowerCase();
    return cachedPrefix;
};

export const LS = {
    set: (key, value) => {
        localStorage.setItem(`${keyPrefix()}${key}`, value);
    },
    get: (key) => {
        return localStorage.getItem(`${keyPrefix()}${key}`);
    },
    remove: (key) => {
        localStorage.removeItem(`${keyPrefix()}${key}`);
    },
    clearNamespace: () => {
        const prefix = keyPrefix();
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith(prefix)) {
                localStorage.removeItem(key);
            }
        });
    }
};