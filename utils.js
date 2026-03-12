
import { G } from './global.js';
import { log, trace, debug, info, warn, error } from './log.js';

export function deepFreeze(obj) {
    // 1. Retrieve the property names defined on obj
    const propNames = Object.getOwnPropertyNames(obj);

    // 2. Freeze properties before freezing self
    for (const name of propNames) {
        const value = obj[name];

        // 3. If value is an object, freeze it recursively
        if (value && typeof value === "object") {
            deepFreeze(value);
        }
    }

    return Object.freeze(obj);
}

export function format(json) {
    // Determine indentation: undefined (minified), other wise indent by 2 spaces
    return JSON.stringify(json, null, (G.settings?.minifyJson ? undefined : 2));
}

export function dumpLocalStorageForDebug() {
    trace("U.dumpLocalStorageForDebug", "LocalStorage Dump");

    if (!localStorage.length) {
        trace("U.dumpLocalStorageForDebug", "localStorage is empty");
        return;
    }

    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);

        trace("U.dumpLocalStorageForDebug", `------ Key: ${key}`);
        try {
            trace("U.dumpLocalStorageForDebug", "Parsed:", JSON.parse(value));
        } catch {
            trace("U.dumpLocalStorageForDebug", "Raw:", value);
        }
        trace("U.dumpLocalStorageForDebug", "-------------");
    }
}
