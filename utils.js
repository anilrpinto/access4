"use strict";

import { G } from './global.js';

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

// A safer version for buffers of any size instead of a straight
// btoa(String.fromCharCode(...new Uint8Array(buffer)))
function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

export function format(json) {
    // Determine indentation: undefined (minified), other wise indent by 2 spaces
    return JSON.stringify(json, null, (G.settings?.minifyJson ? undefined : 2));
}