import { G } from '@/shared/global.js';
import { log, trace, debug, info, warn, error } from '@/shared/log.js';

export const delay = (ms) => new Promise(res => setTimeout(res, ms));

export function format(json) {
    // Determine indentation: undefined (minified), otherwise indent by 2 spaces
    return JSON.stringify(json, null, (G.settings?.minifyJson ? undefined : 2));
}

export function getCurrentTime() {
    return new Date().toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    }).toLowerCase();
}

export function asLocalTime(utc) {
    return new Date(utc).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    }).toLowerCase();
}

/**
 * Converts an ISO string (UTC) to a local, readable format.
 * Example: "2026-03-27T19:14:52Z" -> "3/27/2026, 12:14:52 PM"
 */
export function formatLocalTime(isoString) {
    if (!isoString) return "N/A";
    try {
        const date = new Date(isoString);
        return date.toLocaleString(); // Uses the browser's local timezone and format
    } catch (e) {
        return isoString;
    }
}

/**
 * Returns a "clean" local ISO-like string without the 'Z' for logging.
 */
export function getLocalTimestamp() {
    const now = new Date();
    const offset = now.getTimezoneOffset() * 60000;
    return new Date(now - offset).toISOString().slice(0, -1).replace('T', ' ');
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