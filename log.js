"use strict";

import { logEl } from './ui.js';

export const DEBUG = 3;
export const INFO = 2;
export const WARN = 1;
export const ERROR = 0;

let _level = DEBUG;

// Mapping levels to colors and labels
const LABELS = ['ERROR', 'WARN ', 'INFO ', 'DEBUG'];

export function setLogLevel(level) {
    if (level)
        _level = level;
}

function _log(level, msg, ...args) {
    if (level > _level)
        return;

    const now = new Date();
    const ts = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}.${now.getMilliseconds().toString().padStart(3, '0')}`;

    const data = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : arg).join(' ');

    const message = `${ts} |${LABELS[level]}| ${msg} ${data}`;
    console.log(message);

    try {
        logEl.textContent += message + "\n";
    } catch (err) {
        console.warn("logEl not yet initialized!");
    }
}

export function error(message, ...args) {
    _log(ERROR, message, ...args);
}

export function warn(message, ...args) {
    _log(WARN, message, ...args);
}

export function info(message, ...args) {
    _log(INFO, message, ...args);
}


export function debug(message, ...args) {
    _log(DEBUG, message, ...args);
}

export function log(message, ...args) {
    debug(message, ...args);
}