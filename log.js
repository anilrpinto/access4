"use strict";

import { logEl } from './ui.js';

export const ERROR = 0;
export const WARN = 1;
export const INFO = 2;
export const DEBUG = 3;
export const TRACE = 4;

let _level = TRACE;
const _filter = [];

// Mapping levels to colors and labels
const LABELS = ['ERROR', 'WARN ', 'INFO ', 'DEBUG', 'TRACE'];

export function setLogLevel(level) {
    if (level)
        _level = level;
}

export function onlyLogLevels(...levels) {
    if (levels) {
        _filter.length = 0;
        _filter.push(...levels);
    }
}

function _log(level, msg, ...args) {
    if (level > _level || (_filter.length && !_filter.includes(level)))
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
    _log(ERROR, "❌" + message, ...args);
}

export function warn(message, ...args) {
    _log(WARN, "⚠️" + message, ...args);
}

export function info(message, ...args) {
    _log(INFO, "✅" + message, ...args);
}

export function debug(message, ...args) {
    _log(DEBUG, message, ...args);
}

export function trace(message, ...args) {
    _log(TRACE, "🔍" + message, ...args);
}

export function log(message, ...args) {
    debug(message, ...args);
}