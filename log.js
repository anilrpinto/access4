"use strict";

import { logEl } from './ui.js';

export const ERROR = 0;
export const WARN = 1;
export const INFO = 2;
export const DEBUG = 3;
export const TRACE = 4;

let _level = DEBUG;
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

function _log(level, icon, TAG, msg, ...args) {
    //TODO: Add filter on TAG
    if (level > _level || (_filter.length && !_filter.includes(level)))
        return;

    const now = new Date();
    const ts = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}.${now.getMilliseconds().toString().padStart(3, '0')}`;

    const data = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : arg).join(' ');

    const message = `${ts} ${icon}[${(TAG??"").padStart(30)}] ${msg} ${data}`;
    console.log(message);

    try {
        logEl.textContent += message + "\n";
    } catch (err) {
        console.warn("logEl not yet initialized!");
    }
}

function _isLogLevelEnabled(level) {
    return _level === level;
}

export function isTraceEnabled() {
    return _isLogLevelEnabled(TRACE);
}

export function isLogEnabled() {
    return isDebugEnabled();
}

export function isDebugEnabled() {
    return _isLogLevelEnabled(DEBUG);
}

export function isInfoEnabled() {
    return _isLogLevelEnabled(INFO);
}

export function isWarnEnabled() {
    return _isLogLevelEnabled(WARN);
}

export function isErrorEnabled() {
    return _isLogLevelEnabled(ERROR);
}

export function log(TAG, message, ...args) {
    debug(TAG, message, ...args);
}

export function debug(TAG, message, ...args) {
    _log(DEBUG, "💡", TAG, message, ...args);
}

export function info(TAG, message, ...args) {
    _log(INFO, "✅", TAG, message, ...args);
}

export function warn(TAG, message, ...args) {
    _log(WARN, "⚠️", TAG, message, ...args);
}

export function error(TAG, message, ...args) {
    _log(ERROR, "❌", TAG, message, ...args);
}

export function trace(TAG, message, ...args) {
    _log(TRACE, "🔍", TAG, message, ...args);
}
