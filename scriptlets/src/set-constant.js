// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Adwarden

function setConstant(chain, cvalue) {
    if ( typeof chain !== 'string' || chain === '' ) { return; }
    var value;
    if ( cvalue === 'undefined' ) { value = undefined; }
    else if ( cvalue === 'false' ) { value = false; }
    else if ( cvalue === 'true' ) { value = true; }
    else if ( cvalue === 'null' ) { value = null; }
    else if ( cvalue === 'noopFunc' ) { value = function () {}; }
    else if ( cvalue === 'trueFunc' ) { value = function () { return true; }; }
    else if ( cvalue === 'falseFunc' ) { value = function () { return false; }; }
    else if ( cvalue === "''" ) { value = ''; }
    else if ( cvalue === 'emptyArr' ) { value = []; }
    else if ( cvalue === 'emptyObj' ) { value = {}; }
    else if ( /^-?\d+$/.test(cvalue) ) {
        value = parseInt(cvalue, 10);
        if ( isNaN(value) || Math.abs(value) > 0x7FFF ) { return; }
    } else { return; }
    var owner = window;
    var parts = chain.split('.');
    var prop = parts.pop();
    for ( var i = 0; i < parts.length; i++ ) {
        owner = owner[parts[i]];
        if ( owner === undefined || owner === null ) { return; }
        if ( typeof owner !== 'object' && typeof owner !== 'function' ) { return; }
    }
    try {
        Object.defineProperty(owner, prop, {
            configurable: true,
            get: function () { return value; },
            set: function () {}
        });
    } catch ( e ) {}
}
