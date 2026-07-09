// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Adwarden

function abortOnPropertyRead(chain) {
    if ( typeof chain !== 'string' || chain === '' ) { return; }
    var rid = Math.random().toString(36).slice(2);
    var abort = function () { throw new ReferenceError(rid); };
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
            get: abort,
            set: function () {}
        });
    } catch ( e ) {}
}
