// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Adwarden

function abortCurrentInlineScript(chain, needle) {
    if ( typeof chain !== 'string' || chain === '' ) { return; }
    var owner = window;
    var parts = chain.split('.');
    var prop = parts.pop();
    for ( var i = 0; i < parts.length; i++ ) {
        owner = owner[parts[i]];
        if ( owner === undefined || owner === null ) { return; }
        if ( typeof owner !== 'object' && typeof owner !== 'function' ) { return; }
    }
    var reNeedle = null;
    if ( needle !== undefined && needle !== '' ) {
        try { reNeedle = new RegExp(needle); } catch ( e ) { reNeedle = null; }
    }
    var rid = Math.random().toString(36).slice(2);
    var thisScript = document.currentScript;
    var desc = Object.getOwnPropertyDescriptor(owner, prop);
    var getter = desc && desc.get;
    var setter = desc && desc.set;
    var value = desc ? desc.value : owner[prop];
    var validate = function () {
        var script = document.currentScript;
        if ( script instanceof HTMLScriptElement === false ) { return; }
        if ( script === thisScript || script.src !== '' ) { return; }
        if ( reNeedle !== null && reNeedle.test(script.textContent) === false ) { return; }
        throw new ReferenceError(rid);
    };
    try {
        Object.defineProperty(owner, prop, {
            configurable: true,
            get: function () { validate(); return getter ? getter.call(owner) : value; },
            set: function (v) { validate(); if ( setter ) { setter.call(owner, v); } else { value = v; } }
        });
    } catch ( e ) {}
}
