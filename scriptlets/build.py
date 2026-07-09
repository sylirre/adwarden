#!/usr/bin/env python3
"""Assemble the first-party scriptlet resource pack (P4-3).

Reads the MIT-licensed scriptlet sources in src/ and emits a JSON array of
`adblock` crate resources (function-style, base64 content) to the app asset
`scriptlets_builtin.json`. adblock-rust looks scriptlets up by `<name>.js`, so
each resource is named accordingly with common uBO/AdGuard aliases.

Regenerate with:  python3 scriptlets/build.py
"""
import base64, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "app", "src", "main", "assets", "scriptlets_builtin.json")

# (source file, canonical .js name, [alias.js ...])
MANIFEST = [
    ("set-constant.js", "set-constant.js", ["set.js"]),
    ("abort-on-property-read.js", "abort-on-property-read.js", ["aopr.js"]),
    ("abort-current-inline-script.js", "abort-current-inline-script.js",
     ["acis.js", "abort-current-script.js"]),
    ("noop.js", "noop.js", ["noopjs"]),
]

def main():
    pack = []
    for src, name, aliases in MANIFEST:
        js = open(os.path.join(HERE, "src", src)).read()
        pack.append({
            "name": name,
            "aliases": aliases,
            "kind": {"mime": "application/javascript"},
            "content": base64.b64encode(js.encode()).decode(),
        })
    with open(OUT, "w") as f:
        json.dump(pack, f, indent=2)
        f.write("\n")
    print(f"wrote {os.path.relpath(OUT, os.path.join(HERE, '..'))}: {len(pack)} resources")

if __name__ == "__main__":
    main()
