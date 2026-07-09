# Built-in scriptlet pack

First-party, **MIT-licensed** reimplementations of the highest-value ad-filter
scriptlets, shipped as `app/src/main/assets/scriptlets_builtin.json` and injected
by the P4 HTTP rewriter when "Run scriptlets" is on. They match the uBO/AdGuard
scriptlet **names/aliases** so `##+js(set-constant, …)` rules in EasyList/AdGuard
resolve out of the box.

We deliberately do **not** bundle the GPL uBO/AdGuard scriptlet libraries; users
who want the full set can point the (runtime-downloaded) scriptlet-pack URL at a
compatible `adblock`-crate resource JSON, which overrides this built-in pack.

Included: `set-constant` (`set`), `abort-on-property-read` (`aopr`),
`abort-current-inline-script` (`acis`), `noop`.

Sources live in `src/`. Regenerate the asset after editing:

```
python3 scriptlets/build.py
```

## License

Copyright (c) Adwarden. Released under the MIT License.
