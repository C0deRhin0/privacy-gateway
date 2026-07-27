# Examples

`context-map.example.json` is a fictional schema example for the optional contextual
pseudonymization loader. It is safe to copy as a starting point, but it is **not** a
deployment configuration.

Copy it to a private path outside the repository, replace every fictional alias and
identifier with local values, then set `PRIVACY_GATEWAY_CONTEXT_MAP_PATH` to that
private file. Contextual maps can reveal sensitive relationships even without API
keys, so never commit, publish, send to an upstream provider, or use real entities in
this directory.

The loader expects a `routes` object. Each absolute route contains `BASE`, `STANDARD`,
and/or `STRICT` lists. Modes are cumulative: `STANDARD` includes `BASE`, and `STRICT`
includes both lower modes. Entries require `entity_type`, `canonical_id`, and one or
more `aliases`; `match` may be `whole_word` (the default) or `exact`. `nearby_context`
and `context_distance` optionally constrain a match. Use `allow_canonical_fallback`
only with a distinct `provider_fallback_token`.
