# Runtime data directory

`python -m detection_toolkit init-db` creates two files here:

- `detection_toolkit.sqlite3`: the demo database, including the rule plans you create.
- `secret_key`: the session-signing key (mode 0600).

Both are local runtime files and are ignored by Git. Delete them, or run
`init-db --reset`, to start over from the bundled demo data.
