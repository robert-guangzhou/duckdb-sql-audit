# duckdb-sql-audit

Full-statement SQL auditing for DuckDB 2.0 — a loadable extension with a
Rust core: tamper-evident hash-chained local records + NATS publishing, with
quack-server client attribution (connection records + per-statement
`conn_id` correlation).

## What it does

- **Captures every statement** (DDL/DML/SELECT/SET/TX/EXPLAIN/PRAGMA) via the
  `parser_override` hook — pass-through, zero semantic change, no recursion.
- **Hash chain**: every record (STMT/CONN/SYS) is a link —
  `entry_hmac = HMAC-SHA256(key, seq|ts|type|principal|verdict|hash_field|prev_hash)`.
  `sql_audit_verify()` walks the chain and reports the first bad seq;
  splicing (delete-a-record + rewire `prev_hash`) is detected because
  `prev_hash` is inside the HMAC.
- **Connection records** (independent C-series, joined to statements only by
  `conn_id`): open/reject event, verdict, token fingerprint (sha256 of the
  client credential), authoritative rejection reason (via quack_oauth's
  audit log), self-reported `sub` (256-byte cap + full hash) and `azp`.
- **Local sink**: append-only JSONL, size-based rotation, retention
  (`prune`/`halt`), 0700/0600 permissions, torn-tail recovery on reopen.
- **NATS sink**: `local`/`nats`/`both`/`off` modes, 5s reconnect cooldown
  (fail-fast, never stalls the writer), transparent segmentation of oversize
  payloads (`SQLASEG1` binary frames, server `max_payload` respected),
  optional per-publish PING/PONG confirmation, periodic chain-head anchors
  on `<subject>.anchor`.
- **Multi-process safe**: writers take a per-directory flock and rebase onto
  the disk tail — concurrent sessions on one audit dir keep the chain linear.
- **quack integration**: takes over `quack_authentication_function` /
  `quack_authorization_function` at LOAD (previous functions become
  delegates with faithful semantics — authn deny / authz rewrite / errors
  propagate). Auto-rechain: if the hooks are overwritten (e.g. following the
  quack_oauth README), the next health poll re-takes them, adopts the new
  function as delegate and writes a `rehook` SYS event into the chain.

## Build

Requires: DuckDB extension build tree (`extension-ci-tools` + `duckdb/`
submodule — see the [extension template](https://github.com/duckdb/extension-template)),
Rust (cargo, stable).

```bash
cd rust && cargo build --release && cp target/release/libsql_audit.a ../src/
mkdir -p build && cd build
cmake .. -DGENERATE_EXTENSION=true -DCMAKE_BUILD_TYPE=Release
make -j
# → build/release/extension/sql_audit/sql_audit.duckdb_extension
```

## Usage

```sql
SET allow_unsigned_extensions=true;
LOAD '/path/to/sql_audit.duckdb_extension';
-- STRICT parser mode + quack hook takeover happen automatically at LOAD.

SELECT * FROM sql_audit_health();   -- counters, hook state, delegates
SELECT * FROM sql_audit_verify();   -- chain check: ok, first_bad_seq,
                                    -- total, chain_head, window_start_seq
SELECT sql_audit_rehook();          -- manual hook recovery
```

### Settings

| Setting | Default | Meaning |
|---|---|---|
| `sql_audit_path` | `~/.duckdb/sql_audit` | audit directory (JSONL + chain key) |
| `sql_audit_key_file` | *(empty)* | externalized chain key (different mount/vault); runtime rotation not supported |
| `sql_audit_max_file_mb` | 64 | rotation size |
| `sql_audit_retention_files` | 32 | max audit files |
| `sql_audit_retention_policy` | `prune` | `prune` (delete oldest) or `halt` (stop writing, SQL continues) |
| `sql_audit_disk_free_pct` | 5 | stop writing when disk free % drops below this (0 = disabled; releases halt when set to 0) |
| `sql_audit_mode` | `local` | `local` / `nats` / `both` / `off` |
| `sql_audit_nats_url` | *(empty)* | e.g. `nats://host:4222` |
| `sql_audit_nats_subject` | `sqlaudit` | record subject; anchors on `<subject>.anchor` |
| `sql_audit_nats_secret_name` | *(empty)* | name of a `sql_audit_nats` SECRET with credentials (falls back to bare URL) |
| `sql_audit_nats_confirm` | false | PING/PONG ack per publish |
| `sql_audit_auto_hook` | true | auto re-take quack hooks when overwritten |

### NATS authentication (SECRET)

```sql
-- Create credentials (nats_rw-compatible six-param surface, pick ONE auth method)
CREATE SECRET my_nats (
    TYPE sql_audit_nats,
    URL 'nats://localhost:4222',
    TOKEN 'my-token'              -- or: USER 'alice', PASSWORD 's3cret'
                                 -- or: NKEY 'SU...' (seed)
                                 -- or: CREDS '/path/to/file.creds' (JWT + seed)
);

-- Apply the secret
SET sql_audit_nats_secret_name = 'my_nats';
SET sql_audit_mode = 'both';
```

### Record schema (v5)

Common chain header `E`-series on every record: `seq, schema_ver(=5), ts_ms,
record_type(STMT|CONN|SYS), prev_hash, entry_hmac, principal, verdict`.
Payloads: STMT → `query_sha256/query_len/query` (+`conn_id` when attributed);
CONN → `conn_id, event, verdict, token_fp, reason, sub, sub_truncated,
sub_sha256, azp`; SYS → `event_type, detail, detail_sha256`.

## tools/sql_audit_sub.py

Subscriber-side companion: subscribes to records + anchors, reassembles
`SQLASEG1` segments (5s incompleteness reporting), optionally re-verifies
every record HMAC (`--keyfile`), and `--reconcile <audit_dir>` compares the
highest seq received vs on disk — cross-end detection of tail loss that a
writer cannot see locally (power-loss torn writes).

## Tests

- `tests/comprehensive_final.py` — 64 cases: capture/regression, chain
  attacks (field tamper / key swap / splice), rotation & retention, halt
  rollback, NATS modes & outage cooldown, attribution, ACL/gatekeeper/
  quack co-existence, auto-rechain, multi-process (sequential + concurrent),
  crash/oversize, subscriber e2e, LOW-fix regressions.
- `tests/p4_integration.py` — 26 cases + 7 documented skips against a real
  Keycloak realm: oauth delegation semantics, rechain per the quack_oauth
  README, acl order matrix, gatekeeper co-load, full-stack scenarios,
  C-series field assertions (authoritative reasons, sub cap).

## Known boundaries (documented, by design)

- A root attacker who can read the chain key can recompute the whole chain —
  mitigate by externalizing the key (`sql_audit_key_file`) and relying on
  NATS anchors as cross-end evidence.
- A power-loss-torn **last** record is not locally detectable (seq reuse is
  legitimate healing); cross-end detection via `--reconcile`.
- NATS PUB is fire-and-forget unless `sql_audit_nats_confirm=true`.
- Truncated `sub` values cannot be hash-reverified (original text is not
  stored); the stored prefix is byte-budgeted to ≤256B.
- C08–C12 (server_uri / client ip / host / version / platform) require
  upstream quack callback changes; recorded as null today.
