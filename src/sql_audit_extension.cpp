#include "sql_audit_ffi.h"
#include "duckdb/main/extension.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/extension_callback_manager.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include <atomic>
#include <cctype>
#include <cstring>
#include <functional>

namespace duckdb {

// Real hook evidence: STRICT option actually set at LOAD, and the number of
// times our parser_override was invoked by DuckDB (proves the hook fires).
static std::atomic<int64_t> g_override_calls{0};
static bool g_strict_set_ok = false;

// === P4-3 + L5: hook takeover / delegation / auto-rechain state ===
// quack invokes hooks via `SELECT <quack_authentication_function>(?,?,?)`
// and `SELECT <quack_authorization_function>(?,?)` (quack_server.cpp:628-660).
// We take over both hooks; the previous function becomes our DELEGATE and
// its semantics pass through unchanged (authn BOOLEAN, authz VARCHAR rewrite).
// State lives in PER-DATABASE extension settings (L5): a pointer-keyed map
// dangled when :memory: databases were freed and their addresses reused —
// settings die with their database, so nothing crosses over.
//   sql_audit_hook_delegate_{authn,authz}: current delegate ("" = pass-through)
//   sql_audit_hook_snapshot_{authn,authz}: last handled hook value
//     == chain name → taken over;  == "" after chain → user unloaded (respected)
static const char *SET_DELEGATE_A = "sql_audit_hook_delegate_authn";
static const char *SET_DELEGATE_Z = "sql_audit_hook_delegate_authz";
static const char *SET_SNAPSHOT_A = "sql_audit_hook_snapshot_authn";
static const char *SET_SNAPSHOT_Z = "sql_audit_hook_snapshot_authz";
static std::atomic<bool> g_auto_hook{true};
static const char *AUTHN_CHAIN = "sql_audit_authn_chain";
static const char *AUTHZ_CHAIN = "sql_audit_authz_chain";

// L4: delegate names are interpolated into `SELECT <name>(?,?)`; only plain
// identifiers are acceptable. A non-identifier value is NOT adopted and the
// hook is NOT re-taken — quack will fail evaluating the bogus name, which
// denies the operation (fail-closed by quack's own semantics).
static bool IsPlainIdentifier(const string &s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!(std::isalnum((unsigned char)c) || c == '_' || c == '.')) return false;
    }
    return true;
}

// Set while inside a chain function: delegate calls go through the SQL
// engine and must not be captured (audit pollution) or re-checked.
static thread_local bool g_in_chain = false;

static string GetQuackSetting(DatabaseInstance &db, const char *name) {
    Value v;
    auto &config = DBConfig::GetConfig(db);
    if (!config.TryGetCurrentSetting(Identifier(name), v)) return "";
    if (v.IsNull()) return "";
    return v.GetValue<string>();
}

// Own internal settings (same per-DB lifetime as quack's)
static string GetOwnStr(DatabaseInstance &db, const char *name) {
    return GetQuackSetting(db, name);
}
static void SetOwnStr(DatabaseInstance &db, const char *name, const string &val) {
    try {
        DBConfig::GetConfig(db).SetOption(name, Value(val));
    } catch (...) {
    }
}

static void AuditSysEvent(const char *event_type, const string &detail) {
    sql_audit_sys_event(event_type, (int64_t)strlen(event_type),
                        detail.c_str(), (int64_t)detail.size());
}

// Try to take over one hook (LOAD time). Persists state in per-DB settings.
static void HookTakeover(DatabaseInstance &db, const char *setting,
                         const char *chain_name, const char *delegate_setting,
                         const char *snapshot_setting, bool *took_over) {
    auto &config = DBConfig::GetConfig(db);
    string current = GetQuackSetting(db, setting);
    if (current == chain_name) {
        SetOwnStr(db, snapshot_setting, chain_name); // already ours
        *took_over = !GetOwnStr(db, delegate_setting).empty() || true;
        return;
    }
    if (!current.empty() && !IsPlainIdentifier(current)) {
        // L4: pre-existing invalid value — leave it, quack fails closed.
        SetOwnStr(db, snapshot_setting, current);
        return;
    }
    string delegate = current; // may be "" (default authn) — still take over
    try {
        config.SetOption(setting, Value(chain_name));
        SetOwnStr(db, delegate_setting, delegate);
        SetOwnStr(db, snapshot_setting, chain_name);
        *took_over = true;
    } catch (...) {
        // quack not loaded / setting absent: remember, stay quiet
        SetOwnStr(db, snapshot_setting, current);
    }
}

// Snapshot check (health poll). All state in per-DB settings:
//   snapshot == chain name  → we own the hook
//   snapshot == "" (after chain) → user unloaded; respected
//   snapshot == current     → quiet
static void CheckAndRechain(DatabaseInstance &db, const char *setting,
                            const char *chain_name, const char *delegate_setting,
                            const char *snapshot_setting) {
    string current = GetQuackSetting(db, setting);
    string snapshot = GetOwnStr(db, snapshot_setting);
    if (current == snapshot) return;         // fast path: nothing changed
    if (current == chain_name) {
        SetOwnStr(db, snapshot_setting, chain_name);
        return;
    }
    if (!g_auto_hook.load()) {               // explicit unload honored
        SetOwnStr(db, snapshot_setting, current);
        return;
    }
    if (current.empty() && snapshot == chain_name) { // user cleared: respect
        SetOwnStr(db, snapshot_setting, "");
        return;
    }
    if (!current.empty() && !IsPlainIdentifier(current)) {
        // L4: rejected adoption; leave the hook as-is — quack evaluating a
        // bogus function name errors out, which denies the operation.
        SetOwnStr(db, snapshot_setting, current); // debounce repeat events
        AuditSysEvent("delegate_rejected", string(setting) +
                      " value is not a plain identifier: " + current);
        return;
    }
    // New function (or empty with quack freshly loaded): adopt as delegate
    // and take the hook back. Debounce (r7): re-setting the SAME function
    // restores the hook silently — only a genuinely different function
    // logs a rehook event.
    bool same_delegate = (current == GetOwnStr(db, delegate_setting));
    SetOwnStr(db, delegate_setting, current);
    try {
        DBConfig::GetConfig(db).SetOption(setting, Value(chain_name));
        SetOwnStr(db, snapshot_setting, chain_name);
        if (!same_delegate) {
            AuditSysEvent("rehook", string(setting) + " -> " + chain_name +
                          " (delegate=" + (current.empty() ? "<none>" : current) + ")");
        }
    } catch (...) {
        // could not re-take (quack absent?); snapshot stays at current
        SetOwnStr(db, snapshot_setting, current);
    }
}

// === Parser Override ===
// - g_in_chain: delegate evaluation inside a chain function is engine work,
//   not a user statement.
// - dispatch filter (L6): ONLY the placeholder form quack actually sends
//   (`SELECT sql_audit_auth{n,z}_chain(?, ?)`) is filtered — it carries no
//   audit information (the attributed record is produced INSIDE the chain
//   function). A user's literal call `SELECT sql_audit_authz_chain('c','q')`
//   is a normal statement and IS audited.
// Hot path: zero heap allocations — the old Lower() copy added ~17us at p99
// (interleaved benchmark, acceptance gate is <5us).
static inline bool DispatchPrefixAt(const char *s, size_t n, size_t pos,
                                    const char *pre, size_t plen) {
    if (pos + plen > n) return false;
    for (size_t i = 0; i < plen; i++) {
        char c = s[pos + i];
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (c != pre[i]) return false;
    }
    return true;
}
static ParserOverrideResult AuditOverride(ParserExtensionInfo *, const string &query, ParserOptions &) {
    g_override_calls.fetch_add(1, std::memory_order_relaxed);
    if (g_in_chain) return ParserOverrideResult();
    const char *s = query.c_str();
    size_t n = query.size();
    size_t lead = 0;
    while (lead < n && (s[lead] == ' ' || s[lead] == '\t' || s[lead] == '\r' || s[lead] == '\n')) lead++;
    if (lead >= n) return ParserOverrideResult();
    static const char kDispatchA[] = "select sql_audit_authn_chain(?, ?";
    static const char kDispatchZ[] = "select sql_audit_authz_chain(?, ?";
    if (DispatchPrefixAt(s, n, lead, kDispatchA, sizeof(kDispatchA) - 1) ||
        DispatchPrefixAt(s, n, lead, kDispatchZ, sizeof(kDispatchZ) - 1)) {
        return ParserOverrideResult();
    }
    sql_audit_capture(query.c_str(), (int64_t)n);
    return ParserOverrideResult();
}

// === P4-3: Authn Chain (delegates to real authn, records connection) ===
static void AuthnChainFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto conn_id = args.GetValue(0, 0).ToString();
    auto auth_string = args.GetValue(1, 0).ToString();
    auto token = args.GetValue(2, 0).ToString();
    string authn_delegate = GetOwnStr(*state.GetContext().db, SET_DELEGATE_A);

    string verdict = "ok";
    bool allowed = true;
    string reason; // C04: authoritative classification (empty if unavailable)
    if (!authn_delegate.empty()) {
        // delegate with faithful semantics (quack evaluates hooks the same way)
        g_in_chain = true;
        try {
            auto &ctx = state.GetContext();
            Connection con(*ctx.db);
            auto res = con.Query(StringUtil::Format("SELECT %s(?, ?, ?)", authn_delegate),
                                 Value(conn_id), Value(auth_string), Value(token));
            if (!res || res->HasError()) {
                allowed = false; // callback error = Denied (quack semantics)
            } else {
                auto chunk = res->Fetch();
                Value v = (chunk && chunk->size() > 0) ? chunk->GetValue(0, 0) : Value();
                if (v.IsNull()) {
                    allowed = false; // Denied(): NULL
                } else if (v.type().id() == LogicalTypeId::BOOLEAN) {
                    allowed = v.GetValue<bool>(); // Denied(): BOOLEAN false
                } else {
                    allowed = true; // quack Denied(): non-bool non-null passes
                }
            }
            // C04: the delegate only returns a boolean — the authoritative
            // reason lives in quack_oauth's own audit log (zero-arg table
            // function). Match our token by token_hash (= sha256(token)[:8],
            // same derivation as our token_fp) to avoid cross-connection
            // ambiguity.
            if (!allowed) {
                try {
                    auto log = con.Query(
                        "SELECT reason FROM quack_oauth_audit_log() WHERE token_hash = "
                        "(SELECT lower(substr(sha256(?)::VARCHAR, 1, 8))) "
                        "ORDER BY timestamp_unix_s DESC LIMIT 1",
                        Value(auth_string));
                    if (log && !log->HasError()) {
                        auto lc = log->Fetch();
                        if (lc && lc->size() > 0) {
                            Value rv = lc->GetValue(0, 0);
                            if (!rv.IsNull()) reason = rv.GetValue<string>();
                        }
                    }
                } catch (...) {
                    // audit log unavailable (non-oauth delegate): Rust falls
                    // back to expired/denied classification
                }
            }
        } catch (std::exception &e) {
            AuditSysEvent("authn_delegate_error", e.what());
            allowed = false; // fail-closed
        }
        g_in_chain = false;
        verdict = allowed ? "ok" : "reject";
    }

    // The fingerprint must cover the CLIENT credential (arg2: auth_string,
    // which is the JWT in quack_oauth deployments) — arg3 is the server PSK
    // and would make every connection's token_fp identical (proven R7).
    sql_audit_conn_open(conn_id.c_str(), (int64_t)conn_id.size(),
                        auth_string.c_str(), (int64_t)auth_string.size(),
                        verdict.c_str(), (int64_t)verdict.size(),
                        reason.c_str(), (int64_t)reason.size());
    if (!allowed) sql_audit_conn_reject_add();
    result.SetValue(0, Value::BOOLEAN(allowed));
}

// === P4-3: Authz Chain (delegates to real authz, captures with connection) ===
static void AuthzChainFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto conn_id = args.GetValue(0, 0).ToString();
    auto query = args.GetValue(1, 0).ToString();
    string authz_delegate = GetOwnStr(*state.GetContext().db, SET_DELEGATE_Z);

    // Capture statement with connection attribution FIRST (audit regardless)
    sql_audit_capture_stmt(conn_id.c_str(), (int64_t)conn_id.size(),
                           query.c_str(), (int64_t)query.size());

    if (authz_delegate.empty()) {
        result.SetValue(0, Value(query)); // pass-through
        return;
    }
    // Delegate with faithful semantics mirroring quack's Denied():
    //   error -> throw (Denied)   NULL -> NULL (Denied)
    //   BOOLEAN false -> NULL (Denied)   BOOLEAN true -> original query
    //   VARCHAR -> rewrite        other types -> original query
    g_in_chain = true;
    Value out = Value(query);
    try {
        auto &ctx = state.GetContext();
        Connection con(*ctx.db);
        auto res = con.Query(StringUtil::Format("SELECT %s(?, ?)", authz_delegate),
                             Value(conn_id), Value(query));
        if (res && !res->HasError()) {
            auto chunk = res->Fetch();
            if (chunk && chunk->size() > 0) {
                Value v = chunk->GetValue(0, 0);
                if (v.IsNull()) {
                    out = Value(); // NULL return = deny (quack Denied())
                } else if (v.type().id() == LogicalTypeId::BOOLEAN) {
                    if (!v.GetValue<bool>()) {
                        out = Value(); // FALSE = deny
                    } // TRUE: keep original query
                } else if (v.type().id() == LogicalTypeId::VARCHAR) {
                    out = v; // rewrite
                }
            }
        } else {
            g_in_chain = false;
            throw InternalException(res ? res->GetError() : "authz delegate produced no result");
        }
    } catch (std::exception &e) {
        AuditSysEvent("authz_delegate_error", string(authz_delegate) + ": " + e.what());
        g_in_chain = false;
        throw; // faithful: a failing authz delegate fails the statement
    }
    g_in_chain = false;
    result.SetValue(0, out);
}

// === Health Table Function (now 11 columns) ===
struct HealthState : GlobalTableFunctionState { bool done = false; };
static unique_ptr<FunctionData> HealthBind(ClientContext &, TableFunctionBindInput &,
                                            vector<LogicalType> &types, vector<Identifier> &names) {
    names.push_back("captured");    types.push_back(LogicalType::BIGINT);
    names.push_back("dropped");     types.push_back(LogicalType::BIGINT);
    names.push_back("pending");     types.push_back(LogicalType::BIGINT);
    names.push_back("records");     types.push_back(LogicalType::BIGINT);
    names.push_back("files");       types.push_back(LogicalType::BIGINT);
    names.push_back("halted");      types.push_back(LogicalType::BOOLEAN);
    names.push_back("nats_pub");    types.push_back(LogicalType::BIGINT);
    names.push_back("nats_err");    types.push_back(LogicalType::BIGINT);
    names.push_back("conns");       types.push_back(LogicalType::BIGINT);
    names.push_back("conn_rejects");types.push_back(LogicalType::BIGINT);
    names.push_back("hook_state");  types.push_back(LogicalType::VARCHAR);
    names.push_back("authn_delegate"); types.push_back(LogicalType::VARCHAR);
    names.push_back("authz_delegate"); types.push_back(LogicalType::VARCHAR);
    return nullptr;
}
static unique_ptr<GlobalTableFunctionState> HealthInit(ClientContext &, TableFunctionInitInput &) {
    return make_uniq<HealthState>();
}
static void HealthFn(ClientContext &ctx, TableFunctionInput &data, DataChunk &output) {
    // P4-3: health polling is the auto-rechain check point (r7 design:
    // "health continuously validates the current hook values") — monitoring polls health, hooks converge
    // on every call. Covers both "hook overwritten" and "quack loaded after
    // us" (initial takeover happens here when LOAD-time takeover was skipped).
    if (g_strict_set_ok) {
        CheckAndRechain(*ctx.db, "quack_authentication_function", AUTHN_CHAIN,
                        SET_DELEGATE_A, SET_SNAPSHOT_A);
        CheckAndRechain(*ctx.db, "quack_authorization_function", AUTHZ_CHAIN,
                        SET_DELEGATE_Z, SET_SNAPSHOT_Z);
    }
    auto &st = data.global_state->Cast<HealthState>();
    if (st.done) { output.SetCardinality(0); return; }
    output.SetCardinality(1);
    output.SetValue(0, 0, Value::BIGINT(sql_audit_get_captured()));
    output.SetValue(1, 0, Value::BIGINT(sql_audit_get_dropped()));
    output.SetValue(2, 0, Value::BIGINT(sql_audit_get_pending()));
    output.SetValue(3, 0, Value::BIGINT(sql_audit_get_record_count()));
    output.SetValue(4, 0, Value::BIGINT(sql_audit_get_file_count()));
    output.SetValue(5, 0, Value::BOOLEAN(sql_audit_get_halted() != 0));
    output.SetValue(6, 0, Value::BIGINT(sql_audit_get_nats_published()));
    output.SetValue(7, 0, Value::BIGINT(sql_audit_get_nats_errors()));
    output.SetValue(8, 0, Value::BIGINT(sql_audit_get_conn_count()));
    output.SetValue(9, 0, Value::BIGINT(sql_audit_get_conn_reject_count()));
    // hook_state from real evidence, not a hardcoded value:
    //   not_hooked — STRICT could not be enabled at LOAD
    //   hooked     — our parser_override has actually fired (g_override_calls>0)
    //   registered — STRICT on, override registered, no statement seen yet
    string hook_str;
    if (!g_strict_set_ok) {
        hook_str = "not_hooked";
    } else if (g_override_calls.load(std::memory_order_relaxed) > 0) {
        hook_str = "hooked";
    } else {
        hook_str = "registered";
    }
    output.SetValue(10, 0, Value(hook_str));
    output.SetValue(11, 0, Value(GetOwnStr(*ctx.db, SET_DELEGATE_A)));
    output.SetValue(12, 0, Value(GetOwnStr(*ctx.db, SET_DELEGATE_Z)));
    st.done = true;
}

// === Verify (5 columns: + window_start_seq, total from disk) ===
struct VerifyState : GlobalTableFunctionState { bool done = false; };
static unique_ptr<FunctionData> VerifyBind(ClientContext &, TableFunctionBindInput &,
                                            vector<LogicalType> &types, vector<Identifier> &names) {
    names.push_back("ok");       types.push_back(LogicalType::BOOLEAN);
    names.push_back("first_bad_seq"); types.push_back(LogicalType::BIGINT);
    names.push_back("total_records"); types.push_back(LogicalType::BIGINT);
    names.push_back("chain_head"); types.push_back(LogicalType::VARCHAR);
    names.push_back("window_start_seq"); types.push_back(LogicalType::BIGINT);
    return nullptr;
}
static unique_ptr<GlobalTableFunctionState> VerifyInit(ClientContext &, TableFunctionInitInput &) {
    return make_uniq<VerifyState>();
}
static void VerifyFn(ClientContext &, TableFunctionInput &data, DataChunk &output) {
    auto &st = data.global_state->Cast<VerifyState>();
    if (st.done) { output.SetCardinality(0); return; }
    char head[65] = {0};
    int64_t window_start = -1;
    int64_t disk_total = 0;
    int64_t result = sql_audit_verify(head, 64, &window_start, &disk_total);
    output.SetCardinality(1);
    output.SetValue(0, 0, Value::BOOLEAN(result == 0));
    output.SetValue(1, 0, Value::BIGINT(result));
    output.SetValue(2, 0, Value::BIGINT(disk_total));
    output.SetValue(3, 0, Value(string(head, strnlen(head, 64))));
    output.SetValue(4, 0, Value::BIGINT(window_start));
    st.done = true;
}

// === Settings callbacks (unchanged from Phase 3) ===
static void PathSetCallback(ClientContext &ctx, SetScope scope, Value &input) {
    auto path = input.ToString();
    sql_audit_set_path(path.c_str(), (int64_t)path.size());
}
static void MaxFileMbCallback(ClientContext &ctx, SetScope scope, Value &input) {
    sql_audit_set_max_file_mb(input.GetValue<int64_t>());
}
static void RetentionFilesCallback(ClientContext &ctx, SetScope scope, Value &input) {
    sql_audit_set_retention_files(input.GetValue<int64_t>());
}
static void RetentionPolicyCallback(ClientContext &ctx, SetScope scope, Value &input) {
    auto policy = input.ToString();
    int halt = (policy == "halt") ? 1 : 0;
    sql_audit_set_retention_policy(halt);
}
static void NatsUrlCallback(ClientContext &ctx, SetScope scope, Value &input) {
    auto url = input.ToString();
    sql_audit_set_nats_url(url.c_str(), (int64_t)url.size());
}
static void NatsSubjectCallback(ClientContext &ctx, SetScope scope, Value &input) {
    auto subj = input.ToString();
    sql_audit_set_nats_subject(subj.c_str(), (int64_t)subj.size());
}
static void ModeCallback(ClientContext &ctx, SetScope scope, Value &input) {
    auto mode = input.ToString();
    sql_audit_set_mode(mode.c_str(), (int64_t)mode.size());
}
static void AutoHookCallback(ClientContext &ctx, SetScope scope, Value &input) {
    g_auto_hook.store(input.GetValue<bool>());
}
static void KeyFileCallback(ClientContext &ctx, SetScope scope, Value &input) {
    auto path = input.ToString();
    sql_audit_set_key_file(path.c_str(), (int64_t)path.size());
}
static void NatsConfirmCallback(ClientContext &ctx, SetScope scope, Value &input) {
    sql_audit_set_nats_confirm(input.GetValue<bool>() ? 1 : 0);
}

// P4-3: manual re-hook (explicit recovery, mirrors auto-rechain semantics)
static void RehookFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &ctx = state.GetContext();
    bool did = false;
    string current = GetQuackSetting(*ctx.db, "quack_authentication_function");
    if (!current.empty() && current != AUTHN_CHAIN && IsPlainIdentifier(current)) {
        SetOwnStr(*ctx.db, SET_DELEGATE_A, current);
    }
    try {
        DBConfig::GetConfig(*ctx.db).SetOption("quack_authentication_function", Value(AUTHN_CHAIN));
        SetOwnStr(*ctx.db, SET_SNAPSHOT_A, AUTHN_CHAIN);
        did = true;
    } catch (...) {}
    string current_z = GetQuackSetting(*ctx.db, "quack_authorization_function");
    if (!current_z.empty() && current_z != AUTHZ_CHAIN && IsPlainIdentifier(current_z)) {
        SetOwnStr(*ctx.db, SET_DELEGATE_Z, current_z);
    }
    try {
        DBConfig::GetConfig(*ctx.db).SetOption("quack_authorization_function", Value(AUTHZ_CHAIN));
        SetOwnStr(*ctx.db, SET_SNAPSHOT_Z, AUTHZ_CHAIN);
        did = true;
    } catch (...) {}
    AuditSysEvent("rehook", "manual sql_audit_rehook()");
    result.SetValue(0, Value::BOOLEAN(did));
}

// === Load ===
static void LoadInternal(ExtensionLoader &loader) {
    auto &db = loader.GetDatabaseInstance();
    sql_audit_init();

    // Register table functions
    TableFunction health_fn("sql_audit_health", {}, HealthFn, HealthBind, HealthInit);
    loader.RegisterFunction(health_fn);
    TableFunction verify_fn("sql_audit_verify", {}, VerifyFn, VerifyBind, VerifyInit);
    loader.RegisterFunction(verify_fn);

    // Phase 4: Register chain functions (for quack authn/authz delegation)
    ScalarFunction authn_chain("sql_audit_authn_chain",
        {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
        LogicalType::BOOLEAN, AuthnChainFunction);
    authn_chain.SetVolatile();
    loader.RegisterFunction(authn_chain);

    ScalarFunction authz_chain("sql_audit_authz_chain",
        {LogicalType::VARCHAR, LogicalType::VARCHAR},
        LogicalType::VARCHAR, AuthzChainFunction);
    authz_chain.SetVolatile();
    loader.RegisterFunction(authz_chain);

// P4-3: manual re-hook
    ScalarFunction rehook_fn("sql_audit_rehook", {}, LogicalType::BOOLEAN, RehookFunction);
    rehook_fn.SetVolatile();
    loader.RegisterFunction(rehook_fn);


    // Register parser override
    auto &callbacks = ExtensionCallbackManager::Get(db);
    ParserExtension ext;
    ext.parser_override = AuditOverride;
    callbacks.Register(std::move(ext));

    // Register settings
    auto &config = DBConfig::GetConfig(db);
    config.AddExtensionOption("sql_audit_path", "Audit output directory",
                              LogicalType::VARCHAR, Value(""), PathSetCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_max_file_mb", "Max file MB before rotation",
                              LogicalType::BIGINT, Value::BIGINT(64), MaxFileMbCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_retention_files", "Max audit files",
                              LogicalType::BIGINT, Value::BIGINT(32), RetentionFilesCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_retention_policy", "Retention: prune or halt",
                              LogicalType::VARCHAR, Value("prune"), RetentionPolicyCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_nats_url", "NATS server URL",
                              LogicalType::VARCHAR, Value(""), NatsUrlCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_nats_subject", "NATS subject",
                              LogicalType::VARCHAR, Value("sqlaudit"), NatsSubjectCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_mode", "Mode: local/nats/both/off",
                              LogicalType::VARCHAR, Value("local"), ModeCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_auto_hook", "Auto re-take quack hooks when overwritten",
                              LogicalType::BOOLEAN, Value::BOOLEAN(true), AutoHookCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_key_file", "Externalized chain key file (outside audit dir)",
                              LogicalType::VARCHAR, Value(""), KeyFileCallback, SetScope::GLOBAL);
    config.AddExtensionOption("sql_audit_nats_confirm", "PING/PONG confirmation for every NATS publish",
                              LogicalType::BOOLEAN, Value::BOOLEAN(false), NatsConfirmCallback, SetScope::GLOBAL);
    // internal per-DB hook state (do not SET manually)
    config.AddExtensionOption(SET_DELEGATE_A, "internal: authn delegate", LogicalType::VARCHAR, Value(""), nullptr, SetScope::GLOBAL);
    config.AddExtensionOption(SET_DELEGATE_Z, "internal: authz delegate", LogicalType::VARCHAR, Value(""), nullptr, SetScope::GLOBAL);
    config.AddExtensionOption(SET_SNAPSHOT_A, "internal: authn hook snapshot", LogicalType::VARCHAR, Value(""), nullptr, SetScope::GLOBAL);
    config.AddExtensionOption(SET_SNAPSHOT_Z, "internal: authz hook snapshot", LogicalType::VARCHAR, Value(""), nullptr, SetScope::GLOBAL);

    // === AUTO-HOOK: Auto-enable STRICT at LOAD time ===
    // (duckdb-acl precedent: acl_extension.cpp:341-344)
    // This eliminates the "forgot to SET strict" failure mode
    auto &client_config = DBConfig::GetConfig(db);
    Value strict_val = Value("strict");
    try {
        client_config.SetOption("allow_parser_override_extension", strict_val);
        g_strict_set_ok = true;
    } catch (...) {
        // Setting might not be settable at load time in all contexts
        // Fall back: user manually sets it (health panel reports not_hooked)
        g_strict_set_ok = false;
    }

    // === P4-3: take over quack authn/authz hooks at LOAD (per-DB state) ===
    // If quack is already loaded, its current hook function becomes our
    // delegate; if quack loads LATER, the first health poll completes the
    // takeover (CheckAndRechain handles the empty-but-registered case).
    if (g_strict_set_ok) {
        bool took_a = false, took_z = false;
        HookTakeover(db, "quack_authentication_function", AUTHN_CHAIN,
                     SET_DELEGATE_A, SET_SNAPSHOT_A, &took_a);
        if (took_a) {
            string old_authn = GetOwnStr(db, SET_DELEGATE_A);
            AuditSysEvent("hook", string("quack_authentication_function -> ") + AUTHN_CHAIN +
                          " (delegate=" + (old_authn.empty() ? "<none>" : old_authn) + ")");
        }
        HookTakeover(db, "quack_authorization_function", AUTHZ_CHAIN,
                     SET_DELEGATE_Z, SET_SNAPSHOT_Z, &took_z);
        if (took_z) {
            string old_authz = GetOwnStr(db, SET_DELEGATE_Z);
            AuditSysEvent("hook", string("quack_authorization_function -> ") + AUTHZ_CHAIN +
                          " (delegate=" + (old_authz.empty() ? "<none>" : old_authz) + ")");
        }
    }
}

} // namespace duckdb

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(sql_audit, loader) {
    duckdb::LoadInternal(loader);
}
}
