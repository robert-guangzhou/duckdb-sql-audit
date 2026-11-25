// sql_audit_bridge.cpp — C++ bridge connecting sql_audit's Rust engine to
// the nats_rw extension via DuckDB's SQL layer.
//
// Architecture: Rust consumer thread → FFI → Connection.Query(SQL) →
// nats_rw_publish_batch() → NATS. This replaces the hand-written raw TCP
// client (sink_nats.rs) with nats_rw's async-nats/TLS/pooled connection.

#include "duckdb.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/config.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

namespace duckdb {

// ============================================================
// 1. DatabaseInstance capture (set at LOAD, used by bridge FFI)
// ============================================================

static DatabaseInstance *g_bridge_db = nullptr;

void SetBridgeDatabase(DatabaseInstance *db) {
    g_bridge_db = db;
}

// ============================================================
// 2. BridgeGuard RAII (prevents auditing the bridge's own SQL)
// ============================================================

static thread_local bool g_in_bridge = false;

struct BridgeGuard {
    BridgeGuard()  { g_in_bridge = true; }
    ~BridgeGuard() { g_in_bridge = false; }  // exception-safe reset
};

bool IsInBridge() {
    return g_in_bridge;
}

// ============================================================
// 3. SQL escaping (DuckDB literals: only ' needs '' doubling)
//    Payloads use ::BLOB for binary safety.
// ============================================================

static string bridge_escape(const char *s) {
    string out;
    for (const char *p = s; *p; p++) {
        if (*p == '\'') {
            out += "''";
        } else {
            out += *p;
        }
    }
    return out;
}

// ============================================================
// 4. Bridge publish FFI (called from Rust consumer thread)
// ============================================================

#define BRIDGE_BATCH_SIZE 64
#define BRIDGE_DEFAULT_TIMEOUT_SEC 30

extern "C" int32_t sql_audit_bridge_publish(
    const char **subjects,
    const char **payloads,
    int64_t count,
    const char *secret_name,
    int32_t confirm,
    uint32_t timeout_sec,
    char *err_buf,
    int64_t err_len
) {
    if (!g_bridge_db) {
        snprintf(err_buf, err_len, "bridge: DatabaseInstance not captured");
        return -1;
    }
    if (count <= 0) return 0;
    if (timeout_sec == 0) timeout_sec = BRIDGE_DEFAULT_TIMEOUT_SEC;

    BridgeGuard guard;
    Connection con(*g_bridge_db);
    int32_t total_published = 0;

    // Process in batches of ≤64 to keep SQL text bounded
    for (int64_t batch_start = 0; batch_start < count; batch_start += BRIDGE_BATCH_SIZE) {
        int64_t batch_end = std::min(batch_start + BRIDGE_BATCH_SIZE, count);
        int64_t batch_count = batch_end - batch_start;

        // Build: SELECT * FROM nats_rw_publish_batch(
        //   [{'subject':'...','payload':'...'::BLOB}, ...],
        //   secret_name := '...', confirm := true/false)
        string sql = "SELECT * FROM nats_rw_publish_batch([";
        for (int64_t i = batch_start; i < batch_end; i++) {
            string subj = bridge_escape(subjects[i]);
            string payload = bridge_escape(payloads[i]);
            if (i > batch_start) sql += ", ";
            sql += "{'subject': '" + subj + "', 'payload': '" + payload + "'::BLOB}";
        }
        string secret = bridge_escape(secret_name ? secret_name : "");
        sql += "], secret_name := '" + secret +
               "', confirm := " + (confirm ? "true" : "false") + ")";

        // Watchdog: interrupt if query exceeds timeout
        auto done = std::make_shared<std::atomic<bool>>(false);
        auto watchdog = std::thread([done, &con, timeout_sec]() {
            for (uint32_t i = 0; i < timeout_sec * 10 && !done->load(); i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (!done->load()) {
                con.Interrupt();
            }
        });

        int32_t rc;
        try {
            auto result = con.Query(sql);
            done->store(true);
            if (result->HasError()) {
                snprintf(err_buf, err_len, "bridge: %s", result->GetError().c_str());
                watchdog.join();
                return -1;
            }
            // Extract 'published' column from the single-row result
            auto chunk = result->Fetch();
            if (chunk && chunk->size() > 0) {
                total_published += (int32_t)chunk->GetValue(0, 0).GetValue<int64_t>();
            }
            rc = 0;
        } catch (std::exception &e) {
            done->store(true);
            snprintf(err_buf, err_len, "bridge exception: %s", e.what());
            watchdog.join();
            return -1;
        }
        watchdog.join();
        if (rc != 0) return rc;
    }

    return total_published;
}

// ============================================================
// 5. Probe: is nats_rw_publish_batch available?
// ============================================================

extern "C" int32_t sql_audit_bridge_probe_function() {
    if (!g_bridge_db) return -1;
    try {
        BridgeGuard guard;
        Connection con(*g_bridge_db);
        auto result = con.Query(
            "SELECT count(*) FROM duckdb_functions() "
            "WHERE function_name = 'nats_rw_publish_batch'");
        if (result->HasError()) return -1;
        auto chunk = result->Fetch();
        if (chunk && chunk->size() > 0) {
            return chunk->GetValue(0, 0).GetValue<int64_t>() > 0 ? 0 : -1;
        }
        return -1;
    } catch (...) {
        return -1;
    }
}

// ============================================================
// 6. Try to auto-load nats_rw extension
// ============================================================

extern "C" int32_t sql_audit_bridge_try_load_nats_rw() {
    if (!g_bridge_db) return -1;
    // For now, just probe — auto-load requires extension infrastructure
    // that may not be available in all DuckDB builds. Users should LOAD
    // nats_rw explicitly before using mode=nats/both.
    return sql_audit_bridge_probe_function();
}

} // namespace duckdb
