#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum { SQL_AUDIT_PASS=0, SQL_AUDIT_REJECT=1, SQL_AUDIT_DEGRADED=2 } SqlAuditVerdict;
int32_t sql_audit_init(void);
void sql_audit_shutdown(void);
SqlAuditVerdict sql_audit_capture(const char* q, int64_t len);
int64_t sql_audit_get_captured(void);
int64_t sql_audit_get_dropped(void);
int64_t sql_audit_get_pending(void);
int32_t sql_audit_flush(int64_t timeout_ms);
int32_t sql_audit_set_path(const char* path, int64_t path_len);
int64_t sql_audit_verify(char* out_head, int64_t head_len,
                         int64_t* window_start, int64_t* disk_total);
int64_t sql_audit_get_record_count(void);
int32_t sql_audit_set_max_file_mb(int64_t mb);
int32_t sql_audit_set_retention_files(int64_t count);
int32_t sql_audit_set_retention_policy(int32_t halt);
int64_t sql_audit_get_file_count(void);
int32_t sql_audit_get_halted(void);
int32_t sql_audit_set_nats_subject(const char* subject, int64_t subject_len);
int32_t sql_audit_set_mode(const char* mode, int64_t mode_len);
int64_t sql_audit_get_nats_published(void);
int64_t sql_audit_get_nats_errors(void);
// Phase 4: Connection records + quack attribution
int32_t sql_audit_conn_open(const char* conn_id, int64_t conn_len,
                             const char* token, int64_t token_len,
                             const char* authn_result, int64_t result_len,
                             const char* reason, int64_t reason_len);
int32_t sql_audit_capture_stmt(const char* conn_id, int64_t conn_len,
                                const char* query, int64_t query_len);
int64_t sql_audit_get_conn_count(void);
int64_t sql_audit_get_conn_reject_count(void);
int32_t sql_audit_get_hook_state(void); // 0=not-hooked, 1=hooked, 2=overridden
// P4-3: auto-rechain support
int32_t sql_audit_sys_event(const char* event_type, int64_t type_len,
                            const char* detail, int64_t detail_len);
int32_t sql_audit_conn_reject_add(void);

// LOW-fix batch (r24): key externalization + NATS confirmation
int32_t sql_audit_set_key_file(const char* path, int64_t path_len);
int32_t sql_audit_set_nats_confirm(int32_t on);
int32_t sql_audit_set_disk_free_pct(int64_t pct);
int64_t sql_audit_get_disk_free_pct(void);
// Bridge to nats_rw extension (v2.0)
int32_t sql_audit_bridge_publish(
    const char** subjects, const char** payloads, int64_t count,
    const char* secret_name, int32_t confirm, uint32_t timeout_sec,
    char* err_buf, int64_t err_len);
int32_t sql_audit_bridge_probe_function(void);
int32_t sql_audit_bridge_try_load_nats_rw(void);
int32_t sql_audit_set_nats_secret_bridge(const char* secret_name, int64_t name_len);
#ifdef __cplusplus
}
#endif
