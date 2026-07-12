#ifndef U2R_PREFIX_H_
#define U2R_PREFIX_H_

// Only rename struct/class types that differ between codebases.
// Do NOT rename functions (they're shared or only in one codebase).

#define conn_info_t       u2r_conn_info_t
#define blob_t            u2r_blob_t
#define conn_manager_t    u2r_conn_manager_t
#define conv_manager_t    u2r_conv_manager_t
#define anti_replay_t     u2r_anti_replay_t
#define lru_collector_t   u2r_lru_collector_t

#endif
