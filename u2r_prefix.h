#ifndef U2R_PREFIX_H_
#define U2R_PREFIX_H_

// Type renames
#define conn_info_t       u2r_conn_info_t
#define blob_t            u2r_blob_t
#define conn_manager_t    u2r_conn_manager_t
#define conv_manager_t    u2r_conv_manager_t
#define anti_replay_t     u2r_anti_replay_t
#define lru_collector_t   u2r_lru_collector_t

// Global renames (conflicting variables)
#define conn_manager      u2r_conn_manager
#define random_drop       u2r_random_drop
#define raw_mode          u2r_raw_mode
#define mtu_warn          u2r_mtu_warn
#define about_to_exit     u2r_about_to_exit

// Function renames (conflicting functions)
#define server_clear_function u2r_server_clear_function
#define crc32h             u2r_crc32h

#endif
