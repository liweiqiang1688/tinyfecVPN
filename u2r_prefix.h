#ifndef U2R_PREFIX_H_
#define U2R_PREFIX_H_

// Type renames
#define conn_info_t       u2r_conn_info_t
#define blob_t            u2r_blob_t
#define conn_manager_t    u2r_conn_manager_t
#define conv_manager_t    u2r_conv_manager_t
#define anti_replay_t     u2r_anti_replay_t
#define lru_collector_t   u2r_lru_collector_t

// Function renames for functions that exist in BOTH and have
// IDENTICAL signatures. These must be renamed to avoid link errors.
// Functions with same signature AND same implementation are NOT renamed
// (the linker will pick one, which is fine).
#define set_buf_size           u2r_set_buf_size
#define get_sock_error         u2r_get_sock_error
#define get_sock_errno         u2r_get_sock_errno
#define create_fifo            u2r_create_fifo
#define myexit                 u2r_myexit
#define my_ntoa                u2r_my_ntoa
#define pack_u64               u2r_pack_u64
#define get_u64_h              u2r_get_u64_h
#define get_u64_l              u2r_get_u64_l
#define csum                   u2r_csum
#define csum_with_header       u2r_csum_with_header
#define larger_than_u32        u2r_larger_than_u32
#define larger_than_u16        u2r_larger_than_u16
#define numbers_to_char        u2r_numbers_to_char
#define char_to_numbers        u2r_char_to_numbers
#define hton64                 u2r_hton64
#define ntoh64                 u2r_ntoh64
#define print_binary_chars     u2r_print_binary_chars
#define run_command            u2r_run_command
#define trim                   u2r_trim
#define trim_conf_line         u2r_trim_conf_line
#define parse_conf_line        u2r_parse_conf_line
#define read_file              u2r_read_file
#define string_to_vec          u2r_string_to_vec
#define string_to_vec2         u2r_string_to_vec2
#define hex_to_u32             u2r_hex_to_u32
#define hex_to_u32_with_endian u2r_hex_to_u32_with_endian
#define djb2                   u2r_djb2
#define sdbm                   u2r_sdbm
#define process_arg            u2r_process_arg
#define pre_process_arg        u2r_pre_process_arg
#define print_help             u2r_print_help
#define load_config            u2r_load_config
#define process_log_level      u2r_process_log_level
#define process_lower_level_arg u2r_process_lower_level_arg
#define signal_handler          u2r_signal_handler
#define iptables_rule           u2r_iptables_rule
#define clear_iptables_rule     u2r_clear_iptables_rule
#define add_iptables_rule       u2r_add_iptables_rule
#define iptables_gen_add        u2r_iptables_gen_add
#define iptables_rule_init      u2r_iptables_rule_init
#define keep_iptables_rule      u2r_keep_iptables_rule
#define unit_test               u2r_unit_test
#define set_timer               u2r_set_timer
#define set_timer_server        u2r_set_timer_server

#endif
