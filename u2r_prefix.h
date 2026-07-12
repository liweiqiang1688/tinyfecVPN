#ifndef U2R_PREFIX_H_
#define U2R_PREFIX_H_

// Rename conflicting STRUCT/CLASS types
#define conn_info_t       u2r_conn_info_t
#define blob_t            u2r_blob_t
#define conn_manager_t    u2r_conn_manager_t
#define conv_manager_t    u2r_conv_manager_t
#define anti_replay_t     u2r_anti_replay_t
#define lru_collector_t   u2r_lru_collector_t

// Rename global variables that exist in both codebases
#define local_addr        u2r_local_addr
#define remote_addr       u2r_remote_addr
#define source_addr       u2r_source_addr
#define program_mode      u2r_program_mode
#define raw_mode          u2r_raw_mode
#define raw_ip_version    u2r_raw_ip_version
#define key_string        u2r_key_string
#define fifo_file         u2r_fifo_file
#define const_id          u2r_const_id
#define bind_fd           u2r_bind_fd
#define udp_fd            u2r_udp_fd
#define epollfd           u2r_epollfd
#define timer_fd          u2r_timer_fd
#define conn_manager      u2r_conn_manager
#define fd_manager        u2r_fd_manager
#define about_to_exit     u2r_about_to_exit
#define socket_buf_size   u2r_socket_buf_size
#define bind_addr         u2r_bind_addr
#define bind_addr_used    u2r_bind_addr_used
#define dev               u2r_dev
#define mtu_warn          u2r_mtu_warn
#define random_drop       u2r_random_drop

// Function renames (only those that have different implementations)
#define process_arg       u2r_process_arg
#define pre_process_arg   u2r_pre_process_arg
#define print_help        u2r_print_help
#define myexit            u2r_myexit
#define get_current_time  u2r_get_current_time
#define setnonblocking    u2r_setnonblocking
#define set_buf_size      u2r_set_buf_size
#define get_sock_error    u2r_get_sock_error
#define create_fifo       u2r_create_fifo
#define get_true_random_number    u2r_get_true_random_number
#define get_true_random_number_nz u2r_get_true_random_number_nz
#define get_true_random_number_64 u2r_get_true_random_number_64
#define force_socket_buf  u2r_force_socket_buf
#define read_file         u2r_read_file
#define string_to_vec2    u2r_string_to_vec2
#define hex_to_u32        u2r_hex_to_u32
#define hex_to_u32_with_endian u2r_hex_to_u32_with_endian
#define csum_with_header  u2r_csum_with_header
#define larger_than_u32   u2r_larger_than_u32
#define larger_than_u16   u2r_larger_than_u16
#define numbers_to_char   u2r_numbers_to_char
#define char_to_numbers   u2r_char_to_numbers
#define hton64            u2r_hton64
#define ntoh64            u2r_ntoh64
#define print_binary_chars u2r_print_binary_chars
#define run_command       u2r_run_command

#endif
