// Prefix header to avoid conflicts between udp2raw and UDPspeeder symbols.
// Include this BEFORE any udp2raw headers.
// After all includes, #undef the macros.

#ifndef U2R_PREFIX_H_
#define U2R_PREFIX_H_

// ---- Renamed types ----
#define conn_info_t       u2r_conn_info_t
#define blob_t            u2r_blob_t
#define conn_manager_t    u2r_conn_manager_t
#define conv_manager_t    u2r_conv_manager_t
#define anti_replay_t     u2r_anti_replay_t
#define lru_collector_t   u2r_lru_collector_t
#define raw_info_t        u2r_raw_info_t
#define packet_info_t     u2r_packet_info_t
#define fd_manager_t      u2r_fd_manager_t

// ---- Renamed global variables (ones that exist in both projects) ----
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
#define force_source_ip   u2r_force_source_ip
#define force_source_port u2r_force_source_port
#define source_port       u2r_source_port
#define fail_time_counter u2r_fail_time_counter
#define debug_flag        u2r_debug_flag
#define epoll_trigger_counter u2r_epoll_trigger_counter
#define keep_thread       u2r_keep_thread
#define keep_thread_running u2r_keep_thread_running
#define simple_rule       u2r_simple_rule
#define keep_rule         u2r_keep_rule
#define auto_add_iptables_rule u2r_auto_add_iptables_rule
#define generate_iptables_rule u2r_generate_iptables_rule
#define generate_iptables_rule_add u2r_generate_iptables_rule_add
#define retry_on_error    u2r_retry_on_error
#define debug_resend      u2r_debug_resend
#define clear_iptables    u2r_clear_iptables
#define iptables_rule_added u2r_iptables_rule_added
#define iptables_rule_keeped u2r_iptables_rule_keeped
#define iptables_rule_keep_index u2r_iptables_rule_keep_index

// ---- Functions that have different implementations ----
#define process_arg       u2r_process_arg
#define pre_process_arg   u2r_pre_process_arg
#define print_help        u2r_print_help
#define myexit            u2r_myexit
#define mylog             u2r_mylog
#define log_bare          u2r_log_bare
#define get_current_time  u2r_get_current_time
#define create_fifo       u2r_create_fifo
#define setnonblocking    u2r_setnonblocking
#define set_buf_size      u2r_set_buf_size
#define get_sock_error    u2r_get_sock_error
#define get_sock_errno    u2r_get_sock_errno

#endif
