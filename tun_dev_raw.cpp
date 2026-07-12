// tun_dev_raw.cpp - Raw socket transport layer for tinyfecVPN
// Compiles udp2raw code with renamed symbols to avoid conflicts with UDPspeeder.

#include "u2r_prefix.h"

#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "encrypt.h"
#include "fd_manager.h"

#include "common.cpp"
#include "log.cpp"
#include "misc.cpp"
#include "fd_manager.cpp"
#include "network.cpp"
#include "connection.cpp"
#include "encrypt.cpp"
#include "lib/md5.cpp"
#include "lib/pbkdf2-sha1.cpp"
#include "lib/pbkdf2-sha256.cpp"
#include "lib/aes_faster_c/aes.cpp"
#include "lib/aes_faster_c/wrapper.cpp"

#undef conn_info_t
#undef blob_t
#undef conn_manager_t
#undef conv_manager_t
#undef anti_replay_t
#undef lru_collector_t
#undef raw_info_t
#undef packet_info_t
#undef fd_manager_t
#undef local_addr
#undef remote_addr
#undef source_addr
#undef program_mode
#undef raw_mode
#undef raw_ip_version
#undef key_string
#undef fifo_file
#undef const_id
#undef bind_fd
#undef udp_fd
#undef epollfd
#undef timer_fd
#undef conn_manager
#undef fd_manager
#undef about_to_exit
#undef socket_buf_size
#undef bind_addr
#undef bind_addr_used
#undef force_source_ip
#undef force_source_port
#undef source_port
#undef fail_time_counter
#undef debug_flag
#undef epoll_trigger_counter
#undef keep_thread
#undef keep_thread_running
#undef simple_rule
#undef keep_rule
#undef auto_add_iptables_rule
#undef generate_iptables_rule
#undef generate_iptables_rule_add
#undef retry_on_error
#undef debug_resend
#undef clear_iptables
#undef iptables_rule_added
#undef iptables_rule_keeped
#undef iptables_rule_keep_index
#undef process_arg
#undef pre_process_arg
#undef print_help
#undef myexit
#undef mylog
#undef log_bare
#undef get_current_time
#undef create_fifo
#undef setnonblocking
#undef set_buf_size
#undef get_sock_error
#undef get_sock_errno

#include "tun_dev_raw.h"

// Internal state structures using udp2raw (renamed) types
struct raw_client_t {
    u2r_conn_info_t conn_info;
    int is_ready;
};

struct raw_server_t {
    u2r_conn_info_t conn_info;
    int is_ready;
    int has_client;
};

// Accessor helpers for renamed globals
static inline address_t& raw_remote_addr() { return u2r_remote_addr; }
static inline address_t& raw_local_addr()  { return u2r_local_addr; }
static inline int&       raw_bind_fd()     { return u2r_bind_fd; }
static inline int&       raw_udp_fd()      { return u2r_udp_fd; }

raw_client_t *raw_client_init(const char *remote_addr_str, const char *local_addr_str,
                               const char *key, const char *dev) {
    raw_client_t *ctx = new raw_client_t();
    memset(ctx, 0, sizeof(*ctx));
    ctx->is_ready = 0;

    raw_remote_addr().from_str((char *)remote_addr_str);
    raw_local_addr().from_str((char *)local_addr_str);

    u2r_program_mode = client_mode;
    u2r_raw_mode = mode_faketcp;
    u2r_raw_ip_version = raw_remote_addr().get_type();
    u2r_use_tcp_dummy_socket = 0;

    if (key && key[0])
        strncpy(u2r_key_string, key, sizeof(u2r_key_string) - 1);
    if (dev && dev[0])
        strncpy(u2r_dev, dev, sizeof(u2r_dev) - 1);

    srand(u2r_get_true_random_number_nz());
    u2r_const_id = u2r_get_true_random_number_nz();
    u2r_my_init_keys(u2r_key_string, 1);

    u2r_mylog(log_info, "raw_client_init done\n");
    return ctx;
}

void raw_client_destroy(raw_client_t *ctx) {
    if (ctx) delete ctx;
}

int raw_client_get_raw_recv_fd(raw_client_t *) {
    return u2r_raw_recv_fd;
}

int raw_client_start(raw_client_t *ctx) {
    u2r_lower_level = 0;
    u2r_init_raw_socket();

    u2r_conn_info_t &conn_info = ctx->conn_info;
    conn_info.my_id = u2r_get_true_random_number_nz();
    conn_info.prepare();

    u2r_packet_info_t &send_info = conn_info.raw_info.send_info;
    send_info.new_dst_ip.from_address_t(raw_remote_addr());
    send_info.dst_port = raw_remote_addr().get_port();

    address_t tmp_addr;
    if (u2r_get_src_adress2(tmp_addr, raw_remote_addr()) != 0) {
        u2r_mylog(log_warn, "get_src_adress() failed\n");
        return -1;
    }
    send_info.new_src_ip.from_address_t(tmp_addr);
    send_info.src_port = u2r_client_bind_to_a_new_port2(raw_bind_fd(), tmp_addr);

    u2r_mylog(log_info, "using port %d\n", send_info.src_port);
    u2r_init_filter(send_info.src_port);

    conn_info.state.client_current_state = client_tcp_handshake;
    conn_info.last_state_time = u2r_get_current_time();
    conn_info.last_hb_sent_time = 0;

    send_info.syn = 1;
    send_info.ack = 0;
    send_info.psh = 0;
    send_info.seq = u2r_get_true_random_number();
    send_info.ack_seq = u2r_get_true_random_number();
    u2r_send_raw0(conn_info.raw_info, 0, 0);

    u2r_mylog(log_info, "raw_client_start: sent syn\n");
    return 0;
}

void raw_client_on_timer(raw_client_t *ctx) {
    u2r_conn_info_t &conn_info = ctx->conn_info;
    u2r_packet_info_t &send_info = conn_info.raw_info.send_info;
    u2r_packet_info_t &recv_info = conn_info.raw_info.recv_info;
    u2r_raw_info_t &raw_info = conn_info.raw_info;

    conn_info.blob->conv_manager.c.clear_inactive();

    if (raw_info.disabled) {
        conn_info.state.client_current_state = client_idle;
        conn_info.my_id = u2r_get_true_random_number_nz();
        u2r_mylog(log_info, "state back to client_idle\n");
        return;
    }

    if (conn_info.state.client_current_state == client_idle) {
        raw_info.rst_received = 0;
        raw_info.disabled = 0;
        ctx->is_ready = 0;
        conn_info.blob->anti_replay.re_init();
        conn_info.my_id = u2r_get_true_random_number_nz();

        address_t tmp_addr;
        if (u2r_get_src_adress2(tmp_addr, raw_remote_addr()) != 0) return;
        send_info.new_src_ip.from_address_t(tmp_addr);
        send_info.src_port = u2r_client_bind_to_a_new_port2(raw_bind_fd(), tmp_addr);
        u2r_init_filter(send_info.src_port);

        conn_info.state.client_current_state = client_tcp_handshake;
        conn_info.last_state_time = u2r_get_current_time();
        conn_info.last_hb_sent_time = 0;
        send_info.syn = 1; send_info.ack = 0; send_info.psh = 0;
        send_info.seq = u2r_get_true_random_number();
        send_info.ack_seq = u2r_get_true_random_number();
        u2r_send_raw0(raw_info, 0, 0);
        return;
    }

    if (conn_info.state.client_current_state == client_tcp_handshake) {
        if (u2r_get_current_time() - conn_info.last_state_time > client_handshake_timeout) {
            conn_info.state.client_current_state = client_idle;
            u2r_mylog(log_info, "state back to client_idle from client_tcp_handshake\n");
            return;
        }
        if (u2r_get_current_time() - conn_info.last_hb_sent_time > client_retry_interval) {
            if (conn_info.last_hb_sent_time == 0) {
                send_info.psh = 0; send_info.syn = 1; send_info.ack = 0; send_info.ts_ack = 0;
                send_info.seq = u2r_get_true_random_number();
                send_info.ack_seq = u2r_get_true_random_number();
            }
            u2r_send_raw0(raw_info, 0, 0);
            conn_info.last_hb_sent_time = u2r_get_current_time();
            u2r_mylog(log_info, "(re)sent tcp syn\n");
        }
        return;
    }

    if (conn_info.state.client_current_state == client_handshake1) {
        if (u2r_get_current_time() - conn_info.last_state_time > client_handshake_timeout) {
            conn_info.state.client_current_state = client_idle;
            u2r_mylog(log_info, "state back to client_idle from client_handshake1\n");
            return;
        }
        if (u2r_get_current_time() - conn_info.last_hb_sent_time > client_retry_interval) {
            if (conn_info.last_hb_sent_time == 0) {
                send_info.seq++;
                send_info.ack_seq = recv_info.seq + 1;
                send_info.ts_ack = recv_info.ts;
                raw_info.reserved_send_seq = send_info.seq;
            }
            send_info.seq = raw_info.reserved_send_seq;
            send_info.psh = 0; send_info.syn = 0; send_info.ack = 1;
            u2r_send_raw0(raw_info, 0, 0);
            u2r_send_handshake(raw_info, conn_info.my_id, 0, u2r_const_id);
            send_info.seq += raw_info.send_info.data_len;
            conn_info.last_hb_sent_time = u2r_get_current_time();
            u2r_mylog(log_info, "(re)sent handshake1\n");
        }
        return;
    }

    if (conn_info.state.client_current_state == client_handshake2) {
        if (u2r_get_current_time() - conn_info.last_state_time > client_handshake_timeout) {
            conn_info.state.client_current_state = client_idle;
            u2r_mylog(log_info, "state back to client_idle from client_handshake2\n");
            return;
        }
        if (u2r_get_current_time() - conn_info.last_hb_sent_time > client_retry_interval) {
            if (conn_info.last_hb_sent_time == 0) {
                send_info.ack_seq = recv_info.seq + raw_info.recv_info.data_len;
                send_info.ts_ack = recv_info.ts;
                raw_info.reserved_send_seq = send_info.seq;
            }
            send_info.seq = raw_info.reserved_send_seq;
            u2r_send_handshake(raw_info, conn_info.my_id, conn_info.oppsite_id, u2r_const_id);
            send_info.seq += raw_info.send_info.data_len;
            conn_info.last_hb_sent_time = u2r_get_current_time();
            u2r_mylog(log_info, "(re)sent handshake2\n");
        }
        return;
    }

    if (conn_info.state.client_current_state == client_ready) {
        if (u2r_get_current_time() - conn_info.last_hb_recv_time > client_conn_timeout) {
            conn_info.state.client_current_state = client_idle;
            conn_info.my_id = u2r_get_true_random_number_nz();
            ctx->is_ready = 0;
            u2r_mylog(log_info, "state back to client_idle from client_ready bc of timeout\n");
            return;
        }
        if (u2r_get_current_time() - conn_info.last_oppsite_roller_time > client_conn_uplink_timeout) {
            conn_info.state.client_current_state = client_idle;
            conn_info.my_id = u2r_get_true_random_number_nz();
            ctx->is_ready = 0;
            u2r_mylog(log_info, "state back to client_idle from client_ready bc of uplink timeout\n");
            return;
        }
        if (u2r_get_current_time() - conn_info.last_hb_sent_time < heartbeat_interval) return;

        u2r_mylog(log_debug, "heartbeat sent <%x,%x>\n", conn_info.oppsite_id, conn_info.my_id);
        if (u2r_hb_mode == 0)
            u2r_send_safer(conn_info, 'h', u2r_hb_buf, 0);
        else
            u2r_send_safer(conn_info, 'h', u2r_hb_buf, u2r_hb_len);
        conn_info.last_hb_sent_time = u2r_get_current_time();
        return;
    }
}

int raw_client_recv_packet(raw_client_t *ctx, char *data, int max_len) {
    u2r_conn_info_t &conn_info = ctx->conn_info;
    u2r_raw_info_t &raw_info = conn_info.raw_info;
    u2r_packet_info_t &send_info = raw_info.send_info;
    u2r_packet_info_t &recv_info = raw_info.recv_info;

    if (u2r_raw_recv_fd < 0) return -1;

    int data_len;
    char *raw_data;

    if (u2r_pre_recv_raw_packet() < 0) return -1;

    if (conn_info.state.client_current_state == client_idle) {
        u2r_discard_raw_packet();
        return 0;
    }

    if (conn_info.state.client_current_state == client_tcp_handshake) {
        if (u2r_recv_raw0(raw_info, raw_data, data_len) < 0) return -1;
        if (data_len >= max_data_len + 1) {
            u2r_mylog(log_debug, "data_len=%d >= max_data_len+1,ignored\n", data_len);
            return -1;
        }
        if (!recv_info.new_src_ip.equal(send_info.new_dst_ip) || recv_info.src_port != send_info.dst_port) {
            u2r_mylog(log_debug, "unexpected adress\n");
            return -1;
        }
        if (data_len == 0 && raw_info.recv_info.syn == 1 && raw_info.recv_info.ack == 1) {
            if (recv_info.ack_seq != send_info.seq + 1) {
                u2r_mylog(log_debug, "seq ack_seq mis match\n");
                return -1;
            }
            u2r_mylog(log_info, "state changed from client_tcp_handshake to client_handshake1\n");
            conn_info.state.client_current_state = client_handshake1;
            conn_info.last_state_time = u2r_get_current_time();
            conn_info.last_hb_sent_time = 0;
            raw_client_on_timer(ctx);
            return 0;
        }
        u2r_mylog(log_debug, "unexpected packet type,expected:syn ack\n");
        return -1;
    }

    if (conn_info.state.client_current_state == client_handshake1) {
        if (u2r_recv_bare(raw_info, raw_data, data_len) != 0) {
            u2r_mylog(log_debug, "recv_bare failed!\n");
            return -1;
        }
        if (!recv_info.new_src_ip.equal(send_info.new_dst_ip) || recv_info.src_port != send_info.dst_port) {
            u2r_mylog(log_debug, "unexpected adress\n");
            return -1;
        }
        if (data_len < int(3 * sizeof(my_id_t))) {
            u2r_mylog(log_debug, "too short to be a handshake\n");
            return -1;
        }

        my_id_t tmp_oppsite_id;
        memcpy(&tmp_oppsite_id, &raw_data[0], sizeof(tmp_oppsite_id));
        tmp_oppsite_id = ntohl(tmp_oppsite_id);

        my_id_t tmp_my_id;
        memcpy(&tmp_my_id, &raw_data[sizeof(my_id_t)], sizeof(tmp_my_id));
        tmp_my_id = ntohl(tmp_my_id);

        if (tmp_my_id != conn_info.my_id) {
            u2r_mylog(log_debug, "tmp_my_id doesnt match\n");
            return -1;
        }
        if (recv_info.ack_seq != send_info.seq) {
            u2r_mylog(log_debug, "seq ack_seq mis match\n");
            return -1;
        }
        if (recv_info.seq != send_info.ack_seq) {
            u2r_mylog(log_debug, "seq ack_seq mis match\n");
            return -1;
        }
        conn_info.oppsite_id = tmp_oppsite_id;

        u2r_mylog(log_info, "changed state from client_handshake1 to client_handshake2\n");
        conn_info.state.client_current_state = client_handshake2;
        conn_info.last_state_time = u2r_get_current_time();
        conn_info.last_hb_sent_time = 0;
        raw_client_on_timer(ctx);
        return 0;
    }

    if (conn_info.state.client_current_state == client_handshake2 ||
        conn_info.state.client_current_state == client_ready) {
        vector<char> type_vec;
        vector<string> data_vec;
        u2r_recv_safer_multi(conn_info, type_vec, data_vec);
        if (data_vec.empty()) {
            u2r_mylog(log_debug, "recv_safer failed!\n");
            return -1;
        }

        for (int i = 0; i < (int)type_vec.size(); i++) {
            char type = type_vec[i];
            char *d = (char *)data_vec[i].c_str();
            int d_len = data_vec[i].length();

            if (conn_info.state.client_current_state == client_handshake2) {
                u2r_mylog(log_info, "changed state from client_handshake2 to client_ready\n");
                conn_info.state.client_current_state = client_ready;
                ctx->is_ready = 1;
                conn_info.last_hb_sent_time = 0;
                conn_info.last_hb_recv_time = u2r_get_current_time();
                conn_info.last_oppsite_roller_time = conn_info.last_hb_recv_time;
                raw_client_on_timer(ctx);
            }

            if (d_len >= 0 && type == 'h') {
                u2r_mylog(log_debug, "[hb]heart beat received\n");
                conn_info.last_hb_recv_time = u2r_get_current_time();
            } else if (d_len >= int(sizeof(u32_t)) && type == 'd') {
                if (u2r_hb_mode == 0)
                    conn_info.last_hb_recv_time = u2r_get_current_time();

                u32_t tmp_conv_id;
                memcpy(&tmp_conv_id, &d[0], sizeof(tmp_conv_id));
                tmp_conv_id = ntohl(tmp_conv_id);

                if (!conn_info.blob->conv_manager.c.is_conv_used(tmp_conv_id)) {
                    u2r_mylog(log_info, "unknow conv %d,ignore\n", tmp_conv_id);
                    continue;
                }
                conn_info.blob->conv_manager.c.update_active_time(tmp_conv_id);

                int pkt_len = d_len - sizeof(u32_t);
                if (pkt_len > 0 && pkt_len <= max_len) {
                    memcpy(data, d + sizeof(u32_t), pkt_len);
                    return pkt_len;
                }
            }
        }
        return 0;
    }

    u2r_discard_raw_packet();
    return 0;
}

int raw_client_send_packet(raw_client_t *ctx, const char *data, int len) {
    if (!ctx->is_ready) {
        u2r_mylog(log_debug, "not ready, can't send\n");
        return -1;
    }

    u2r_conn_info_t &conn_info = ctx->conn_info;

    u32_t conv = conn_info.blob->conv_manager.c.get_new_conv();
    conn_info.blob->conv_manager.c.insert_conv(conv, raw_remote_addr());
    conn_info.blob->conv_manager.c.update_active_time(conv);
    u2r_send_data_safer(conn_info, data, len, conv);
    return 0;
}

int raw_client_is_ready(raw_client_t *ctx) {
    return ctx->is_ready;
}

// ---- Server ----

raw_server_t *raw_server_init(const char *local_addr_str, const char *key, const char *dev) {
    raw_server_t *ctx = new raw_server_t();
    memset(ctx, 0, sizeof(*ctx));
    ctx->is_ready = 0;
    ctx->has_client = 0;

    raw_local_addr().from_str((char *)local_addr_str);

    u2r_program_mode = server_mode;
    u2r_raw_mode = mode_faketcp;
    u2r_raw_ip_version = raw_local_addr().get_type();

    if (key && key[0])
        strncpy(u2r_key_string, key, sizeof(u2r_key_string) - 1);
    if (dev && dev[0])
        strncpy(u2r_dev, dev, sizeof(u2r_dev) - 1);

    srand(u2r_get_true_random_number_nz());
    u2r_const_id = u2r_get_true_random_number_nz();
    u2r_my_init_keys(u2r_key_string, 0);

    u2r_mylog(log_info, "raw_server_init done\n");
    return ctx;
}

void raw_server_destroy(raw_server_t *ctx) {
    if (ctx) delete ctx;
}

int raw_server_get_raw_recv_fd(raw_server_t *) {
    return u2r_raw_recv_fd;
}

int raw_server_start(raw_server_t *ctx) {
    u2r_lower_level = 0;
    u2r_init_raw_socket();

    raw_bind_fd() = socket(raw_local_addr().get_type(), SOCK_STREAM, 0);
    if (bind(raw_bind_fd(), (struct sockaddr *)&raw_local_addr().inner, raw_local_addr().get_len()) != 0) {
        u2r_mylog(log_fatal, "bind fail\n");
        u2r_myexit(-1);
    }
    if (listen(raw_bind_fd(), SOMAXCONN) != 0) {
        u2r_mylog(log_fatal, "listen fail\n");
        u2r_myexit(-1);
    }

    u2r_init_filter(raw_local_addr().get_port());
    u2r_mylog(log_info, "now listening at %s\n", raw_local_addr().get_str());
    return 0;
}

void raw_server_on_timer(raw_server_t *ctx) {
    if (!ctx->has_client || !ctx->is_ready) return;

    u2r_conn_info_t &conn_info = ctx->conn_info;
    conn_info.blob->conv_manager.s.clear_inactive("");

    if (conn_info.state.server_current_state == server_ready) {
        if (u2r_get_current_time() - conn_info.last_hb_sent_time < heartbeat_interval) return;

        if (u2r_hb_mode == 0)
            u2r_send_safer(conn_info, 'h', u2r_hb_buf, 0);
        else
            u2r_send_safer(conn_info, 'h', u2r_hb_buf, u2r_hb_len);
        conn_info.last_hb_sent_time = u2r_get_current_time();
        u2r_mylog(log_debug, "heart beat sent\n");
    }
}

int raw_server_recv_packet(raw_server_t *ctx, char *data, int max_len) {
    if (u2r_raw_recv_fd < 0) return -1;

    u2r_raw_info_t peek_raw_info;
    peek_raw_info.peek = 1;
    u2r_packet_info_t &peek_info = peek_raw_info.recv_info;

    if (u2r_pre_recv_raw_packet() < 0) return -1;
    if (u2r_peek_raw(peek_raw_info) < 0) {
        u2r_discard_raw_packet();
        return -1;
    }

    int data_len;
    char *raw_data;
    address_t addr;
    addr.from_ip_port_new(u2r_raw_ip_version, &peek_info.new_src_ip, peek_info.src_port);

    if (peek_info.syn == 1) {
        if (!ctx->has_client || ctx->conn_info.state.server_current_state != server_ready) {
            u2r_raw_info_t tmp_raw_info;
            if (u2r_recv_raw0(tmp_raw_info, raw_data, data_len) < 0) return 0;
            if (data_len >= max_data_len + 1) return -1;

            u2r_packet_info_t &send_syn = tmp_raw_info.send_info;
            u2r_packet_info_t &recv_syn = tmp_raw_info.recv_info;

            send_syn.new_src_ip = recv_syn.new_dst_ip;
            send_syn.src_port = recv_syn.dst_port;
            send_syn.dst_port = recv_syn.src_port;
            send_syn.new_dst_ip = recv_syn.new_src_ip;

            if (data_len == 0 && tmp_raw_info.recv_info.syn == 1 && tmp_raw_info.recv_info.ack == 0) {
                send_syn.ack_seq = recv_syn.seq + 1;
                send_syn.psh = 0; send_syn.syn = 1; send_syn.ack = 1;
                send_syn.ts_ack = recv_syn.ts;
                u2r_mylog(log_info, "received syn,sent syn ack back\n");
                u2r_send_raw0(tmp_raw_info, 0, 0);
                return 0;
            }
        } else {
            u2r_discard_raw_packet();
        }
        return 0;
    }

    if (!ctx->has_client) {
        u2r_raw_info_t tmp_raw_info;
        if (u2r_recv_bare(tmp_raw_info, raw_data, data_len) < 0) return 0;
        if (data_len < int(3 * sizeof(my_id_t))) return -1;

        my_id_t zero;
        memcpy(&zero, &raw_data[sizeof(my_id_t)], sizeof(zero));
        zero = ntohl(zero);
        if (zero != 0) return -1;

        u2r_mylog(log_info, "got packet from a new client\n");
        ctx->conn_info.raw_info = tmp_raw_info;

        u2r_conn_info_t &conn_info = ctx->conn_info;
        u2r_raw_info_t &rinfo = conn_info.raw_info;
        u2r_packet_info_t &sinfo = rinfo.send_info;
        u2r_packet_info_t &dinfo = rinfo.recv_info;

        sinfo.new_src_ip = dinfo.new_dst_ip;
        sinfo.src_port = dinfo.dst_port;
        sinfo.dst_port = dinfo.src_port;
        sinfo.new_dst_ip = dinfo.new_src_ip;

        conn_info.my_id = u2r_get_true_random_number_nz();
        ctx->has_client = 1;

        u2r_mylog(log_info, "created new conn,my_id is %x\n", conn_info.my_id);
        conn_info.state.server_current_state = server_handshake1;
        conn_info.last_state_time = u2r_get_current_time();

        my_id_t tmp_oppsite_id;
        memcpy(&tmp_oppsite_id, &raw_data[0], sizeof(tmp_oppsite_id));
        tmp_oppsite_id = ntohl(tmp_oppsite_id);

        sinfo.seq = dinfo.ack_seq;
        sinfo.ack_seq = dinfo.seq + rinfo.recv_info.data_len;
        sinfo.ts_ack = dinfo.ts;

        u2r_send_handshake(rinfo, conn_info.my_id, tmp_oppsite_id, u2r_const_id);
        u2r_mylog(log_info, "changed state to server_handshake1\n");
        return 0;
    }

    u2r_conn_info_t &conn_info = ctx->conn_info;
    u2r_raw_info_t &rinfo = conn_info.raw_info;

    if (conn_info.state.server_current_state == server_handshake1) {
        if (u2r_recv_bare(rinfo, raw_data, data_len) != 0) return -1;
        if (data_len < int(3 * sizeof(my_id_t))) return -1;

        my_id_t tmp_oppsite_id;
        memcpy(&tmp_oppsite_id, &raw_data[0], sizeof(tmp_oppsite_id));
        tmp_oppsite_id = ntohl(tmp_oppsite_id);

        my_id_t tmp_my_id;
        memcpy(&tmp_my_id, &raw_data[sizeof(my_id_t)], sizeof(tmp_my_id));
        tmp_my_id = ntohl(tmp_my_id);

        if (tmp_my_id != conn_info.my_id) return -1;
        conn_info.oppsite_id = tmp_oppsite_id;

        my_id_t tmp_oppsite_const_id;
        memcpy(&tmp_oppsite_const_id, &raw_data[sizeof(my_id_t) * 2], sizeof(tmp_oppsite_const_id));
        tmp_oppsite_const_id = ntohl(tmp_oppsite_const_id);

        u2r_packet_info_t &sinfo = rinfo.send_info;
        u2r_packet_info_t &dinfo = rinfo.recv_info;
        sinfo.seq = dinfo.ack_seq;
        sinfo.ack_seq = dinfo.seq + rinfo.recv_info.data_len;
        sinfo.ts_ack = dinfo.ts;

        conn_info.prepare();
        conn_info.state.server_current_state = server_ready;
        conn_info.oppsite_const_id = tmp_oppsite_const_id;
        ctx->is_ready = 1;

        conn_info.last_hb_recv_time = u2r_get_current_time();
        conn_info.last_hb_sent_time = conn_info.last_hb_recv_time;

        if (u2r_hb_mode == 0)
            u2r_send_safer(conn_info, 'h', u2r_hb_buf, 0);
        else
            u2r_send_safer(conn_info, 'h', u2r_hb_buf, u2r_hb_len);

        u2r_mylog(log_info, "changed state to server_ready\n");
        conn_info.blob->anti_replay.re_init();
        return 0;
    }

    if (conn_info.state.server_current_state == server_ready) {
        vector<char> type_vec;
        vector<string> data_vec;
        u2r_recv_safer_multi(conn_info, type_vec, data_vec);
        if (data_vec.empty()) return -1;

        for (int i = 0; i < (int)type_vec.size(); i++) {
            char type = type_vec[i];
            char *d = (char *)data_vec[i].c_str();
            int d_len = data_vec[i].length();

            if (type == 'h' && d_len >= 0) {
                conn_info.last_hb_recv_time = u2r_get_current_time();
                continue;
            }
            if (type == 'd' && d_len >= int(sizeof(u32_t))) {
                my_id_t tmp_conv_id;
                memcpy(&tmp_conv_id, &d[0], sizeof(tmp_conv_id));
                tmp_conv_id = ntohl(tmp_conv_id);

                if (u2r_hb_mode == 0)
                    conn_info.last_hb_recv_time = u2r_get_current_time();

                if (!conn_info.blob->conv_manager.s.is_conv_used(tmp_conv_id)) {
                    if (conn_info.blob->conv_manager.s.get_size() >= max_conv_num) continue;
                    conn_info.blob->conv_manager.s.insert_conv(tmp_conv_id, 0);
                }
                conn_info.blob->conv_manager.s.update_active_time(tmp_conv_id);

                int pkt_len = d_len - sizeof(u32_t);
                if (pkt_len > 0 && pkt_len <= max_len) {
                    memcpy(data, d + sizeof(u32_t), pkt_len);
                    return pkt_len;
                }
            }
        }
        return 0;
    }

    if (conn_info.state.server_current_state == server_idle) {
        u2r_discard_raw_packet();
        return 0;
    }
    return 0;
}

int raw_server_send_packet(raw_server_t *ctx, const char *data, int len) {
    if (!ctx->is_ready || !ctx->has_client) return -1;

    u2r_conn_info_t &conn_info = ctx->conn_info;
    u32_t conv = conn_info.blob->conv_manager.s.get_new_conv();
    conn_info.blob->conv_manager.s.insert_conv(conv, 0);
    conn_info.blob->conv_manager.s.update_active_time(conv);
    u2r_send_data_safer(conn_info, data, len, conv);
    return 0;
}

int raw_server_is_ready(raw_server_t *ctx) {
    return ctx->is_ready && ctx->has_client;
}

// Forward declarations
int tun_dev_raw_client_event_loop();
int tun_dev_raw_server_event_loop();
