#include "u2r_prefix.h"

#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "encrypt.h"
#include "fd_manager.h"

// Declare udp2raw-specific globals from misc.cpp (NOT included)
raw_mode_t raw_mode = mode_faketcp;
u32_t raw_ip_version = (u32_t)-1;
int hb_mode = 1;
int hb_len = 1200;
char hb_buf[buf_len];
int mtu_warn = 1375;
int bind_addr_used = 0;
my_ip_t bind_addr;
int ttl_value = 64;
int about_to_exit = 0;
my_id_t const_id = 0;
int bind_fd = -1;
int force_source_ip = 0;
int force_source_port = 0;
int source_port = -1;
int fail_time_counter = 0;
int debug_flag = 0;
int keep_thread_running = 0;

// Include common.cpp with renamed functions to get get_true_random_number etc.
// But we must rename functions that are ALSO in UDPspeeder to avoid conflicts.
#define get_current_time       u2r_get_current_time
#define get_current_time_us    u2r_get_current_time_us
#define setnonblocking         u2r_setnonblocking
#define set_buf_size           u2r_set_buf_size
#define get_sock_error         u2r_get_sock_error
#define get_sock_errno         u2r_get_sock_errno
#define create_fifo            u2r_create_fifo
#define myexit                 u2r_myexit
#define my_ntoa                u2r_my_ntoa
#define pack_u64               u2r_pack_u64
#define get_u64_h              u2r_get_u64_h
#define get_u64_l              u2r_get_u64_l
#define read_file              u2r_read_file
#define string_to_vec          u2r_string_to_vec
#define string_to_vec2         u2r_string_to_vec2
#define hex_to_u32             u2r_hex_to_u32
#define hex_to_u32_with_endian u2r_hex_to_u32_with_endian
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
#define djb2                   u2r_djb2
#define sdbm                   u2r_sdbm
#define init_random_number_fd  u2r_init_random_number_fd
#define new_connected_udp_fd   u2r_new_connected_udp_fd

#include "common.cpp"
// Include network.cpp, connection.cpp — their functions use the
// common.cpp functions (some renamed, some not).
#include "network.cpp"
#include "connection.cpp"
#include "encrypt.cpp"
#include "lib/md5.cpp"
#include "lib/pbkdf2-sha1.cpp"
#include "lib/pbkdf2-sha256.cpp"
#define polarssl_zeroize polarssl_zeroize_aes
#include "lib/aes_faster_c/aes.cpp"
#include "lib/aes_faster_c/wrapper.cpp"
#undef polarssl_zeroize

// Undef function renames — now common.cpp funcs are u2r_ prefixed,
// but get_true_random_number etc. keep their original names.
#undef get_current_time
#undef get_current_time_us
#undef setnonblocking
#undef set_buf_size
#undef get_sock_error
#undef get_sock_errno
#undef create_fifo
#undef myexit
#undef my_ntoa
#undef pack_u64
#undef get_u64_h
#undef get_u64_l
#undef read_file
#undef string_to_vec
#undef string_to_vec2
#undef hex_to_u32
#undef hex_to_u32_with_endian
#undef csum
#undef csum_with_header
#undef larger_than_u32
#undef larger_than_u16
#undef numbers_to_char
#undef char_to_numbers
#undef hton64
#undef ntoh64
#undef print_binary_chars
#undef run_command
#undef trim
#undef trim_conf_line
#undef parse_conf_line
#undef djb2
#undef sdbm
#undef init_random_number_fd
#undef new_connected_udp_fd

// Undef type renames
#undef conn_info_t
#undef blob_t
#undef conn_manager_t
#undef conv_manager_t
#undef anti_replay_t
#undef lru_collector_t

#include "tun_dev_raw.h"

struct raw_client_t {
    u2r_conn_info_t conn_info;
    int is_ready;
};

struct raw_server_t {
    u2r_conn_info_t conn_info;
    int is_ready;
    int has_client;
};

raw_client_t *raw_client_init(const char *remote_addr_str, const char *local_addr_str,
                               const char *key, const char *dev_name) {
    raw_client_t *ctx = new raw_client_t();
    ctx->is_ready = 0;

    extern address_t remote_addr, local_addr;
    extern program_mode_t program_mode;
    extern char key_string[1000];
    extern my_id_t const_id;

    remote_addr.from_str((char *)remote_addr_str);
    local_addr.from_str((char *)local_addr_str);

    program_mode = client_mode;
    raw_mode = mode_faketcp;
    raw_ip_version = remote_addr.get_type();
    use_tcp_dummy_socket = 0;

    if (key && key[0]) strncpy(key_string, key, sizeof(key_string) - 1);
    if (dev_name && dev_name[0]) strncpy(dev, dev_name, sizeof(dev) - 1);

    srand(get_true_random_number_nz());
    const_id = get_true_random_number_nz();
    my_init_keys(key_string, 1);

    mylog(log_info, "raw_client_init done\n");
    return ctx;
}

void raw_client_destroy(raw_client_t *ctx) { if (ctx) delete ctx; }
int raw_client_get_raw_recv_fd(raw_client_t *) { return raw_recv_fd; }

int raw_client_start(raw_client_t *ctx) {
    extern address_t remote_addr;
    extern int bind_fd;

    lower_level = 0;
    init_raw_socket();

    u2r_conn_info_t &conn_info = ctx->conn_info;
    conn_info.my_id = get_true_random_number_nz();
    conn_info.prepare();

    packet_info_t &send_info = conn_info.raw_info.send_info;
    send_info.new_dst_ip.from_address_t(remote_addr);
    send_info.dst_port = remote_addr.get_port();

    address_t tmp_addr;
    if (get_src_adress2(tmp_addr, remote_addr) != 0) {
        mylog(log_warn, "get_src_adress() failed\n");
        return -1;
    }
    send_info.new_src_ip.from_address_t(tmp_addr);
    send_info.src_port = client_bind_to_a_new_port2(bind_fd, tmp_addr);
    init_filter(send_info.src_port);

    conn_info.state.client_current_state = client_tcp_handshake;
    conn_info.last_state_time = get_current_time();
    conn_info.last_hb_sent_time = 0;

    send_info.syn = 1; send_info.ack = 0; send_info.psh = 0;
    send_info.seq = get_true_random_number();
    send_info.ack_seq = get_true_random_number();
    send_raw0(conn_info.raw_info, 0, 0);

    mylog(log_info, "raw_client_start: sent syn\n");
    return 0;
}

void raw_client_on_timer(raw_client_t *ctx) {
    u2r_conn_info_t &conn = ctx->conn_info;
    packet_info_t &si = conn.raw_info.send_info;
    packet_info_t &ri = conn.raw_info.recv_info;
    raw_info_t &raw = conn.raw_info;

    conn.blob->conv_manager.c.clear_inactive();

    if (raw.disabled) {
        conn.state.client_current_state = client_idle;
        conn.my_id = get_true_random_number_nz();
        return;
    }

    if (conn.state.client_current_state == client_idle) {
        raw.rst_received = 0; raw.disabled = 0; ctx->is_ready = 0;
        conn.blob->anti_replay.re_init();
        conn.my_id = get_true_random_number_nz();
        address_t tmp;
        if (get_src_adress2(tmp, remote_addr) != 0) return;
        si.new_src_ip.from_address_t(tmp);
        si.src_port = client_bind_to_a_new_port2(bind_fd, tmp);
        init_filter(si.src_port);
        conn.state.client_current_state = client_tcp_handshake;
        conn.last_state_time = get_current_time();
        conn.last_hb_sent_time = 0;
        si.syn = 1; si.ack = 0; si.psh = 0;
        si.seq = get_true_random_number();
        si.ack_seq = get_true_random_number();
        send_raw0(raw, 0, 0);
        return;
    }

    if (conn.state.client_current_state == client_tcp_handshake) {
        if (get_current_time() - conn.last_state_time > client_handshake_timeout) {
            conn.state.client_current_state = client_idle;
            return;
        }
        if (get_current_time() - conn.last_hb_sent_time > client_retry_interval) {
            if (conn.last_hb_sent_time == 0) {
                si.psh = 0; si.syn = 1; si.ack = 0; si.ts_ack = 0;
                si.seq = get_true_random_number();
                si.ack_seq = get_true_random_number();
            }
            send_raw0(raw, 0, 0);
            conn.last_hb_sent_time = get_current_time();
        }
        return;
    }

    if (conn.state.client_current_state == client_handshake1) {
        if (get_current_time() - conn.last_state_time > client_handshake_timeout) {
            conn.state.client_current_state = client_idle;
            return;
        }
        if (get_current_time() - conn.last_hb_sent_time > client_retry_interval) {
            if (conn.last_hb_sent_time == 0) {
                si.seq++; si.ack_seq = ri.seq + 1;
                si.ts_ack = ri.ts; raw.reserved_send_seq = si.seq;
            }
            si.seq = raw.reserved_send_seq;
            si.psh = 0; si.syn = 0; si.ack = 1;
            send_raw0(raw, 0, 0);
            send_handshake(raw, conn.my_id, 0, const_id);
            si.seq += raw.send_info.data_len;
            conn.last_hb_sent_time = get_current_time();
        }
        return;
    }

    if (conn.state.client_current_state == client_handshake2) {
        if (get_current_time() - conn.last_state_time > client_handshake_timeout) {
            conn.state.client_current_state = client_idle;
            return;
        }
        if (get_current_time() - conn.last_hb_sent_time > client_retry_interval) {
            if (conn.last_hb_sent_time == 0) {
                si.ack_seq = ri.seq + raw.recv_info.data_len;
                si.ts_ack = ri.ts; raw.reserved_send_seq = si.seq;
            }
            si.seq = raw.reserved_send_seq;
            send_handshake(raw, conn.my_id, conn.oppsite_id, const_id);
            si.seq += raw.send_info.data_len;
            conn.last_hb_sent_time = get_current_time();
        }
        return;
    }

    if (conn.state.client_current_state == client_ready) {
        if (get_current_time() - conn.last_hb_recv_time > client_conn_timeout) {
            conn.state.client_current_state = client_idle;
            conn.my_id = get_true_random_number_nz();
            ctx->is_ready = 0;
            return;
        }
        if (get_current_time() - conn.last_oppsite_roller_time > client_conn_uplink_timeout) {
            conn.state.client_current_state = client_idle;
            conn.my_id = get_true_random_number_nz();
            ctx->is_ready = 0;
            return;
        }
        if (get_current_time() - conn.last_hb_sent_time < heartbeat_interval) return;
        if (hb_mode == 0) send_safer(conn, 'h', hb_buf, 0);
        else send_safer(conn, 'h', hb_buf, hb_len);
        conn.last_hb_sent_time = get_current_time();
    }
}

int raw_client_recv_packet(raw_client_t *ctx, char *data, int max_len) {
    u2r_conn_info_t &conn = ctx->conn_info;
    raw_info_t &raw = conn.raw_info;
    packet_info_t &si = raw.send_info, &ri = raw.recv_info;

    if (raw_recv_fd < 0) return -1;
    int data_len; char *raw_data;
    if (pre_recv_raw_packet() < 0) return -1;

    if (conn.state.client_current_state == client_idle) { discard_raw_packet(); return 0; }

    if (conn.state.client_current_state == client_tcp_handshake) {
        if (recv_raw0(raw, raw_data, data_len) < 0) return -1;
        if (data_len >= max_data_len + 1) return -1;
        if (!ri.new_src_ip.equal(si.new_dst_ip) || ri.src_port != si.dst_port) return -1;
        if (data_len == 0 && raw.recv_info.syn == 1 && raw.recv_info.ack == 1) {
            if (ri.ack_seq != si.seq + 1) return -1;
            mylog(log_info, "got syn-ack, moving to handshake1\n");
            conn.state.client_current_state = client_handshake1;
            conn.last_state_time = get_current_time();
            conn.last_hb_sent_time = 0;
            raw_client_on_timer(ctx);
            return 0;
        }
        return -1;
    }

    if (conn.state.client_current_state == client_handshake1) {
        if (recv_bare(raw, raw_data, data_len) != 0) return -1;
        if (!ri.new_src_ip.equal(si.new_dst_ip) || ri.src_port != si.dst_port) return -1;
        if (data_len < int(3 * sizeof(my_id_t))) return -1;

        my_id_t opp, my;
        memcpy(&opp, &raw_data[0], sizeof(opp)); opp = ntohl(opp);
        memcpy(&my, &raw_data[sizeof(my_id_t)], sizeof(my)); my = ntohl(my);
        if (my != conn.my_id) return -1;
        if (ri.ack_seq != si.seq) return -1;
        if (ri.seq != si.ack_seq) return -1;
        conn.oppsite_id = opp;
        conn.state.client_current_state = client_handshake2;
        conn.last_state_time = get_current_time();
        conn.last_hb_sent_time = 0;
        raw_client_on_timer(ctx);
        return 0;
    }

    if (conn.state.client_current_state == client_handshake2 ||
        conn.state.client_current_state == client_ready) {
        vector<char> type_vec; vector<string> data_vec;
        recv_safer_multi(conn, type_vec, data_vec);
        if (data_vec.empty()) return -1;

        for (int i = 0; i < (int)type_vec.size(); i++) {
            char type = type_vec[i]; char *d = (char *)data_vec[i].c_str(); int d_len = data_vec[i].length();

            if (conn.state.client_current_state == client_handshake2) {
                conn.state.client_current_state = client_ready;
                ctx->is_ready = 1;
                conn.last_hb_sent_time = 0;
                conn.last_hb_recv_time = get_current_time();
                conn.last_oppsite_roller_time = conn.last_hb_recv_time;
                raw_client_on_timer(ctx);
            }

            if (type == 'h') { conn.last_hb_recv_time = get_current_time(); continue; }
            if (type == 'd' && d_len >= int(sizeof(u32_t))) {
                if (hb_mode == 0) conn.last_hb_recv_time = get_current_time();
                u32_t conv_id; memcpy(&conv_id, &d[0], sizeof(conv_id)); conv_id = ntohl(conv_id);
                if (!conn.blob->conv_manager.c.is_conv_used(conv_id)) continue;
                conn.blob->conv_manager.c.update_active_time(conv_id);
                int pl = d_len - sizeof(u32_t);
                if (pl > 0 && pl <= max_len) { memcpy(data, d + sizeof(u32_t), pl); return pl; }
            }
        }
        return 0;
    }

    discard_raw_packet();
    return 0;
}

int raw_client_send_packet(raw_client_t *ctx, const char *data, int len) {
    if (!ctx->is_ready) return -1;
    u2r_conn_info_t &conn = ctx->conn_info;
    u32_t conv = conn.blob->conv_manager.c.get_new_conv();
    conn.blob->conv_manager.c.insert_conv(conv, remote_addr);
    conn.blob->conv_manager.c.update_active_time(conv);
    send_data_safer(conn, data, len, conv);
    return 0;
}

int raw_client_is_ready(raw_client_t *ctx) { return ctx->is_ready; }

// ---- Server ----

raw_server_t *raw_server_init(const char *local_addr_str, const char *key, const char *dev_name) {
    raw_server_t *ctx = new raw_server_t();
    ctx->is_ready = 0; ctx->has_client = 0;

    extern address_t local_addr;
    extern program_mode_t program_mode;
    extern char key_string[1000];
    extern my_id_t const_id;

    local_addr.from_str((char *)local_addr_str);
    program_mode = server_mode;
    raw_mode = mode_faketcp;
    raw_ip_version = local_addr.get_type();

    if (key && key[0]) strncpy(key_string, key, sizeof(key_string) - 1);
    if (dev_name && dev_name[0]) strncpy(dev, dev_name, sizeof(dev) - 1);

    srand(get_true_random_number_nz());
    const_id = get_true_random_number_nz();
    my_init_keys(key_string, 0);
    mylog(log_info, "raw_server_init done\n");
    return ctx;
}

void raw_server_destroy(raw_server_t *ctx) { if (ctx) delete ctx; }
int raw_server_get_raw_recv_fd(raw_server_t *) { return raw_recv_fd; }

int raw_server_start(raw_server_t *) {
    extern address_t local_addr;
    extern int bind_fd;

    lower_level = 0;
    init_raw_socket();
    bind_fd = socket(local_addr.get_type(), SOCK_STREAM, 0);
    if (bind(bind_fd, (struct sockaddr *)&local_addr.inner, local_addr.get_len()) != 0) {
        mylog(log_fatal, "bind fail\n"); myexit(-1);
    }
    if (listen(bind_fd, SOMAXCONN) != 0) {
        mylog(log_fatal, "listen fail\n"); myexit(-1);
    }
    init_filter(local_addr.get_port());
    mylog(log_info, "now listening at %s\n", local_addr.get_str());
    return 0;
}

void raw_server_on_timer(raw_server_t *ctx) {
    if (!ctx->has_client || !ctx->is_ready) return;
    u2r_conn_info_t &conn = ctx->conn_info;
    conn.blob->conv_manager.s.clear_inactive((char *)"");
    if (conn.state.server_current_state == server_ready) {
        if (get_current_time() - conn.last_hb_sent_time < heartbeat_interval) return;
        if (hb_mode == 0) send_safer(conn, 'h', hb_buf, 0);
        else send_safer(conn, 'h', hb_buf, hb_len);
        conn.last_hb_sent_time = get_current_time();
    }
}

int raw_server_recv_packet(raw_server_t *ctx, char *data, int max_len) {
    if (raw_recv_fd < 0) return -1;
    raw_info_t peek_raw_info; peek_raw_info.peek = 1;
    packet_info_t &peek_info = peek_raw_info.recv_info;
    if (pre_recv_raw_packet() < 0) return -1;
    if (peek_raw(peek_raw_info) < 0) { discard_raw_packet(); return -1; }
    int data_len; char *raw_data;
    address_t addr;
    addr.from_ip_port_new(raw_ip_version, &peek_info.new_src_ip, peek_info.src_port);
    if (peek_info.syn == 1) {
        if (!ctx->has_client || ctx->conn_info.state.server_current_state != server_ready) {
            raw_info_t tmp; if (recv_raw0(tmp, raw_data, data_len) < 0) return 0;
            if (data_len >= max_data_len + 1) return -1;
            packet_info_t &ss = tmp.send_info, &rs = tmp.recv_info;
            ss.new_src_ip = rs.new_dst_ip; ss.src_port = rs.dst_port;
            ss.dst_port = rs.src_port; ss.new_dst_ip = rs.new_src_ip;
            if (data_len == 0 && tmp.recv_info.syn == 1 && tmp.recv_info.ack == 0) {
                ss.ack_seq = rs.seq + 1; ss.psh = 0; ss.syn = 1; ss.ack = 1;
                ss.ts_ack = rs.ts; send_raw0(tmp, 0, 0);
                return 0;
            }
        } else { discard_raw_packet(); }
        return 0;
    }
    if (!ctx->has_client) {
        raw_info_t tmp; if (recv_bare(tmp, raw_data, data_len) < 0) return 0;
        if (data_len < int(3 * sizeof(my_id_t))) return -1;
        my_id_t z; memcpy(&z, &raw_data[sizeof(my_id_t)], sizeof(z)); z = ntohl(z);
        if (z != 0) return -1;
        ctx->conn_info.raw_info = tmp;
        u2r_conn_info_t &cn = ctx->conn_info;
        raw_info_t &ri = cn.raw_info;
        packet_info_t &ss = ri.send_info, &rs = ri.recv_info;
        ss.new_src_ip = rs.new_dst_ip; ss.src_port = rs.dst_port;
        ss.dst_port = rs.src_port; ss.new_dst_ip = rs.new_src_ip;
        cn.my_id = get_true_random_number_nz(); ctx->has_client = 1;
        cn.state.server_current_state = server_handshake1;
        cn.last_state_time = get_current_time();
        my_id_t oid; memcpy(&oid, &raw_data[0], sizeof(oid)); oid = ntohl(oid);
        ss.seq = rs.ack_seq; ss.ack_seq = rs.seq + ri.recv_info.data_len;
        ss.ts_ack = rs.ts;
        send_handshake(ri, cn.my_id, oid, const_id);
        return 0;
    }
    u2r_conn_info_t &cn = ctx->conn_info;
    raw_info_t &ri = cn.raw_info;
    if (cn.state.server_current_state == server_handshake1) {
        if (recv_bare(ri, raw_data, data_len) != 0) return -1;
        if (data_len < int(3 * sizeof(my_id_t))) return -1;
        my_id_t oid, mid, ocid;
        memcpy(&oid, &raw_data[0], sizeof(oid)); oid = ntohl(oid);
        memcpy(&mid, &raw_data[sizeof(my_id_t)], sizeof(mid)); mid = ntohl(mid);
        if (mid != cn.my_id) return -1;
        cn.oppsite_id = oid;
        memcpy(&ocid, &raw_data[sizeof(my_id_t)*2], sizeof(ocid)); ocid = ntohl(ocid);
        packet_info_t &ss = ri.send_info, &rs = ri.recv_info;
        ss.seq = rs.ack_seq; ss.ack_seq = rs.seq + ri.recv_info.data_len;
        ss.ts_ack = rs.ts;
        cn.prepare(); cn.state.server_current_state = server_ready;
        cn.oppsite_const_id = ocid; ctx->is_ready = 1;
        cn.last_hb_recv_time = get_current_time();
        cn.last_hb_sent_time = cn.last_hb_recv_time;
        if (hb_mode == 0) send_safer(cn, 'h', hb_buf, 0);
        else send_safer(cn, 'h', hb_buf, hb_len);
        cn.blob->anti_replay.re_init();
        return 0;
    }
    if (cn.state.server_current_state == server_ready) {
        vector<char> tv; vector<string> dv;
        recv_safer_multi(cn, tv, dv);
        if (dv.empty()) return -1;
        for (int i = 0; i < (int)tv.size(); i++) {
            char t = tv[i]; char *d = (char *)dv[i].c_str(); int dl = dv[i].length();
            if (t == 'h') { cn.last_hb_recv_time = get_current_time(); continue; }
            if (t == 'd' && dl >= int(sizeof(u32_t))) {
                my_id_t cid; memcpy(&cid, &d[0], sizeof(cid)); cid = ntohl(cid);
                if (hb_mode == 0) cn.last_hb_recv_time = get_current_time();
                if (!cn.blob->conv_manager.s.is_conv_used(cid)) {
                    if (cn.blob->conv_manager.s.get_size() >= max_conv_num) continue;
                    cn.blob->conv_manager.s.insert_conv(cid, 0);
                }
                cn.blob->conv_manager.s.update_active_time(cid);
                int pl = dl - sizeof(u32_t);
                if (pl > 0 && pl <= max_len) { memcpy(data, d + sizeof(u32_t), pl); return pl; }
            }
        }
        return 0;
    }
    if (cn.state.server_current_state == server_idle) { discard_raw_packet(); return 0; }
    return 0;
}

int raw_server_send_packet(raw_server_t *ctx, const char *data, int len) {
    if (!ctx->is_ready || !ctx->has_client) return -1;
    u2r_conn_info_t &cn = ctx->conn_info;
    u32_t conv = cn.blob->conv_manager.s.get_new_conv();
    cn.blob->conv_manager.s.insert_conv(conv, 0);
    cn.blob->conv_manager.s.update_active_time(conv);
    send_data_safer(cn, data, len, conv);
    return 0;
}

int raw_server_is_ready(raw_server_t *ctx) { return ctx->is_ready && ctx->has_client; }
