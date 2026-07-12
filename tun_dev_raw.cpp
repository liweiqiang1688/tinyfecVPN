#include "u2r_prefix.h"

#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "encrypt.h"
#include "fd_manager.h"
#define aes_key_optimize 0

// udp2raw-specific globals from misc.cpp (NOT included).
// Use u2r_ prefix for globals that conflict with UDPspeeder.
raw_mode_t u2r_raw_mode = mode_faketcp;
u32_t raw_ip_version = (u32_t)-1;
int hb_mode = 1;
int hb_len = 1200;
char hb_buf[buf_len];
int u2r_mtu_warn = 1375;
int bind_addr_used = 0;
my_ip_t bind_addr;
int ttl_value = 64;
int u2r_about_to_exit = 0;
my_id_t const_id = 0;
int bind_fd = -1;
int force_source_ip = 0;
int force_source_port = 0;
int source_port = -1;
int fail_time_counter = 0;
int debug_flag = 0;
int keep_thread_running = 0;
int max_rst_allowed = -1;
int max_rst_to_show = 15;
int enable_dns_resolve = 0;
pthread_t keep_thread;
u64_t keep_rule_last_time = 0;
int force_socket_buf = 0;

// Stub functions from misc.cpp needed at link time (unused in our wrapper)
int keep_iptables_rule() { return 0; }
int clear_iptables_rule() { return 0; }
int iptables_rule_init(const char *, u32_t, int) { return 0; }
int iptables_gen_add(const char *, u32_t) { return 0; }
void iptables_rule() {}
int process_lower_level_arg() { return 0; }
int handle_lower_level(raw_info_t &) { return 0; }

// Stub functions from common.cpp (needed by network.cpp lower_level code)
int read_file(const char *, string &) { return -1; }
vector<vector<string>> string_to_vec2(const char *) { return {}; }
int hex_to_u32(const string &, u32_t &) { return -1; }
int hex_to_u32_with_endian(const string &, u32_t &) { return -1; }
unsigned short csum_with_header(char *, int, const unsigned short *, int) { return 0; }
bool larger_than_u32(u32_t a, u32_t b) { return a > b; }
bool larger_than_u16(u16_t a, u16_t b) { return a > b; }
u64_t hton64(u64_t a) {
    u32_t h = (u32_t)(a >> 32);
    u32_t l = (u32_t)(a & 0xffffffff);
    return ((u64_t)htonl(l) << 32) | htonl(h);
}
u64_t ntoh64(u64_t a) {
    return hton64(a);
}
void print_binary_chars(const char *, int) {}

// Provide missing functions from common.cpp (NOT included).
// These are needed by network.cpp/connection.cpp but not in UDPspeeder.

static int random_number_fd = -1;
u32_t get_true_random_number() {
    if (random_number_fd == -1) {
        random_number_fd = open("/dev/urandom", O_RDONLY);
        setnonblocking(random_number_fd);
    }
    u32_t ret;
    if (read(random_number_fd, &ret, sizeof(ret)) != sizeof(ret)) return rand();
    return ret;
}
u32_t get_true_random_number_nz() {
    u32_t ret = 0;
    while (ret == 0) ret = get_true_random_number();
    return ret;
}
u64_t get_true_random_number_64() {
    u64_t ret;
    if (random_number_fd == -1) {
        random_number_fd = open("/dev/urandom", O_RDONLY);
        setnonblocking(random_number_fd);
    }
    if (read(random_number_fd, &ret, sizeof(ret)) != sizeof(ret)) return ((u64_t)rand() << 32) | rand();
    return ret;
}

bool my_ip_t::equal(const my_ip_t &b) const {
    if (raw_ip_version == AF_INET) return v4 == b.v4;
    else if (raw_ip_version == AF_INET6) return memcmp(&v6, &b.v6, sizeof(v6)) == 0;
    return false;
}
int my_ip_t::from_address_t(address_t a) {
    if (a.get_type() == raw_ip_version && raw_ip_version == AF_INET) v4 = a.inner.ipv4.sin_addr.s_addr;
    else if (a.get_type() == raw_ip_version && raw_ip_version == AF_INET6) v6 = a.inner.ipv6.sin6_addr;
    return 0;
}
char *my_ip_t::get_str1() const {
    static char res[max_addr_len];
    if (raw_ip_version == AF_INET) inet_ntop(AF_INET, &v4, res, max_addr_len);
    else inet_ntop(AF_INET6, &v6, res, max_addr_len);
    return res;
}
char *my_ip_t::get_str2() const {
    static char res[max_addr_len];
    if (raw_ip_version == AF_INET) inet_ntop(AF_INET, &v4, res, max_addr_len);
    else inet_ntop(AF_INET6, &v6, res, max_addr_len);
    return res;
}
int numbers_to_char(my_id_t id1, my_id_t id2, my_id_t id3, char *&data, int &len) {
    static char buf[buf_len];
    data = buf;
    my_id_t tmp = htonl(id1);
    memcpy(buf, &tmp, sizeof(tmp));
    tmp = htonl(id2);
    memcpy(buf + sizeof(tmp), &tmp, sizeof(tmp));
    tmp = htonl(id3);
    memcpy(buf + sizeof(tmp) * 2, &tmp, sizeof(tmp));
    len = sizeof(my_id_t) * 3;
    return 0;
}
int char_to_numbers(const char *data, int len, my_id_t &id1, my_id_t &id2, my_id_t &id3) {
    if (len < int(sizeof(my_id_t) * 3)) return -1;
    memcpy(&id1, data + 0, sizeof(id1)); id1 = ntohl(id1);
    memcpy(&id2, data + sizeof(my_id_t), sizeof(id2)); id2 = ntohl(id2);
    memcpy(&id3, data + sizeof(my_id_t) * 2, sizeof(id3)); id3 = ntohl(id3);
    return 0;
}

// Include udp2raw source files (common.cpp excluded)
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

#undef conn_info_t
#undef blob_t
#undef conn_manager_t
#undef conv_manager_t
#undef anti_replay_t
#undef lru_collector_t
#undef conn_manager
#undef random_drop
#undef raw_mode
#undef mtu_warn
#undef about_to_exit
#undef server_clear_function
#undef crc32h

#include "tun_dev_raw.h"

struct raw_client_t { u2r_conn_info_t conn_info; int is_ready; };
struct raw_server_t { u2r_conn_info_t conn_info; int is_ready; int has_client; };

raw_client_t *raw_client_init(const char *remote_addr_str, const char *local_addr_str,
                               const char *key, const char *dev_name) {
    raw_client_t *ctx = new raw_client_t();
    ctx->is_ready = 0;
    extern address_t remote_addr, local_addr;
    extern program_mode_t program_mode;
    extern char key_string[1000];
    remote_addr.from_str((char *)remote_addr_str);
    local_addr.from_str((char *)local_addr_str);
    program_mode = client_mode;
    u2r_raw_mode = mode_faketcp;
    raw_ip_version = remote_addr.get_type();
    use_tcp_dummy_socket = 0;
    if (key && key[0]) strncpy(key_string, key, sizeof(key_string) - 1);
    if (dev_name && dev_name[0]) strncpy(dev, dev_name, sizeof(dev) - 1);

    srand(get_true_random_number_nz());
    const_id = get_true_random_number_nz();
    my_init_keys(key_string, 1);
    return ctx;
}
void raw_client_destroy(raw_client_t *ctx) { if (ctx) delete ctx; }
int raw_client_get_raw_recv_fd(raw_client_t *) { return raw_recv_fd; }

int raw_client_start(raw_client_t *ctx) {
    extern address_t remote_addr;
    lower_level = 0; init_raw_socket();
    u2r_conn_info_t &c = ctx->conn_info;
    c.my_id = get_true_random_number_nz(); c.prepare();
    packet_info_t &si = c.raw_info.send_info;
    si.new_dst_ip.from_address_t(remote_addr);
    si.dst_port = remote_addr.get_port();
    address_t tmp;
    if (get_src_adress2(tmp, remote_addr) != 0) return -1;
    si.new_src_ip.from_address_t(tmp);
    si.src_port = client_bind_to_a_new_port2(bind_fd, tmp);
    init_filter(si.src_port);
    c.state.client_current_state = client_tcp_handshake;
    c.last_state_time = get_current_time(); c.last_hb_sent_time = 0;
    si.syn = 1; si.ack = 0; si.psh = 0;
    si.seq = get_true_random_number(); si.ack_seq = get_true_random_number();
    send_raw0(c.raw_info, 0, 0);
    return 0;
}

void raw_client_on_timer(raw_client_t *ctx) {
    u2r_conn_info_t &c = ctx->conn_info;
    packet_info_t &si = c.raw_info.send_info, &ri = c.raw_info.recv_info;
    raw_info_t &raw = c.raw_info;
    c.blob->conv_manager.c.clear_inactive();
    if (raw.disabled) { c.state.client_current_state = client_idle; c.my_id = get_true_random_number_nz(); return; }
    if (c.state.client_current_state == client_idle) {
        raw.rst_received = 0; raw.disabled = 0; ctx->is_ready = 0;
        c.blob->anti_replay.re_init(); c.my_id = get_true_random_number_nz();
        address_t t; if (get_src_adress2(t, remote_addr) != 0) return;
        si.new_src_ip.from_address_t(t);
        si.src_port = client_bind_to_a_new_port2(bind_fd, t); init_filter(si.src_port);
        c.state.client_current_state = client_tcp_handshake;
        c.last_state_time = get_current_time(); c.last_hb_sent_time = 0;
        si.syn = 1; si.ack = 0; si.psh = 0;
        si.seq = get_true_random_number(); si.ack_seq = get_true_random_number();
        send_raw0(raw, 0, 0); return;
    }
    if (c.state.client_current_state == client_tcp_handshake) {
        if (get_current_time() - c.last_state_time > client_handshake_timeout) { c.state.client_current_state = client_idle; return; }
        if (get_current_time() - c.last_hb_sent_time > client_retry_interval) {
            if (c.last_hb_sent_time == 0) { si.psh = 0; si.syn = 1; si.ack = 0; si.ts_ack = 0; si.seq = get_true_random_number(); si.ack_seq = get_true_random_number(); }
            send_raw0(raw, 0, 0); c.last_hb_sent_time = get_current_time();
        } return;
    }
    if (c.state.client_current_state == client_handshake1) {
        if (get_current_time() - c.last_state_time > client_handshake_timeout) { c.state.client_current_state = client_idle; return; }
        if (get_current_time() - c.last_hb_sent_time > client_retry_interval) {
            if (c.last_hb_sent_time == 0) { si.seq++; si.ack_seq = ri.seq + 1; si.ts_ack = ri.ts; raw.reserved_send_seq = si.seq; }
            si.seq = raw.reserved_send_seq; si.psh = 0; si.syn = 0; si.ack = 1;
            send_raw0(raw, 0, 0); send_handshake(raw, c.my_id, 0, const_id);
            si.seq += raw.send_info.data_len; c.last_hb_sent_time = get_current_time();
        } return;
    }
    if (c.state.client_current_state == client_handshake2) {
        if (get_current_time() - c.last_state_time > client_handshake_timeout) { c.state.client_current_state = client_idle; return; }
        if (get_current_time() - c.last_hb_sent_time > client_retry_interval) {
            if (c.last_hb_sent_time == 0) { si.ack_seq = ri.seq + raw.recv_info.data_len; si.ts_ack = ri.ts; raw.reserved_send_seq = si.seq; }
            si.seq = raw.reserved_send_seq;
            send_handshake(raw, c.my_id, c.oppsite_id, const_id);
            si.seq += raw.send_info.data_len; c.last_hb_sent_time = get_current_time();
        } return;
    }
    if (c.state.client_current_state == client_ready) {
        if (get_current_time() - c.last_hb_recv_time > client_conn_timeout) { c.state.client_current_state = client_idle; c.my_id = get_true_random_number_nz(); ctx->is_ready = 0; return; }
        if (get_current_time() - c.last_oppsite_roller_time > client_conn_uplink_timeout) { c.state.client_current_state = client_idle; c.my_id = get_true_random_number_nz(); ctx->is_ready = 0; return; }
        if (get_current_time() - c.last_hb_sent_time < heartbeat_interval) return;
        if (hb_mode == 0) send_safer(c, 'h', hb_buf, 0); else send_safer(c, 'h', hb_buf, hb_len);
        c.last_hb_sent_time = get_current_time();
    }
}

int raw_client_recv_packet(raw_client_t *ctx, char *data, int max_len) {
    u2r_conn_info_t &c = ctx->conn_info;
    raw_info_t &raw = c.raw_info; packet_info_t &si = raw.send_info, &ri = raw.recv_info;
    if (raw_recv_fd < 0) return -1;
    int dl; char *rd; if (pre_recv_raw_packet() < 0) return -1;
    if (c.state.client_current_state == client_idle) { discard_raw_packet(); return 0; }
    if (c.state.client_current_state == client_tcp_handshake) {
        if (recv_raw0(raw, rd, dl) < 0) return -1;
        if (dl >= max_data_len + 1) return -1;
        if (!ri.new_src_ip.equal(si.new_dst_ip) || ri.src_port != si.dst_port) return -1;
        if (dl == 0 && raw.recv_info.syn == 1 && raw.recv_info.ack == 1) {
            if (ri.ack_seq != si.seq + 1) return -1;
            c.state.client_current_state = client_handshake1;
            c.last_state_time = get_current_time(); c.last_hb_sent_time = 0;
            raw_client_on_timer(ctx); return 0;
        } return -1;
    }
    if (c.state.client_current_state == client_handshake1) {
        if (recv_bare(raw, rd, dl) != 0) return -1;
        if (!ri.new_src_ip.equal(si.new_dst_ip) || ri.src_port != si.dst_port) return -1;
        if (dl < int(3 * sizeof(my_id_t))) return -1;
        my_id_t o, m; memcpy(&o, &rd[0], sizeof(o)); o = ntohl(o);
        memcpy(&m, &rd[sizeof(my_id_t)], sizeof(m)); m = ntohl(m);
        if (m != c.my_id) return -1;
        if (ri.ack_seq != si.seq || ri.seq != si.ack_seq) return -1;
        c.oppsite_id = o; c.state.client_current_state = client_handshake2;
        c.last_state_time = get_current_time(); c.last_hb_sent_time = 0;
        raw_client_on_timer(ctx); return 0;
    }
    if (c.state.client_current_state == client_handshake2 || c.state.client_current_state == client_ready) {
        vector<char> tv; vector<string> dv; recv_safer_multi(c, tv, dv);
        if (dv.empty()) return -1;
        for (int i = 0; i < (int)tv.size(); i++) {
            char t = tv[i]; char *d = (char *)dv[i].c_str(); int l = dv[i].length();
            if (c.state.client_current_state == client_handshake2) {
                c.state.client_current_state = client_ready; ctx->is_ready = 1;
                c.last_hb_sent_time = 0; c.last_hb_recv_time = get_current_time();
                c.last_oppsite_roller_time = c.last_hb_recv_time; raw_client_on_timer(ctx);
            }
            if (t == 'h') { c.last_hb_recv_time = get_current_time(); continue; }
            if (t == 'd' && l >= int(sizeof(u32_t))) {
                if (hb_mode == 0) c.last_hb_recv_time = get_current_time();
                u32_t cid; memcpy(&cid, &d[0], sizeof(cid)); cid = ntohl(cid);
                if (!c.blob->conv_manager.c.is_conv_used(cid)) continue;
                c.blob->conv_manager.c.update_active_time(cid);
                int pl = l - sizeof(u32_t);
                if (pl > 0 && pl <= max_len) { memcpy(data, d + sizeof(u32_t), pl); return pl; }
            }
        } return 0;
    }
    discard_raw_packet(); return 0;
}

int raw_client_send_packet(raw_client_t *ctx, const char *data, int len) {
    if (!ctx->is_ready) return -1;
    u2r_conn_info_t &c = ctx->conn_info;
    u32_t conv = c.blob->conv_manager.c.get_new_conv();
    c.blob->conv_manager.c.insert_conv(conv, remote_addr);
    c.blob->conv_manager.c.update_active_time(conv);
    send_data_safer(c, data, len, conv);
    return 0;
}
int raw_client_is_ready(raw_client_t *ctx) { return ctx->is_ready; }

// ---- Server ----
raw_server_t *raw_server_init(const char *local_addr_str, const char *key, const char *dev_name) {
    raw_server_t *ctx = new raw_server_t(); ctx->is_ready = 0; ctx->has_client = 0;
    extern address_t local_addr; extern program_mode_t program_mode; extern char key_string[1000];
    local_addr.from_str((char *)local_addr_str);
    program_mode = server_mode; u2r_raw_mode = mode_faketcp; raw_ip_version = local_addr.get_type();
    if (key && key[0]) strncpy(key_string, key, sizeof(key_string) - 1);
    if (dev_name && dev_name[0]) strncpy(dev, dev_name, sizeof(dev) - 1);
    srand(get_true_random_number_nz()); const_id = get_true_random_number_nz();
    my_init_keys(key_string, 0);
    return ctx;
}
void raw_server_destroy(raw_server_t *ctx) { if (ctx) delete ctx; }
int raw_server_get_raw_recv_fd(raw_server_t *) { return raw_recv_fd; }

int raw_server_start(raw_server_t *) {
    extern address_t local_addr;
    lower_level = 0;     init_raw_socket();
    bind_fd = socket(local_addr.get_type(), SOCK_STREAM, 0);
    if (bind(bind_fd, (struct sockaddr *)&local_addr.inner, local_addr.get_len()) != 0) exit(1);
    if (listen(bind_fd, SOMAXCONN) != 0) exit(1);
    init_filter(local_addr.get_port());
    return 0;
}
void raw_server_on_timer(raw_server_t *ctx) {
    if (!ctx->has_client || !ctx->is_ready) return;
    u2r_conn_info_t &c = ctx->conn_info;
    c.blob->conv_manager.s.clear_inactive((char *)"");
    if (c.state.server_current_state == server_ready) {
        if (get_current_time() - c.last_hb_sent_time < heartbeat_interval) return;
        if (hb_mode == 0) send_safer(c, 'h', hb_buf, 0);
        else send_safer(c, 'h', hb_buf, hb_len);
        c.last_hb_sent_time = get_current_time();
    }
}
int raw_server_recv_packet(raw_server_t *ctx, char *data, int max_len) {
    if (raw_recv_fd < 0) return -1;
    raw_info_t pk; pk.peek = 1; packet_info_t &pi = pk.recv_info;
    if (pre_recv_raw_packet() < 0) return -1;
    if (peek_raw(pk) < 0) { discard_raw_packet(); return -1; }
    int dl; char *rd;
    address_t addr; addr.from_ip_port_new(raw_ip_version, &pi.new_src_ip, pi.src_port);
    if (pi.syn == 1) {
        if (!ctx->has_client || ctx->conn_info.state.server_current_state != server_ready) {
            raw_info_t t; if (recv_raw0(t, rd, dl) < 0) return 0;
            if (dl >= max_data_len + 1) return -1;
            packet_info_t &ss = t.send_info, &rs = t.recv_info;
            ss.new_src_ip = rs.new_dst_ip; ss.src_port = rs.dst_port;
            ss.dst_port = rs.src_port; ss.new_dst_ip = rs.new_src_ip;
            if (dl == 0 && t.recv_info.syn == 1 && t.recv_info.ack == 0) {
                ss.ack_seq = rs.seq + 1; ss.psh = 0; ss.syn = 1; ss.ack = 1; ss.ts_ack = rs.ts;
                send_raw0(t, 0, 0);
            }
        } else discard_raw_packet();
        return 0;
    }
    if (!ctx->has_client) {
        raw_info_t t; if (recv_bare(t, rd, dl) < 0) return 0;
        if (dl < int(3 * sizeof(my_id_t))) return -1;
        my_id_t z; memcpy(&z, &rd[sizeof(my_id_t)], sizeof(z)); z = ntohl(z);
        if (z != 0) return -1;
        ctx->conn_info.raw_info = t;
        u2r_conn_info_t &cn = ctx->conn_info;
        raw_info_t &ri = cn.raw_info;
        packet_info_t &ss = ri.send_info, &rs = ri.recv_info;
        ss.new_src_ip = rs.new_dst_ip; ss.src_port = rs.dst_port;
        ss.dst_port = rs.src_port; ss.new_dst_ip = rs.new_src_ip;
        cn.my_id = get_true_random_number_nz(); ctx->has_client = 1;
        cn.state.server_current_state = server_handshake1;
        cn.last_state_time = get_current_time();
        my_id_t o; memcpy(&o, &rd[0], sizeof(o)); o = ntohl(o);
        ss.seq = rs.ack_seq; ss.ack_seq = rs.seq + ri.recv_info.data_len; ss.ts_ack = rs.ts;
        send_handshake(ri, cn.my_id, o, const_id);
        return 0;
    }
    u2r_conn_info_t &cn = ctx->conn_info;
    raw_info_t &ri = cn.raw_info;
    if (cn.state.server_current_state == server_handshake1) {
        if (recv_bare(ri, rd, dl) != 0) return -1;
        if (dl < int(3 * sizeof(my_id_t))) return -1;
        my_id_t o, m, oc;
        memcpy(&o, &rd[0], sizeof(o)); o = ntohl(o);
        memcpy(&m, &rd[sizeof(my_id_t)], sizeof(m)); m = ntohl(m);
        if (m != cn.my_id) return -1;
        cn.oppsite_id = o;
        memcpy(&oc, &rd[sizeof(my_id_t)*2], sizeof(oc)); oc = ntohl(oc);
        packet_info_t &ss = ri.send_info, &rs = ri.recv_info;
        ss.seq = rs.ack_seq; ss.ack_seq = rs.seq + ri.recv_info.data_len; ss.ts_ack = rs.ts;
        cn.prepare(); cn.state.server_current_state = server_ready;
        cn.oppsite_const_id = oc; ctx->is_ready = 1;
        cn.last_hb_recv_time = get_current_time(); cn.last_hb_sent_time = cn.last_hb_recv_time;
        if (hb_mode == 0) send_safer(cn, 'h', hb_buf, 0);
        else send_safer(cn, 'h', hb_buf, hb_len);
        cn.blob->anti_replay.re_init();
        return 0;
    }
    if (cn.state.server_current_state == server_ready) {
        vector<char> tv; vector<string> dv; recv_safer_multi(cn, tv, dv);
        if (dv.empty()) return -1;
        for (int i = 0; i < (int)tv.size(); i++) {
            char t = tv[i]; char *d = (char *)dv[i].c_str(); int l = dv[i].length();
            if (t == 'h') { cn.last_hb_recv_time = get_current_time(); continue; }
            if (t == 'd' && l >= int(sizeof(u32_t))) {
                my_id_t cid; memcpy(&cid, &d[0], sizeof(cid)); cid = ntohl(cid);
                if (hb_mode == 0) cn.last_hb_recv_time = get_current_time();
                if (!cn.blob->conv_manager.s.is_conv_used(cid)) {
                    if (cn.blob->conv_manager.s.get_size() >= max_conv_num) continue;
                    cn.blob->conv_manager.s.insert_conv(cid, 0);
                }
                cn.blob->conv_manager.s.update_active_time(cid);
                int pl = l - sizeof(u32_t);
                if (pl > 0 && pl <= max_len) { memcpy(data, d + sizeof(u32_t), pl); return pl; }
            }
        } return 0;
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
