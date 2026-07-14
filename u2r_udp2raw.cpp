// Separate compilation of all udp2raw sources with prefix macros.
// This avoids single-TU issues that cause encryption key mismatch.
#include "u2r_prefix.h"

#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "encrypt.h"
#include "fd_manager.h"

// Declare udp2raw-specific globals from misc.cpp (NOT included)
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

// Stub functions from misc.cpp
int keep_iptables_rule() { return 0; }
int clear_iptables_rule() { return 0; }
int iptables_rule_init(const char *, u32_t, int) { return 0; }
int iptables_gen_add(const char *, u32_t) { return 0; }
void iptables_rule() {}
int process_lower_level_arg() { return 0; }
int handle_lower_level(raw_info_t &) { return 0; }

// Stub functions from common.cpp
int read_file(const char *, string &) { return -1; }
vector<vector<string>> string_to_vec2(const char *) { return {}; }
int hex_to_u32(const string &, u32_t &) { return -1; }
int hex_to_u32_with_endian(const string &, u32_t &) { return -1; }
bool larger_than_u32(u32_t a, u32_t b) { return a > b; }
bool larger_than_u16(u16_t a, u16_t b) { return a > b; }
u64_t hton64(u64_t a) {
    u32_t h = (u32_t)(a >> 32);
    u32_t l = (u32_t)(a & 0xffffffff);
    return ((u64_t)htonl(l) << 32) | htonl(h);
}
u64_t ntoh64(u64_t a) { return hton64(a); }

unsigned short csum_with_header(char *header, int hlen, const unsigned short *ptr, int nbytes) {
    long sum = 0;
    assert(hlen % 2 == 0);
    unsigned short *tmp = (unsigned short *)header;
    for (int i = 0; i < hlen / 2; i++) sum += *tmp++;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) { unsigned short oddbyte = 0; *((u_char *)&oddbyte) = *(u_char *)ptr; sum += oddbyte; }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    return (unsigned short)(~sum);
}

// Missing functions from common.cpp
static int random_number_fd = -1;
u32_t get_true_random_number() {
    if (random_number_fd == -1) { random_number_fd = open("/dev/urandom", O_RDONLY); setnonblocking(random_number_fd); }
    u32_t ret;
    if (read(random_number_fd, &ret, sizeof(ret)) != sizeof(ret)) return rand();
    return ret;
}
u32_t get_true_random_number_nz() { u32_t ret = 0; while (ret == 0) ret = get_true_random_number(); return ret; }
u64_t get_true_random_number_64() {
    u64_t ret;
    if (random_number_fd == -1) { random_number_fd = open("/dev/urandom", O_RDONLY); setnonblocking(random_number_fd); }
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
    my_id_t tmp = htonl(id1); memcpy(buf, &tmp, sizeof(tmp));
    tmp = htonl(id2); memcpy(buf + sizeof(tmp), &tmp, sizeof(tmp));
    tmp = htonl(id3); memcpy(buf + sizeof(tmp) * 2, &tmp, sizeof(tmp));
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
void print_binary_chars(const char *a, int len) {
    for (int i = 0; i < len && i < 32; i++)
        fprintf(stderr, "<%02x>", (unsigned char)a[i]);
    fprintf(stderr, "\n");
}

// Include udp2raw source files (each gets its own static scope via include)
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
