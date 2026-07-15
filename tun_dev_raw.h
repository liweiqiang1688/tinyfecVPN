#ifndef TUN_DEV_RAW_H_
#define TUN_DEV_RAW_H_

extern char raw_mode_key[1000];
extern int raw_cipher_mode_opt;
extern int raw_auth_mode_opt;
extern int raw_disable_anti_replay_opt;
extern int raw_hb_mode_opt;
extern int raw_hb_len_opt;

typedef struct raw_client_t raw_client_t;
typedef struct raw_server_t raw_server_t;

raw_client_t *raw_client_init(const char *remote_addr_str, const char *local_addr_str,
                               const char *key_string, const char *dev);
void raw_client_destroy(raw_client_t *ctx);
int raw_client_get_raw_recv_fd(raw_client_t *ctx);
int raw_client_start(raw_client_t *ctx);
void raw_client_on_timer(raw_client_t *ctx);
int raw_client_recv_packet(raw_client_t *ctx, char *data, int max_len);
int raw_client_send_packet(raw_client_t *ctx, const char *data, int len);
int raw_client_is_ready(raw_client_t *ctx);

raw_server_t *raw_server_init(const char *local_addr_str, const char *key_string, const char *dev);
void raw_server_destroy(raw_server_t *ctx);
int raw_server_get_raw_recv_fd(raw_server_t *ctx);
int raw_server_start(raw_server_t *ctx);
void raw_server_on_timer(raw_server_t *ctx);
int raw_server_recv_packet(raw_server_t *ctx, char *data, int max_len);
int raw_server_send_packet(raw_server_t *ctx, const char *data, int len);
int raw_server_is_ready(raw_server_t *ctx);

int tun_dev_raw_client_event_loop();
int tun_dev_raw_server_event_loop();

#endif
