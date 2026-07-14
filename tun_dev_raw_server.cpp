#include "tun_dev.h"
#include "tun_dev_raw.h"

static raw_server_t *raw_ctx = 0;
static int s_tun_fd = -1;

static void raw_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    char data[buf_len];
    int len = raw_server_recv_packet(raw_ctx, data, max_data_len + 1);

    if (len <= 0) return;

    mylog(log_trace, "Received packet from raw socket,len: %d\n", len);

    dest_t tun_dest;
    tun_dest.type = type_write_fd;
    tun_dest.inner.fd = s_tun_fd;

    from_fec_to_normal2(conn_info, tun_dest, data, len);
}

static void tun_fd_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    char data[buf_len];
    int len;

    assert(!(revents & EV_ERROR));

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);
    int tun_fd = watcher->fd;

    len = read(tun_fd, data, max_data_len + 1);

    if (len == max_data_len + 1) {
        mylog(log_warn, "huge packet, data_len > %d,dropped\n", max_data_len);
        return;
    }

    if (len < 0) {
        mylog(log_warn, "read from tun_fd return %d,errno=%s\n", len, strerror(errno));
        return;
    }

    do_mssfix(data, len);

    mylog(log_trace, "Received packet from tun,len: %d\n", len);

    if (!raw_server_is_ready(raw_ctx)) {
        mylog(log_debug, "received packet from tun,but there is no client yet,dropped packet\n");
        return;
    }

    int out_n;
    char **out_arr;
    int *out_len;
    my_time_t *out_delay;

    from_normal_to_fec(conn_info, data, len, out_n, out_arr, out_len, out_delay);

    for (int i = 0; i < out_n; i++) {
        raw_server_send_packet(raw_ctx, out_arr[i], out_len[i]);
    }
}

static void delay_manager_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));
}

static void fec_encode_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    mylog(log_trace, "fec_encode_cb() called\n");

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    if (!raw_server_is_ready(raw_ctx)) {
        return;
    }

    int out_n;
    char **out_arr;
    int *out_len;
    my_time_t *out_delay;

    from_normal_to_fec(conn_info, 0, 0, out_n, out_arr, out_len, out_delay);

    for (int i = 0; i < out_n; i++) {
        raw_server_send_packet(raw_ctx, out_arr[i], out_len[i]);
    }
}

static void fifo_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));
    int fifo_fd = watcher->fd;

    char buf[buf_len];
    int len = read(fifo_fd, buf, sizeof(buf));
    if (len < 0) {
        mylog(log_warn, "fifo read failed len=%d,errno=%s\n", len, strerror(errno));
        return;
    }
    buf[len] = 0;
    handle_command(buf);
}

static void conn_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    mylog(log_trace, "conn_timer_cb() called\n");

    raw_server_on_timer(raw_ctx);

    if (raw_server_is_ready(raw_ctx)) {
        conn_info.stat.report_as_server(local_addr);
    }
}

static void prepare_cb(struct ev_loop *loop, struct ev_prepare *watcher, int revents) {
    assert(!(revents & EV_ERROR));
    delay_manager.check();
}

int tun_dev_raw_server_event_loop() {
    int i, j, k, ret;
    int tun_fd;
    int raw_fd;

    conn_info_t *conn_info_p = new conn_info_t;
    conn_info_t &conn_info = *conn_info_p;

    const char *rk = raw_mode_key[0] ? raw_mode_key : key_string;
    raw_ctx = raw_server_init(local_addr.get_str(), rk, "");
    if (!raw_ctx) {
        mylog(log_fatal, "raw_server_init failed\n");
        myexit(-1);
    }

    tun_fd = get_tun_fd(tun_dev);
    assert(tun_fd > 0);
    s_tun_fd = tun_fd;

    assert(set_tun(tun_dev, htonl((ntohl(sub_net_uint32) & 0xFFFFFF00) | 1),
                   htonl((ntohl(sub_net_uint32) & 0xFFFFFF00) | 2), tun_mtu) == 0);

    if (raw_server_start(raw_ctx) < 0) {
        mylog(log_fatal, "raw_server_start failed\n");
        myexit(-1);
    }

    raw_fd = raw_server_get_raw_recv_fd(raw_ctx);

    struct ev_loop *loop = ev_default_loop(0);
    assert(loop != NULL);
    conn_info.loop = loop;

    struct ev_io raw_watcher;
    raw_watcher.data = &conn_info;
    ev_io_init(&raw_watcher, raw_recv_cb, raw_fd, EV_READ);
    ev_io_start(loop, &raw_watcher);

    struct ev_io tun_fd_watcher;
    tun_fd_watcher.data = &conn_info;
    ev_io_init(&tun_fd_watcher, tun_fd_cb, tun_fd, EV_READ);
    ev_io_start(loop, &tun_fd_watcher);

    delay_manager.set_loop_and_cb(loop, delay_manager_cb);

    conn_info.fec_encode_manager.set_data(&conn_info);
    conn_info.fec_encode_manager.set_loop_and_cb(loop, fec_encode_cb);

    conn_info.timer.data = &conn_info;
    ev_init(&conn_info.timer, conn_timer_cb);
    ev_timer_set(&conn_info.timer, 0, timer_interval / 1000.0);
    ev_timer_start(loop, &conn_info.timer);

    struct ev_io fifo_watcher;
    int fifo_fd = -1;

    if (fifo_file[0] != 0) {
        fifo_fd = create_fifo(fifo_file);
        ev_io_init(&fifo_watcher, fifo_cb, fifo_fd, EV_READ);
        ev_io_start(loop, &fifo_watcher);
        mylog(log_info, "fifo_file=%s\n", fifo_file);
    }

    ev_prepare prepare_watcher;
    ev_init(&prepare_watcher, prepare_cb);
    ev_prepare_start(loop, &prepare_watcher);

    mylog(log_info, "now listening at %s\n", local_addr.get_str());

    ev_run(loop, 0);

    mylog(log_warn, "ev_run returned\n");
    myexit(0);

    return 0;
}
