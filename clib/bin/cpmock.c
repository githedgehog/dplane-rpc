#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>

#include "../src/wire.h"
#include "../src/common.h"
#include "../src/display.h"
#include "../test/object_builders.h" /* test object builders */

int sock = -1;
const char *cp_sock_path = "/tmp/CP.sock";
const char *dp_sock_path = "/tmp/DP.sock";
uint64_t seqnum = 1;
buff_t *buff = NULL;

/* unix sock utils */
static void unix_sock_disconnect(void)
{
    if (sock != -1) {
        log_dbg("Closing unix socket to dataplane...");
        close(sock);
        sock = -1;
    }
    if (unlink(cp_sock_path) == 0)
        log_dbg("Deleted unix path at '%s'", cp_sock_path);
}
static int unix_sock_open(const char *bind_path)
{
    struct sockaddr_un un_src;
    memset(&un_src, 0, sizeof(un_src));

    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_err("Failed to open unix socket");
        return -1;
    }

    if (bind_path) {
        size_t path_len = strlen(bind_path);
        if (!path_len || path_len >= sizeof(un_src.sun_path)) {
            log_err("Invalid unix socket path length of %zu", path_len);
            goto fail;
        }
        un_src.sun_family = AF_UNIX;
        strcpy(un_src.sun_path, bind_path);

        /* sanity: remove file system entry */
        if (unlink(un_src.sun_path) == 0)
            log_err("Deleted unix socket path at '%s'", un_src.sun_path);

        /* bind to the provided path */
        if (bind(sock, (struct sockaddr*)&un_src, sizeof(un_src)) < 0) {
            log_err("Unable to bind to %s : %s", un_src.sun_path, strerror(errno));
            goto fail;
        }

        /* set permissions */
        if (chmod(bind_path, S_IRWXU | S_IRWXG | S_IRWXO) < 0 ) {
            log_err("Failure setting permissions to %s : %s", un_src.sun_path, strerror(errno));
            goto fail;
        }
    }
    /* success */
    log_dbg("Successfully created unix socket");
    return sock;

fail:
    unix_sock_disconnect();
    return -1;
}
static int unix_connect(const char *conn_path)
{
    if (!conn_path)
        return EXIT_FAILURE;

    /* open unix socket */
    if (sock < 0) {
        sock = unix_sock_open(cp_sock_path);
        if (sock < 0)
            return EXIT_FAILURE;
    }

    /* set path to connect to */
    struct sockaddr_un dst = {0};
    size_t path_len = strlen(conn_path);
    if (!path_len || path_len >= sizeof(dst.sun_path)) {
        log_err("Invalid unix socket path length of %zu", path_len);
        goto fail;
    }
    dst.sun_family = AF_UNIX;
    strcpy(dst.sun_path, conn_path);

    /* connect to dataplane */
    log_dbg("Connecting to dataplane at '%s'...", conn_path);
    if (connect(sock, (const struct sockaddr *)&dst, sizeof(dst)) < 0) {
        log_err("Failed to connect to dataplane: %s", strerror(errno));
        goto fail;
    }
    log_info("Successfully connected to dataplane at '%s'", conn_path);
    return EXIT_SUCCESS;

fail:
    unix_sock_disconnect();
    return EXIT_FAILURE;
}

/* Send a message */
int send_msg(struct RpcMsg *msg)
{
    int r;
    buff_clear(buff);

    r = encode_msg(buff, msg);
    if (r != E_OK )
        return EXIT_FAILURE;

    r = send(sock, buff->storage, buff->w, 0);
    if (r != buff->w)
        return EXIT_FAILURE;

    log_dbg("Successfully sent msg:%s", str_msg_type(msg->type));
    return EXIT_SUCCESS;
}

static void log_msg(const char *prefix, struct RpcMsg *msg)
{
    switch(msg->type)
    {
        case Request:
            log_dbg("%s msg: %s Op: %s, Object: %s",
                    prefix,
                    str_msg_type(msg->type),
                    str_rpc_op(msg->request.op),
                    str_object_type(msg->request.object.type));
            break;
        default:
            // we only cover requests atm
            break;
    }
}

/* This:
 *  - Encodes a mesage and sends it over the unix sock.
 *  - Reads from the unix socket (expecting to get the same message)
 *  - Decodes it and checks if it matches the message sent
 */
static int send_msg_compare_echo(struct RpcMsg *msg)
{
    int r;
    buff_clear(buff);

    log_msg("Sending ", msg);

    r = encode_msg(buff, msg);
    if (r != E_OK )
        return EXIT_FAILURE;

    r = send(sock, buff->storage, buff->w, 0);
    if (r != buff->w)
        return EXIT_FAILURE;

    index_t size = buff->w;
    buff_clear(buff);
    r = recv(sock, buff->storage, size , 0);
    if (r != size)
        return EXIT_FAILURE;
    else {
        buff->w = r;
    }

    /* decode into recovered */
    struct RpcMsg recovered;
    memset(&recovered, 0, sizeof(recovered));
    r = decode_msg(buff, &recovered);
    if (r != E_OK) {
        log_err("Error decoding received message: %s", err2str(r));
        return EXIT_FAILURE;
    }

    log_msg("Received", msg);

    /* compare recovered vs original */
    r = memcmp(&recovered, msg, sizeof(recovered));
    if (r != 0) {
        buff_dump(buff);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int send_connect(void)
{
    struct conn_info info = build_conn_info();
    struct RpcMsg msg = {.type = Request, .request.op = Connect, .request.seqn = seqnum++};
    conninfo_as_object(&msg.request.object, &info);

    return send_msg_compare_echo(&msg);
}
static int send_rmac(void)
{
    /* build rmac object */
    struct rmac rmac = build_rmac();
    struct RpcMsg msg = {.type = Request, .request.op = Add, .request.seqn = seqnum++};
    rmac_as_object(&msg.request.object, &rmac);

    return send_msg_compare_echo(&msg);
}
static int send_ifaddress(void)
{
    /* build ifaddress */
    struct ifaddress ifaddr = build_ifaddress();
    struct RpcMsg msg = {.type = Request, .request.op = Del, .request.seqn = seqnum++};
    ifaddress_as_object(&msg.request.object, &ifaddr);

    return send_msg_compare_echo(&msg);
}
static int send_ipv4_route(void)
{
    /* build route */
    struct ip_route route = build_ipv4_route("192.168.1.0", 8);
    struct RpcMsg msg = {.type = Request, .request.op = Update, .request.seqn = seqnum++};
    iproute_as_object(&msg.request.object, &route);

    return send_msg_compare_echo(&msg);
}
static int send_ipv6_route(void)
{
    /* build route */
    struct ip_route route = build_ipv6_route("2000:1:2:3:4::", 4);
    struct RpcMsg msg = {.type = Request, .request.op = Update, .request.seqn = seqnum++};
    iproute_as_object(&msg.request.object, &route);

    return send_msg_compare_echo(&msg);
}

static int send_notification(void)
{
    struct RpcMsg msg = {.type = Notification};
    return send_msg(&msg);
}

int main(int argc, char **argv)
{
    int r;

    /* initialize global buffer to serialize / deserialize */
    buff = buff_new(0);
    if (!buff)
        return EXIT_FAILURE;

    /* open socket */
    sock = unix_sock_open(cp_sock_path);
    if (sock == -1)
        return EXIT_FAILURE;

    /* UX connect */
    r = unix_connect(dp_sock_path);
    if (r != EXIT_SUCCESS)
        return r;

    /* Request: connect */
    r = send_connect();
    if (r != EXIT_SUCCESS)
        return r;

    /* Request: Rmac */
    r = send_rmac();
    if (r != EXIT_SUCCESS)
        return r;

    /* Request: Ifaddress */
    r = send_ifaddress();
    if (r != EXIT_SUCCESS)
        return r;

    /* Request: Ip route (Ipv4) */
    r = send_ipv4_route();
    if (r != EXIT_SUCCESS)
        return r;

    /* Request: Ip route (Ipv6) */
    r = send_ipv6_route();
    if (r != EXIT_SUCCESS)
        return r;

    /* Send notification: won't wait for answer */
    r = send_notification();
    if (r != EXIT_SUCCESS)
        return r;

    unix_sock_disconnect();
    buff_free(buff);

    fprintf(stderr, "Success!\n");

    return EXIT_SUCCESS;
}
