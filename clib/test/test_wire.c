#include <string.h>
#include <stdbool.h>

#include "test_common.h"
#include "object_builders.h"
#include "../src/wire.h"

void dump(void *s, size_t len, char *disp)
{
    uint8_t *octets = (uint8_t*)s;
    fprintf(stderr, "%10.10s: ", disp);
    for(int i=0; i < len; i++) {
        fprintf(stderr, "%02x ", octets[i]);
    }
    fprintf(stderr, "\n");
}
void cmp(void *s1, void *s2, size_t len, bool show_all)
{
    uint8_t *octets1 = (uint8_t*)s1;
    uint8_t *octets2 = (uint8_t*)s2;
    for(int i=0; i < len; i++) {
        if (show_all) {
            fprintf(stderr, "(%d) %02x %02x %s\n", i, octets1[i], octets2[i], octets1[i] != octets2[i] ? "*" : "");
        } else if (octets1[i] != octets2[i]) {
            fprintf(stderr, "(%d) %02x %02x\n", i, octets1[i], octets2[i]);
        }
    }
}

int check_object(buffer_t *buff, struct RpcObject *object)
{
    int r;

    /* encode the object */
    r = encode_object(buff, object);
    CHECK(r==E_OK);

    /* decode into recovered */
    struct RpcObject recovered;
    memset(&recovered, 0, sizeof(recovered));

    r = decode_object(buff, &recovered);
    CHECK(r==E_OK);

    CHECK(buff->r == buff->w);
    CHECK(recovered.type == object->type);

    /* getfilter objects have internal pointers (vectors)
     * which can't be mem compared.
     */
    if (recovered.type == GetFilter) {
        struct get_filter *f1 = &object->get_filter;
        struct get_filter *f2 = &recovered.get_filter;
        CHECK(f1->otypes.len == f2->otypes.len);
        CHECK(f1->vrfIds.len == f2->vrfIds.len);
        // this check is ordered
        CHECK(memcmp(f1->otypes.data, f2->otypes.data, f1->otypes.len * sizeof(ObjType)) == 0);
        CHECK(memcmp(f1->vrfIds.data, f2->vrfIds.data, f1->vrfIds.len * sizeof(VrfId)) == 0);

        rpc_object_dispose(&recovered);
        rpc_object_dispose(object);
        return EXIT_SUCCESS;
    }

    /* compare recovered vs original */
    r = memcmp(&recovered, object, sizeof(recovered));
    if (r != 0) {
        buffer_dump(buff);
        dump(object, sizeof(struct RpcObject), "original");
        dump(&recovered, sizeof(struct RpcObject), "recovered");
        cmp(object, &recovered, sizeof(struct RpcObject), false);
        assert(0);
        return EXIT_FAILURE;
    }
    buffer_dump(buff);
    return EXIT_SUCCESS;
}
int check_msg(buffer_t *buff, struct RpcMsg *msg)
{
    int r;

    /* encode the object */
    r = encode_msg(buff, msg);
    CHECK(r==E_OK);

    /* decode into recovered */
    struct RpcMsg recovered;
    memset(&recovered, 0, sizeof(recovered));

    r = decode_msg(buff, &recovered);
    CHECK(r==E_OK);
    CHECK(buff->r == buff->w);

    struct RpcObject *msg_objects = NULL;
    struct RpcObject *rec_objects = NULL;

    /* if msg has a response, it may point to a bunch of
     * objects. Nullify pointers for the dummy comparison
     * to work and later on compare the objects.
     */
    if (recovered.type == Response) {
        msg_objects = msg->response.objects;
        rec_objects = recovered.response.objects;
        msg->response.objects = NULL;
        recovered.response.objects = NULL;
    }

    /* compare recovered vs original */
    r = memcmp(&recovered, msg, sizeof(recovered));
    if (r != 0) {
        buffer_dump(buff);
        //dump(msg, sizeof(struct RpcMsg), "original");
        //dump(&recovered, sizeof(struct RpcMsg), "recovered");
        cmp(msg, &recovered, sizeof(struct RpcMsg), false);
        return EXIT_FAILURE;
    }

    /* compare object array */
    CHECK(!!rec_objects == !!rec_objects);
    if (rec_objects) {
        r = memcmp(msg_objects, rec_objects, sizeof(recovered));
        if (r != 0) {
            cmp(msg, &recovered, sizeof(struct RpcObject) * msg->response.num_objects, false);
            return EXIT_FAILURE;
        }
    }

    /* decoded objects were allocated in heap */
    recovered.response.objects = rec_objects;
    msg_dispose(&recovered);

    //buffer_dump(buff);
    return EXIT_SUCCESS;
}

/* test object encoding / decoding */
int test_object_rmac(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build rmac object */
    struct rmac rmac = build_rmac();

    /* wrap it */
    struct RpcObject object = {.type = Rmac, .rmac = rmac};
    return check_object(buff, &object);
}
int test_object_verinfo(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build verinfo object */
    struct ver_info info = build_ver_info();

    /* wrap it */
    struct RpcObject object = {.type = VerInfo, .ver_info = info};
    return check_object(buff, &object);
}
int test_object_ifaddr(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build ifaddress object */
    struct ifaddress ifaddr = build_ifaddress();

    /* wrap it */
    struct RpcObject object = {.type = IfAddress, .ifaddress = ifaddr};
    return check_object(buff, &object);
}
int test_object_iproute_v4(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build route object */
    struct ip_route route = build_ipv4_route("192.168.1.0", 6);

    /* wrap it */
    struct RpcObject object;
    memset(&object, 0, sizeof(object));
    iproute_as_object(&object, &route);
    return check_object(buff, &object);
}
int test_object_iproute_v6(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build route object */
    struct ip_route route = build_ipv6_route("2000:1:2:3:4::", 6);

    /* wrap it */
    struct RpcObject object;
    memset(&object, 0, sizeof(object));
    iproute_as_object(&object, &route);
    return check_object(buff, &object);
}
int test_object_get_filter(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    struct get_filter filter = {0};
    vec_push_u8(&filter.otypes, IpRoute);
    vec_push_u8(&filter.otypes, IfAddress);
    vec_push_u8(&filter.otypes, Rmac);
    vec_push_u32(&filter.vrfIds, 1000);
    vec_push_u32(&filter.vrfIds, 2000);
    vec_push_u32(&filter.vrfIds, 3000);
    vec_push_u32(&filter.vrfIds, 4000);
    vec_push_u32(&filter.vrfIds, 5000);

    /* wrap it */
    struct RpcObject object;
    memset(&object, 0, sizeof(object));
    getfilter_as_object(&object, &filter);
    return check_object(buff, &object);
}
int test_object_encoding(buffer_t *buff)
{
    if (test_object_rmac(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_object_verinfo(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_object_ifaddr(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_object_iproute_v4(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_object_iproute_v6(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_object_get_filter(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/* test msg:Request encoding / decoding */
int test_msg_request_connect(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build rmac */
    struct ver_info info = build_ver_info();

    /* build request with object */
    struct RpcMsg msg = {.type = Request, .request.op = Connect, .request.seqn = 1234};
    verinfo_as_object(&msg.request.object, &info);
    return check_msg(buff, &msg);
}
int test_msg_request_rmac(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build rmac */
    struct rmac rmac = build_rmac();

    /* build request with object */
    struct RpcMsg msg = {.type = Request, .request.op = Add, .request.seqn = 1234};
    rmac_as_object(&msg.request.object, &rmac);
    return check_msg(buff, &msg);
}
int test_msg_request_ifaddr(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build ifaddr */
    struct ifaddress ifaddr = build_ifaddress();

    /* build request with object */
    struct RpcMsg msg = {.type = Request, .request.op = Del, .request.seqn = 1234};
    ifaddress_as_object(&msg.request.object, &ifaddr);
    return check_msg(buff, &msg);
}
int test_msg_request_ipv4_route(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build route */
    struct ip_route route = build_ipv4_route("192.168.1.0", MAX_NHOPS);

    /* build request with object */
    struct RpcMsg msg = {.type = Request, .request.op = Update, .request.seqn = 1234};
    iproute_as_object(&msg.request.object, &route);
    return check_msg(buff, &msg);
}
int test_msg_request_ipv6_route(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    /* build rmac */
    struct ip_route route = build_ipv6_route("2000:1:2:3:4::", MAX_NHOPS);

    /* build request with object */
    struct RpcMsg msg = {.type = Request, .request.op = Update, .request.seqn = 1234};
    iproute_as_object(&msg.request.object, &route);
    return check_msg(buff, &msg);
}
int test_msg_request(buffer_t *buff)
{
    if (test_msg_request_connect(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_msg_request_rmac(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_msg_request_ifaddr(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_msg_request_ipv4_route(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_msg_request_ipv6_route(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/* test msg:Response encoding / decoding */
int test_msg_response_without_objects(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    struct RpcMsg msg = {0};
    struct RpcResponse resp = {0};

    resp.op = Update;
    resp.seqn = 654321;
    resp.rescode = Ok;
    resp.num_objects = 0;

    msg.type = Response;
    msg.response = resp;

    return check_msg(buff, &msg);
}
int test_msg_response_with_objects(buffer_t *buff)
{
    TEST();
    buffer_clear(buff);

    struct RpcMsg msg;
    memset(&msg, 0, sizeof(msg));
    struct RpcResponse resp = {0};
    struct RpcObject object_buffer[10] = {0};

    resp.op = Update;
    resp.seqn = 654321;
    resp.rescode = Ok;
    resp.objects = object_buffer;

    for(int i = 0; i < 10; i++) {
        struct ip_route route = build_ipv4_route("192.168.50.0", 3);
        struct RpcObject object = {0};
        iproute_as_object(&object, &route);
        if (add_response_object(&resp, &object) != E_OK)
            return EXIT_FAILURE;
    }

    msg.type = Response;
    msg.response = resp;

    return check_msg(buff, &msg);
}
int test_msg_response(buffer_t *buff)
{
    if (test_msg_response_without_objects(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_msg_response_with_objects(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}


int main (int argc, char **argv)
{
    buffer_t *buff = buffer_new(0);
    if (!buff)
        return EXIT_FAILURE;

    /* test object encoding / decoding */
    if (test_object_encoding(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    /* test msg:request encoding / decoding */
    if (test_msg_request(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    /* test msg:response encoding / decoding */
    if (test_msg_response(buff) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    buffer_free(buff);
    fprintf(stderr, "Success!\n");
    return EXIT_SUCCESS;
}
