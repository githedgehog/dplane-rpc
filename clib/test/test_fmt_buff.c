#include <string.h>

#include "test_common.h"
#include "../src/fmt_buff.h"

struct fmt_buff fb;

#include "object_builders.h"
#include "../src/display.h"

/* Not a real test */
int fmt_object_samples(void)
{
    clear_fmt_buff(&fb);

    /* verinfo */
    fprintf(stderr, "\n────────────────── fmt verinfo ──────────────────\n");
    struct ver_info vinfo = build_ver_info();
    fprintf(stderr, "%s\n", fmt_verinfo(&fb, true, &vinfo));

    /* rmac */
    fprintf(stderr, "\n────────────────── fmt Rmac ──────────────────\n");
    struct rmac rmac = build_rmac();
    fprintf(stderr, "%s\n", fmt_rmac(&fb, true, &rmac));

    /* ifaddress */
    fprintf(stderr, "\n────────────────── fmt IfAddress ──────────────────\n");
    struct ifaddress ifa = build_ifaddress();
    fprintf(stderr, "%s\n", fmt_ifaddress(&fb, true, &ifa));

    /* IPv4 route */
    fprintf(stderr, "\n────────────────── fmt IPv4 route ──────────────────\n");
    struct ip_route route = build_ipv4_route("1.2.3.4", 2);
    fprintf(stderr, "%s\n", fmt_iproute(&fb, true, &route));

    /* IPv6 route */
    fprintf(stderr, "\n────────────────── fmt IPv6 route ──────────────────\n");
    struct ip_route route6 = build_ipv6_route("3001:a:b:c::", 2);
    fprintf(stderr, "%s\n", fmt_iproute(&fb, true, &route6));

    /* an Ipv6 route as object */
    fprintf(stderr, "\n────────────────── fmt IPv6 route as RpcObject ──────────────────\n");
    struct RpcObject object = {0};
    iproute_as_object(&object, &route6);
    fprintf(stderr, "%s\n", fmt_rpcobject(&fb, true, &object));

    /* getfilter as Rpcobject */
    fprintf(stderr, "\n────────────────── fmt getfilter ──────────────────\n");
    struct get_filter filter = build_get_filter();
    fprintf(stderr, "%s\n", fmt_getfilter(&fb, true, &filter));
    vec_dispose(&filter.otypes);
    vec_dispose(&filter.vrfIds);

    return EXIT_SUCCESS;
}

/* Not a real test */
void fmt_buff_playground(void)
{
    clear_fmt_buff(&fb);

    fprintf(stderr, "\n────────────────── Playground ──────────────────\n");

    fprintf(stderr, "%s\n", fmt_buff(&fb, "01234"));
    fprintf(stderr, "%s\n", fmt_buff(&fb, "%s %d", "hello", 3));

    clear_fmt_buff(&fb);
    for(int i = 0; i <10; i++)
        fprintf(stderr, "%s\n", fmt_buff(&fb, " %d", i));

    clear_fmt_buff(&fb);
    fmt_buff(&fb, "You");
    fmt_buff(&fb, " talking");
    fmt_buff(&fb, " to");
    fmt_buff(&fb, " %s", "me?");
    fprintf(stderr, "%s\n", fb.buff);
}

/* basic test */
int test_fmt_buff(void)
{
    /* initialize fmt buff */
    init_fmt_buff(&fb, 1);

    /* check initial conditions */
    CHECK(fb.capacity == 1);
    CHECK(fb.w == 0);

    /* write a known string */
    char *test_string = "123456789";
    fmt_buff(&fb, "%s", test_string);
    CHECK(fb.w == strlen(test_string));
    CHECK(fb.w == strlen(fb.buff));
    CHECK(fb.capacity >= fb.w);

    /* clear buffer */
    clear_fmt_buff(&fb);
    CHECK(fb.w == 0);
    CHECK(fb.buff[0] == '\0');
    CHECK(fb.capacity >= strlen(test_string));

    /* write again the same test string */
    fmt_buff(&fb, "%s", test_string);
    CHECK(fb.w == strlen(test_string));
    CHECK(fb.capacity >= fb.w);

    /* write the test string without clearing. The buff should contain twice the string */
    char *test_string_doubled = "123456789123456789";
    fmt_buff(&fb, "%s", test_string);
    CHECK(fb.w == 2 * strlen(test_string));
    CHECK(fb.w == strlen(fb.buff));
    CHECK(fb.capacity >= fb.w);
    CHECK(strncmp(fb.buff, test_string_doubled, fb.w) == 0);

    /* write NUM_ITERS times the test string */
    clear_fmt_buff(&fb);
#define NUM_ITERS 1000
    for (int i = 0; i < NUM_ITERS; i++) {
        fmt_buff(&fb, "%s", test_string);
    }
    CHECK(fb.w == NUM_ITERS * strlen(test_string));
    CHECK(fb.capacity >= fb.w);

    clear_fmt_buff(&fb);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    /* this test initializes the fmt_buffer globally */
    if (test_fmt_buff() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    /* format some objects - always succeeds */
    fmt_object_samples();

    /* place to try things - not a real test */
    fmt_buff_playground();

    /* finalize fmt buff */
    fini_fmt_buff(&fb);
    return EXIT_SUCCESS;
}
