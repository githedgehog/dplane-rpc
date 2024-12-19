#ifndef TEST_OBJECT_BUILDERS_H_
#define TEST_OBJECT_BUILDERS_H_

#include "../src/dp_msg.h"

struct rmac build_rmac(void);
struct ver_info build_ver_info(void);
struct ifaddress build_ifaddress(void);
struct next_hop build_next_hop(const char *addr, Ifindex ifindex, Vni vni);
struct ip_route build_ipv4_route(const char *prefix, NumNhops num_nhops);
struct ip_route build_ipv6_route(const char *prefix, NumNhops num_nhops);

#endif /* TEST_OBJECT_BUILDERS_H_ */
