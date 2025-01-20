#pragma once

#include "../src/dp_msg.h"

struct rmac build_rmac(void);
struct ver_info build_ver_info(void);
struct conn_info build_conn_info(void);
struct ifaddress build_ifaddress(void);
struct next_hop build_next_hop(const char *addr, Ifindex ifindex, Vni vni);
struct ip_route build_ipv4_route(const char *prefix, NumNhops num_nhops);
struct ip_route build_ipv6_route(const char *prefix, NumNhops num_nhops);
struct get_filter build_get_filter(void);
