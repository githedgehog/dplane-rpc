#include <string.h>

#include "object_builders.h"

/* Build objects */
struct rmac build_rmac(void)
{
    /* build rmac object */
    struct rmac rmac = {0};
    set_ip_address(&rmac.address, "7.0.0.9");
    uint8_t mac[MAC_LEN] = {1,2,3,4,5,6};
    set_mac_address(&rmac.mac, mac);
    rmac.vni = 333;
    return rmac;
}
struct ver_info build_ver_info(void)
{
    /* build verinfo object */
    struct ver_info info = VER_INFO_INITIALIZER;
    return info;
}
struct conn_info build_conn_info(void)
{
    /* build connect info object */
    struct conn_info info = {
       .name = "test",
       .pid = 1234,
       .verinfo = build_ver_info()
    };
    return info;
}
struct ifaddress build_ifaddress(void)
{
    struct ifaddress ifaddr = {0};
    strcpy(ifaddr.ifname, "FastEthernet1/2/3");
    set_ip_address(&ifaddr.address, "10.0.0.1");
    ifaddr.len = 30;
    ifaddr.ifindex = 111;
    ifaddr.vrfid = 999;
    return ifaddr;
}
struct next_hop build_next_hop(const char *addr, Ifindex ifindex, Vni vni)
{
    struct next_hop nhop = {0};
    nhop.ifindex = ifindex;
    if (vni != 0) {
        nhop.encap.type = VXLAN;
        nhop.encap.vxlan.vni = vni;
    }
    set_ip_address(&nhop.address, addr);
    return nhop;
}
struct ip_route build_ipv4_route(const char *prefix, NumNhops num_nhops)
{
    /* build route object */
    struct ip_route route = {0};
    set_ip_address(&route.prefix, prefix);
    route.len = 24;
    route.vrfid = 1;
    route.tableid = 44;
    route.type = Bgp;
    route.distance = 20;
    route.metric = 100;
    route.num_nhops = 0;
    for (NumNhops i = 0; i < num_nhops; i++) {
        struct next_hop nhop = build_next_hop("7.0.0.1", 700+i, 3000);
            ip_route_add_nhop(&route, &nhop);
    }
    return route;
}
struct ip_route build_ipv6_route(const char *prefix, NumNhops num_nhops)
{
    /* build route object */
    struct ip_route route = {0};
    set_ip_address(&route.prefix, prefix);
    route.len = 64;
    route.vrfid = 1;
    route.tableid = 44;
    route.type = Bgp;
    route.distance = 20;
    route.metric = 100;
    route.num_nhops = 0;
    for (NumNhops i = 0; i < num_nhops; i++) {
        struct next_hop nhop = build_next_hop("2001:1:2:3::1", 700+i, 3000);
            ip_route_add_nhop(&route, &nhop);
    }
    return route;
}
struct get_filter build_get_filter(void)
{
    struct get_filter filter = {0};

    vec_push_u8(&filter.otypes, IfAddress);
    vec_push_u8(&filter.otypes, Rmac);
    vec_push_u8(&filter.otypes, IpRoute);

    vec_push_u32(&filter.vrfIds, 1);
    vec_push_u32(&filter.vrfIds, 2);
    vec_push_u32(&filter.vrfIds, 3);
    vec_push_u32(&filter.vrfIds, 4);
    vec_push_u32(&filter.vrfIds, 5);
    vec_push_u32(&filter.vrfIds, 6);

    return filter;
}
