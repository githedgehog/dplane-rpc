#pragma once

#include "buffer.h"
#include "dp_types.h"
#include "vec.h"
#include <stdbool.h>

// can override with cmake
#ifndef MAX_ECMP
#define MAX_ECMP 32
#endif

#define MAX_NHOPS MAX_ECMP
#if MAX_NHOPS > MAX_NUM_NHOPS
#error The maximum ecmp is 255
#endif

struct ver_info {
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
};

struct rmac {
    struct ip_address address;
    struct mac_addr mac;
    Vni vni;
};

struct ifaddress {
    struct ip_address address;
    MaskLen len;
    Ifindex ifindex;
    VrfId vrfid;
};

struct next_hop_encap_vxlan {
    Vni vni;
};
struct next_hop_encap {
    EncapType type;
    union {
        struct next_hop_encap_vxlan vxlan;
    };
};
struct next_hop {
    struct ip_address address;
    Ifindex ifindex;
    VrfId vrfid;
    struct next_hop_encap encap;
};

struct ip_route {
    struct ip_address prefix;
    MaskLen len;
    VrfId vrfid;
    RouteTableId tableid;
    RouteType type;
    RouteDistance distance;
    RouteMetric metric;
    NumNhops num_nhops;
    struct next_hop nhops[MAX_NHOPS];
};

struct get_filter {
    vec_u8 otypes;
    vec_u32 vrfIds;
};

struct RpcObject {
    ObjType type;
    union {
        struct ver_info ver_info;
        struct rmac rmac;
        struct ifaddress ifaddress;
        struct ip_route route;
        struct get_filter get_filter;
    };
};

/* utils: check object type
 * (PLEASE update this function when new types are added)
 */
int check_object_type(ObjType type);

/* utils to build objects */
bool has_ip_address(struct ip_address *addr);
int set_ip_address(struct ip_address *addr, const char *str);
int set_mac_address(struct mac_addr *mac, uint8_t addr[MAC_LEN]);
int ip_route_add_nhop(struct ip_route *route, struct next_hop *nhop);

/* utils to wrap objects */
int rmac_as_object(struct RpcObject *object, struct rmac *rmac);
int ifaddress_as_object(struct RpcObject *object, struct ifaddress *ifaddr);
int verinfo_as_object(struct RpcObject *object, struct ver_info *info);
int iproute_as_object(struct RpcObject *object, struct ip_route *route);
int getfilter_as_object(struct RpcObject *object, struct get_filter *filter);

/* object encoding */
int encode_object(buff_t *buff, struct RpcObject *object);
int decode_object(buff_t *buff, struct RpcObject *object);

/* disposal */
void rpc_object_dispose(struct RpcObject *object);

/* version info initializer */
extern const struct ver_info VER_INFO_INITIALIZER;
