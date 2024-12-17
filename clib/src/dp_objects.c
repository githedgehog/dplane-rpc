#include <string.h>
#include <arpa/inet.h>

#include "wire.h"
#include "dp_objects.h"

/* utils: checks */
int check_object_type(ObjType type)
{
    /* This needs to be updated when adding new types :-( */
    switch(type) {
        case None:
            return E_INVAL;
        case VerInfo:
        case IfAddress:
        case Rmac:
        case IpRoute:
            return E_OK;
        default:
            BUG(false, E_INVAL);
    }
    return E_BUG;
}

/* utils: build objects */
bool has_ip_address(struct ip_address *addr)
{
    BUG(!addr, false);
    return (addr->ipver == IPV4 || addr->ipver == IPV6);
}
int set_ip_address(struct ip_address *addr, const char *str)
{
    BUG(!addr || !str, E_BUG);
    int r = inet_pton(AF_INET, str, &addr->addr.ipv4);
    if (r == 1) {
        addr->ipver = IPV4;
        return E_OK;
    }
    r = inet_pton(AF_INET6, str, addr->addr.ipv6);
    if (r == 1) {
        addr->ipver = IPV6;
        return E_OK;
    }
    return E_INVAL;
}
int set_mac_address(struct mac_addr *mac, uint8_t addr[MAC_LEN])
{
    BUG(!mac || !addr, E_BUG);
    memcpy(mac->bytes, addr, MAC_LEN);
    return E_OK;
}
int ip_route_add_nhop(struct ip_route *route, struct next_hop *nhop)
{
    BUG(!route || !nhop, E_BUG);
    if (route->num_nhops == MAX_NHOPS)
        return E_TOO_MANY_NHOPS;
    *(route->nhops + route->num_nhops) = *nhop;
    route->num_nhops++;
    return E_OK;
}

/* utils: wrap objects */
int rmac_as_object(struct RpcObject *object, struct rmac *rmac) {
    BUG(!object || !rmac, E_BUG);
    object->rmac = *rmac;
    object->type = Rmac;
    return E_OK;
}
int ifaddress_as_object(struct RpcObject *object, struct ifaddress *ifaddr) {
    BUG(!object || !ifaddr, E_BUG);
    object->ifaddress = *ifaddr;
    object->type = IfAddress;
    return E_OK;
}
int verinfo_as_object(struct RpcObject *object, struct ver_info *info) {
    BUG(!object || !info, E_BUG);
    object->ver_info = *info;
    object->type = VerInfo;
    return E_OK;
}
int iproute_as_object(struct RpcObject *object, struct ip_route *route) {
    BUG(!object || !route, E_BUG);
    object->route = *route;
    object->type = IpRoute;
    return E_OK;
}

/* Basic types encoders / decoders */
static int encode_ipaddress(buffer_t *buff, struct ip_address *addr)
{
    BUG(!buff || !addr, E_BUG);
    int r;

    if ((r = put_u8(buff, addr->ipver)))
        return r;
    switch(addr->ipver) {
        case NONE: return E_OK;
        case IPV4: return put_raw(buff, &addr->addr.ipv4, IPV4_ADDR_LEN);
        case IPV6: return put_raw(buff, &addr->addr.ipv6, IPV6_ADDR_LEN);
        default:
            return E_INVAL;
    }
}
static int decode_ipaddress(buffer_t *buff, struct ip_address *addr)
{
    BUG(!buff || !addr, E_BUG);
    memset(addr, 0, sizeof(*addr));

    int r;
    if ((r = get_u8(buff, &addr->ipver)))
        return r;

    switch(addr->ipver) {
        case NONE: return E_OK;
        case IPV4: return get_raw(buff, &addr->addr.ipv4, IPV4_ADDR_LEN);
        case IPV6: return get_raw(buff, &addr->addr.ipv6, IPV6_ADDR_LEN);
        default:
            return E_INVALID_DATA;
    }
}
static int encode_mac(buffer_t *buff, struct mac_addr *mac)
{
    BUG(!buff || !mac, E_BUG);
    return put_raw(buff, mac->bytes, sizeof(mac->bytes));
}
static int decode_mac(buffer_t *buff, struct mac_addr *mac)
{
    BUG(!buff || !mac, E_BUG);
    memset(mac, 0, sizeof(*mac));
    return get_raw(buff, mac->bytes, sizeof(mac->bytes));
}

/* ver_info: encode / decode */
static int encode_verinfo(buffer_t *buff, struct ver_info *info)
{
    BUG(!buff || !info, E_BUG);
    int r;
    if ((r = put_u8(buff, info->major)) != E_OK)
        return r;
    if ((r = put_u8(buff, info->minor)) != E_OK)
        return r;
    if ((r = put_u8(buff, info->patch)) != E_OK)
        return r;
    return E_OK;
}
static int decode_verinfo(buffer_t *buff, struct ver_info *info)
{
    BUG(!buff || !info, E_BUG);
    memset(info, 0, sizeof(*info));

    int r;
    if ((r = get_u8(buff, &info->major)) != E_OK)
        return r;
    if ((r = get_u8(buff, &info->minor)) != E_OK)
        return r;
    if ((r = get_u8(buff, &info->patch)) != E_OK)
        return r;
    return E_OK;
}

/* ifadddress: encode / decode */
static int encode_ifaddress(buffer_t *buff, struct ifaddress *ifaddr)
{
    BUG(!buff || !ifaddr, E_BUG);
    int r;
    if (!has_ip_address(&ifaddr->address))
        return E_INVAL;

    if ((r = encode_ipaddress(buff, &ifaddr->address)) != E_OK)
        return r;

    if ((r = put_u8(buff, ifaddr->len)) != E_OK)
        return r;

    if ((r = put_u32(buff, ifaddr->ifindex)) != E_OK)
        return r;

    if ((r = put_u32(buff, ifaddr->vrfid)) != E_OK)
        return r;

    return E_OK;
}
static int decode_ifaddress(buffer_t *buff, struct ifaddress *ifaddr)
{
    BUG(!buff || !ifaddr, E_BUG);
    memset(ifaddr, 0, sizeof(*ifaddr));

    int r;

    if ((r = decode_ipaddress(buff, &ifaddr->address)) != E_OK)
        return r;

    if ((r = get_u8(buff, &ifaddr->len)) != E_OK)
        return r;

    if ((r = get_u32(buff, &ifaddr->ifindex)) != E_OK)
        return r;

    if ((r = get_u32(buff, &ifaddr->vrfid)) != E_OK)
        return r;

    return E_OK;
}

/* rmac: encode / decode */
static int encode_rmac(buffer_t *buff, struct rmac *rmac)
{
    BUG(!buff || !rmac, E_BUG);
    int r;
    if (!has_ip_address(&rmac->address) != E_OK)
        return E_INVAL;

    if ((r = encode_ipaddress(buff, &rmac->address)) != E_OK)
        return r;

    if ((r = encode_mac(buff, &rmac->mac)) != E_OK)
        return r;

    if ((r = put_u32(buff, rmac->vni)) != E_OK)
        return r;

    return E_OK;
}
static int decode_rmac(buffer_t *buff, struct rmac *rmac)
{
    BUG(!buff || !rmac, E_BUG);
    memset(rmac, 0, sizeof(*rmac));

    int r;
    if ((r = decode_ipaddress(buff, &rmac->address)) != E_OK)
        return r;

    if ((r = decode_mac(buff, &rmac->mac)) != E_OK)
        return r;

    if ((r = get_u32(buff, &rmac->vni)) != E_OK)
        return r;

    return E_OK;
}

/* nhop encap: encode / decode */
static int encode_next_hop_encap_vxlan(buffer_t *buff, struct next_hop_encap_vxlan *vxlan) {
    BUG(!buff || !vxlan, E_BUG);
    return put_u32(buff, vxlan->vni);
}
static int decode_next_hop_encap_vxlan(buffer_t *buff, struct next_hop_encap_vxlan *vxlan) {
    BUG(!buff || !vxlan, E_BUG);
    return get_u32(buff, &vxlan->vni);
}
static int encode_next_hop_encap(buffer_t *buff, struct next_hop_encap *encap)
{
    BUG(!buff || !encap, E_BUG);
    int r;

    if ((r = put_u8(buff, encap->type)) != E_OK)
        return r;

    switch (encap->type) {
        case NoEncap: return E_OK;
        case VXLAN: return encode_next_hop_encap_vxlan(buff, &encap->vxlan);
        default: return E_INVAL;
    }
}
static int decode_next_hop_encap(buffer_t *buff, struct next_hop_encap *encap)
{
    BUG(!buff || !encap, E_BUG);
    int r;

    if ((r = get_u8(buff, &encap->type)) != E_OK)
        return r;

    switch (encap->type) {
        case NoEncap: return E_OK;
        case VXLAN: return decode_next_hop_encap_vxlan(buff, &encap->vxlan);
        default: return E_INVALID_DATA;
    }
}

/* 1-nhop: encode / decode */
static int encode_next_hop(buffer_t *buff, struct next_hop *nhop)
{
    BUG(!buff || !nhop, E_BUG);
    int r;

    if ((r = encode_ipaddress(buff, &nhop->address)) != E_OK)
        return r;

    if ((r = put_u32(buff, nhop->ifindex)) != E_OK)
        return r;

    if ((r = put_u32(buff, nhop->vrfid)) != E_OK)
        return r;

    if ((r = encode_next_hop_encap(buff, &nhop->encap)) != E_OK)
        return r;

    return E_OK;
}
static int decode_next_hop(buffer_t *buff, struct next_hop *nhop)
{
    BUG(!buff || !nhop, E_BUG);
    int r;

    if ((r = decode_ipaddress(buff, &nhop->address)) != E_OK)
        return r;

    if ((r = get_u32(buff, &nhop->ifindex)) != E_OK)
        return r;

    if ((r = get_u32(buff, &nhop->vrfid)) != E_OK)
        return r;

    if ((r = decode_next_hop_encap(buff, &nhop->encap)) != E_OK)
        return r;

    return E_OK;
}

/* nhops: encode / decode */
static int encode_next_hops(buffer_t *buff, NumNhops num, struct next_hop *nhops)
{
    BUG(!buff || !nhops, E_BUG);

    int r;
    if ((r = put_u8(buff, num)) != E_OK)
        return r;

    for (NumNhops i = 0; i < num ; i++)
        if ((r = encode_next_hop(buff, &nhops[i])) != E_OK)
            return r;

    return E_OK;
}
static int decode_next_hops(buffer_t *buff, NumNhops *num, struct next_hop *nhops)
{
    BUG(!buff || !nhops, E_BUG);

    int r;
    if ((r = get_u8(buff, num)) != E_OK)
        return r;

    for (NumNhops i = 0; i < *num ; i++)
        if ((r = decode_next_hop(buff, &nhops[i])) != E_OK)
            return r;

    return E_OK;
}

/* ip_route: encode / decode */
static int encode_iproute(buffer_t *buff, struct ip_route *route)
{
    BUG(!buff || !route, E_BUG);

    int r;

    if (!has_ip_address(&route->prefix) != E_OK)
        return E_INVAL;

    if ((r = encode_ipaddress(buff, &route->prefix)) != E_OK)
        return r;

    if ((r = put_u8(buff, route->len)) != E_OK)
        return r;

    if ((r = put_u32(buff, route->vrfid)) != E_OK)
        return r;

    if ((r = put_u32(buff, route->tableid)) != E_OK)
        return r;

    if ((r = put_u8(buff, route->type)) != E_OK)
        return r;

    if ((r = put_u8(buff, route->distance)) != E_OK)
        return r;

    if ((r = put_u32(buff, route->metric)) != E_OK)
        return r;

    if ((r = encode_next_hops(buff, route->num_nhops, route->nhops)) != E_OK)
        return r;

    return E_OK;
}
static int decode_iproute(buffer_t *buff, struct ip_route *route)
{
    BUG(!buff || !route, E_BUG);

    int r;

    if ((r = decode_ipaddress(buff, &route->prefix)) != E_OK)
        return r;

    if ((r = get_u8(buff, &route->len)) != E_OK)
        return r;

    if ((r = get_u32(buff, &route->vrfid)) != E_OK)
        return r;

    if ((r = get_u32(buff, &route->tableid)) != E_OK)
        return r;

    if ((r = get_u8(buff, &route->type)) != E_OK)
        return r;

    if ((r = get_u8(buff, &route->distance)) != E_OK)
        return r;

    if ((r = get_u32(buff, &route->metric)) != E_OK)
        return r;

    if ((r = decode_next_hops(buff, &route->num_nhops, route->nhops)) != E_OK)
        return r;

    return E_OK;
}

/* Object wrapper encoders / decoder */
int encode_object(buffer_t *buff, struct RpcObject *object)
{
    BUG(!buff || !object, E_BUG);

    int r;
    if ((r = put_u8(buff, object->type)) != E_OK)
        return r;

    switch(object->type) {
        case None:
            return E_OK;
        case VerInfo:
            return encode_verinfo(buff, &object->ver_info);
        case IfAddress:
            return encode_ifaddress(buff, &object->ifaddress);
        case Rmac:
            return encode_rmac(buff, &object->rmac);
        case IpRoute:
            return encode_iproute(buff, &object->route);
        default:
            return E_INVAL;
    }
}
int decode_object(buffer_t *buff, struct RpcObject *object)
{
    BUG(!buff || !object, E_BUG);

    int r;
    if ((r = get_u8(buff, &object->type)) != E_OK)
        return r;

    switch(object->type) {
        case None:
            return E_OK;
        case VerInfo:
            return decode_verinfo(buff, &object->ver_info);
        case IfAddress:
            return decode_ifaddress(buff, &object->ifaddress);
        case Rmac:
            return decode_rmac(buff, &object->rmac);
        case IpRoute:
            return decode_iproute(buff, &object->route);
        default:
            return E_INVALID_DATA;
    }
}
