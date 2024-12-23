#include <arpa/inet.h>
#include <string.h>

#include "dp_objects.h"
#include "wire.h"

/* initializers */
const struct ver_info VER_INFO_INITIALIZER = {
    .major = VER_DP_MAJOR, .minor = VER_DP_MINOR, .patch = VER_DP_PATCH};

/* utils: checks */
int check_object_type(ObjType type)
{
    /* This needs to be updated when adding new types :-( */
    switch (type) {
    case None:
        return E_INVAL;
    case VerInfo:
    case IfAddress:
    case Rmac:
    case IpRoute:
    case GetFilter:
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
    if (route->num_nhops >= MAX_NHOPS)
        return E_TOO_MANY_NHOPS;
    *(route->nhops + route->num_nhops) = *nhop;
    route->num_nhops++;
    return E_OK;
}

/* utils: wrap objects */
int rmac_as_object(struct RpcObject *object, struct rmac *rmac)
{
    BUG(!object || !rmac, E_BUG);
    object->rmac = *rmac;
    object->type = Rmac;
    return E_OK;
}

int ifaddress_as_object(struct RpcObject *object, struct ifaddress *ifaddr)
{
    BUG(!object || !ifaddr, E_BUG);
    object->ifaddress = *ifaddr;
    object->type = IfAddress;
    return E_OK;
}

int verinfo_as_object(struct RpcObject *object, struct ver_info *info)
{
    BUG(!object || !info, E_BUG);
    object->ver_info = *info;
    object->type = VerInfo;
    return E_OK;
}

int iproute_as_object(struct RpcObject *object, struct ip_route *route)
{
    BUG(!object || !route, E_BUG);
    object->route = *route;
    object->type = IpRoute;
    return E_OK;
}

int getfilter_as_object(struct RpcObject *object, struct get_filter *filter)
{
    BUG(!object || !filter, E_BUG);
    object->get_filter = *filter;
    object->type = GetFilter;
    return E_OK;
}

/* Basic types encoders / decoders */
static int encode_ipaddress(buffer_t *buff, struct ip_address *addr)
{
    BUG(!buff || !addr, E_BUG);
    int r;

    if ((r = put_u8(buff, addr->ipver)))
        return r;
    switch (addr->ipver) {
    case NONE:
        return E_OK;
    case IPV4:
        return put_raw(buff, &addr->addr.ipv4, IPV4_ADDR_LEN);
    case IPV6:
        return put_raw(buff, &addr->addr.ipv6, IPV6_ADDR_LEN);
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

    switch (addr->ipver) {
    case NONE:
        return E_OK;
    case IPV4:
        return get_raw(buff, &addr->addr.ipv4, IPV4_ADDR_LEN);
    case IPV6:
        return get_raw(buff, &addr->addr.ipv6, IPV6_ADDR_LEN);
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
static int encode_next_hop_encap_vxlan(buffer_t *buff,
                                       struct next_hop_encap_vxlan *vxlan)
{
    BUG(!buff || !vxlan, E_BUG);
    return put_u32(buff, vxlan->vni);
}

static int decode_next_hop_encap_vxlan(buffer_t *buff,
                                       struct next_hop_encap_vxlan *vxlan)
{
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
    case NoEncap:
        return E_OK;
    case VXLAN:
        return encode_next_hop_encap_vxlan(buff, &encap->vxlan);
    default:
        return E_INVAL;
    }
}

static int decode_next_hop_encap(buffer_t *buff, struct next_hop_encap *encap)
{
    BUG(!buff || !encap, E_BUG);
    int r;

    if ((r = get_u8(buff, &encap->type)) != E_OK)
        return r;

    switch (encap->type) {
    case NoEncap:
        return E_OK;
    case VXLAN:
        return decode_next_hop_encap_vxlan(buff, &encap->vxlan);
    default:
        return E_INVALID_DATA;
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
static int encode_next_hops(buffer_t *buff, NumNhops num,
                            struct next_hop *nhops)
{
    BUG(!buff || !nhops, E_BUG);

    int r;
    if ((r = put_u8(buff, num)) != E_OK)
        return r;

    for (NumNhops i = 0; i < num; i++)
        if ((r = encode_next_hop(buff, &nhops[i])) != E_OK)
            return r;

    return E_OK;
}

static int decode_next_hops(buffer_t *buff, NumNhops *num,
                            struct next_hop *nhops)
{
    BUG(!buff || !nhops, E_BUG);

    int r;
    if ((r = get_u8(buff, num)) != E_OK)
        return r;

    for (NumNhops i = 0; i < *num; i++)
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

/* get_filter: encode / decode */
static int encode_getfilter(buffer_t *buff, struct get_filter *filter)
{
    int r;
    uint8_t i;
    uint8_t num_mtypes = 0;

    index_t num_mtypes_pos = buffer_get_woff(buff);

    // make room for num mtypes
    if ((r = put_u8(buff, 0)) != E_OK)
        return r;

    /* match on object type */
    if (filter->otypes.len != 0) {
        num_mtypes++;
        /* add match type */
        if ((r = put_u8(buff, MtObjType)) != E_OK)
            return r;

        /* add match type num values */
        if ((r = put_u8(buff, filter->otypes.len)) != E_OK)
            return r;

        /* add match type values */
        for (i = 0; i < filter->otypes.len; i++) {
            if ((r = put_u8(buff, filter->otypes.data[i])) != E_OK)
                return r;
        }
    }

    if (filter->vrfIds.len != 0) {
        num_mtypes++;

        /* add match type */
        if ((r = put_u8(buff, MtVrf)) != E_OK)
            return r;

        /* add match type num values */
        if ((r = put_u8(buff, filter->vrfIds.len)) != E_OK)
            return r;

        /* add match type values */
        for (i = 0; i < filter->vrfIds.len; i++) {
            if ((r = put_u32(buff, filter->vrfIds.data[i])) != E_OK)
                return r;
        }
    }

    /* write number of mtypes */
    return insert_u8(buff, num_mtypes_pos, num_mtypes);
}

static int decode_getfilter(buffer_t *buff, struct get_filter *filter)
{
    int r;
    uint8_t num_mtypes;
    if ((r = get_u8(buff, &num_mtypes)) != E_OK)
        return r;

    if (num_mtypes == 0)
        return E_OK;

    for (uint8_t i = 0; i < num_mtypes; i++) {
        /* read match type */
        MatchType mtype;
        if ((r = get_u8(buff, &mtype)) != E_OK)
            return r;

        /* read num match values */
        uint8_t num_vals;
        if ((r = get_u8(buff, &num_vals)) != E_OK)
            return r;

        switch (mtype) {
        case MtNone:
            break;
        case MtObjType: {
            ObjType otype;
            for (uint8_t j = 0; j < num_vals; j++)
                if ((r = get_u8(buff, &otype)) != E_OK)
                    return r;
                else
                    vec_push_u8(&filter->otypes, otype);
            break;
        }
        case MtVrf: {
            VrfId vrf;
            for (uint8_t j = 0; j < num_vals; j++)
                if ((r = get_u32(buff, &vrf)) != E_OK)
                    return r;
                else
                    vec_push_u32(&filter->vrfIds, vrf);
            break;
        }
        default:
            return E_INVALID_DATA;
        }
    }
    return E_OK;
}

/* disposal of objects */
static void get_filter_dispose(struct get_filter *filter)
{
    if (!filter)
        return;
    vec_dispose(&filter->otypes);
    vec_dispose(&filter->vrfIds);
}

void rpc_object_dispose(struct RpcObject *object)
{
    if (!object)
        return;
    switch (object->type) {
    case GetFilter:
        get_filter_dispose(&object->get_filter);
        break;
    default:
        break;
    }
}

/* Object wrapper encoders / decoder */
int encode_object(buffer_t *buff, struct RpcObject *object)
{
    BUG(!buff || !object, E_BUG);

    int r;
    if ((r = put_u8(buff, object->type)) != E_OK)
        return r;

    switch (object->type) {
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
    case GetFilter:
        return encode_getfilter(buff, &object->get_filter);
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

    switch (object->type) {
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
    case GetFilter:
        return decode_getfilter(buff, &object->get_filter);
    default:
        return E_INVALID_DATA;
    }
}
