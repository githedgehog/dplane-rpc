// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#include <arpa/inet.h>

#include "common.h"
#include "display.h"
#include "dp_msg.h"
#include "dp_objects.h"
#include "errors.h"
#include "fmt_buff.h"

/* Stringify message type */
const char *str_msg_type(MsgType type)
{
    switch (type) {
    case Control:
        return "Control";
    case Request:
        return "Request";
    case Response:
        return "Response";
    case Notification:
        return "Notification";
    default:
        return "Unknown";
    }
}

/* Stringify object type */
const char *str_object_type(ObjType type)
{
    switch (type) {
    case None:
        return "None";
    case ConnectInfo:
        return "ConnectInfo";
    case IfAddress:
        return "IfAddress";
    case Rmac:
        return "Rmac";
    case IpRoute:
        return "Iproute";
    case GetFilter:
        return "Getfilter";
    default:
        return "Unknown";
    }
}

/* Stringify request operation */
const char *str_rpc_op(RpcOp op)
{
    switch (op) {
    case Connect:
        return "Connect";
    case Add:
        return "Add";
    case Del:
        return "Delete";
    case Update:
        return "Update";
    case Get:
        return "Get";
    default:
        return "Unknown";
    }
}

/* stringify response result code */
const char *str_rescode(RpcResultCode code)
{
    switch (code) {
    case Ok:
        return "Ok";
    case Failure:
        return "Failure";
    case InvalidRequest:
        return "InvalidRequest";
    case Unsupported:
        return "Unsupported";
    case ExpectMore:
        return "ExpectMore";
    default:
        return "Unknown";
    }
}

/* stringify library return codes */
const char *err2str(int e)
{
    switch (e) {
    case E_OK:
        return "Ok";
    case E_BUG:
        return "Bug";
    case E_OOM:
        return "Out-of-memory";
    case E_NOT_ENOUGH_DATA:
        return "Not-enough-data";
    case E_TOO_BIG:
        return "Msg-too-big";
    case E_INVAL:
        return "Invalid argument";
    case E_INVALID_DATA:
        return "Invalid data";
    case E_INCONSIST_LEN:
        return "Msg-inconsistent-length";
    case E_INVALID_MSG_TYPE:
        return "Invalid msg type";
    case E_EXCESS_BYTES:
        return "Excess data";
    case E_TOO_MANY_NHOPS:
        return "Too many next-hops";
    case E_TOO_MANY_OBJECTS:
        return "Too many objects";
    case E_TOO_MANY_MATCH_VALUES:
        return "Too many match values";
    case E_VEC_CAPACITY_EXCEEDED:
        return "Vector capacity exceeded";
    case E_STRING_TOO_LONG:
        return "String is too long";
    default:
        return "Other/Unknown";
    }
}

/* stringify iproute type/protocol */
const char *route_type_str(RouteType rt)
{
    switch (rt) {
    case Connected:
        return "connected";
    case Static:
        return "static";
    case Ospf:
        return "OSPF";
    case Isis:
        return "IS-IS";
    case Bgp:
        return "BGP";
    case Other:
        return "Other";
    default:
        return "Unknown";
    }
}

/* stringify iproute forward action */
const char *route_fwaction_str(ForwardAction a)
{
    switch (a) {
    case Forward: return "forward";
    case Drop: return "drop";
    default: return "unknown";
    }
}

/* basic type formatters */
char *fmt_mac(struct fmt_buff *fb, bool clear, const char *prefix, struct mac_addr *mac)
{
    BUG(!fb || !mac, NULL);
    if (clear)
        clear_fmt_buff(fb);

    if (prefix)
        fmt_buff(fb, "%s", prefix);

    return fmt_buff(fb, "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac->bytes[0], mac->bytes[1],
                    mac->bytes[2], mac->bytes[3],
                    mac->bytes[4], mac->bytes[5]);
}
char *fmt_ipaddr(struct fmt_buff *fb, bool clear, const char *disp_prefix, struct ip_address *ip)
{
    BUG(!fb || !ip, NULL);
    char b[INET_ADDRSTRLEN];
    if (clear)
        clear_fmt_buff(fb);

    if (disp_prefix)
        fmt_buff(fb, "%s", disp_prefix);

    switch (ip->ipver) {
    case NONE:
        return fmt_buff(fb, "none");
    case IPV4:
        return fmt_buff(fb, "%s", inet_ntop(AF_INET, &ip->addr, b, sizeof(b)));
    case IPV6:
        return fmt_buff(fb, "%s", inet_ntop(AF_INET6, &ip->addr, b, sizeof(b)));
    default:
        return fmt_buff(fb, "unknown IP version '%u'", ip->ipver);
    }
}
char *fmt_prefix(struct fmt_buff *fb, bool clear, const char *disp_prefix, struct ip_address *ip, uint8_t pref_len)
{
    BUG(!fb || !ip, NULL);
    char b[INET_ADDRSTRLEN];
    if (clear)
        clear_fmt_buff(fb);

    if (disp_prefix)
        fmt_buff(fb, "%s", disp_prefix);

    switch (ip->ipver) {
    case NONE:
        return fmt_buff(fb, "none");
    case IPV4:
        return fmt_buff(fb, "%s/%u", inet_ntop(AF_INET, &ip->addr, b, sizeof(b)), pref_len);
    case IPV6:
        return fmt_buff(fb, "%s/%u", inet_ntop(AF_INET6, &ip->addr, b, sizeof(b)), pref_len);
    default:
        return fmt_buff(fb, "unknown IP version '%u'", ip->ipver);
    }
}

/* object formatters */
static char *fmt_verinfo(struct fmt_buff *fb, bool clear, struct ver_info *v)
{
    BUG(!fb || !v, NULL);
    if (clear)
        clear_fmt_buff(fb);
    return fmt_buff(fb, "verinfo: %u.%u.%u", v->major, v->minor, v->patch);
}
char *fmt_conninfo(struct fmt_buff *fb, bool clear, struct conn_info *c)
{
    BUG(!fb || !c, NULL);
    if (clear)
        clear_fmt_buff(fb);

    fmt_buff(fb, "ConnInfo ─── name: %s pid: %u ", c->name, c->pid);
    return fmt_verinfo(fb, false, &c->verinfo);
}
char *fmt_rmac(struct fmt_buff *fb, bool clear, struct rmac *rmac)
{
    BUG(!fb || !rmac, NULL);
    if (clear)
        clear_fmt_buff(fb);

    fmt_buff(fb, "rmac ─── vni: %u", rmac->vni);
    fmt_ipaddr(fb, false, " ip:", &rmac->address);
    return fmt_mac(fb, false, " mac:", &rmac->mac);
}
char *fmt_ifaddress(struct fmt_buff *fb, bool clear, struct ifaddress *ifaddr)
{
    BUG(!fb || !ifaddr, NULL);
    if (clear)
        clear_fmt_buff(fb);
    fmt_buff(fb, "Ifaddress ─── ifname: %s", ifaddr->ifname);
    fmt_prefix(fb, false, " ip:", &ifaddr->address, ifaddr->len);
    return fmt_buff(fb, " ifindex:%u vrfid:%u", ifaddr->ifindex, ifaddr->vrfid);
}
char *fmt_iproute(struct fmt_buff *fb, bool clear, struct ip_route *route)
{
    BUG(!fb || !route, NULL);
    if (clear)
        clear_fmt_buff(fb);
    fmt_buff(fb, "Iproute ─── vrfid:%u tbl:%u", route->vrfid, route->tableid);
    fmt_buff(fb, " %s [%u/%u]", route_type_str(route->type), route->distance, route->metric);
    fmt_prefix(fb, false, " ", &route->prefix, route->len);

    struct next_hop *nhop;
    for (unsigned int i = 0; i < route->num_nhops; i++) {
        nhop = &route->nhops[i];
        if (nhop->address.ipver == IPV4 || nhop->address.ipver == IPV6)
            fmt_ipaddr(fb, false, " via", &nhop->address);
        if (nhop->ifindex)
            fmt_buff(fb, " ifindex:%u", nhop->ifindex);
        fmt_buff(fb, " vrfid:%u", nhop->vrfid);
        if (nhop->fwaction != Forward)
            fmt_buff(fb, " action: %s", route_fwaction_str(nhop->fwaction));

        switch (nhop->encap.type) {
        case NoEncap:
            break;
        case VXLAN:
            fmt_buff(fb, " encap: VxLAN(vni:%u)", nhop->encap.vxlan.vni);
            break;
        default:
            fmt_buff(fb, " encap: unknown type (%u)", nhop->encap.type);
            break;
        }
    }
    return fb->buff;
}
char *fmt_getfilter(struct fmt_buff *fb, bool clear, struct get_filter *filter)
{
    BUG(!fb || !filter, NULL);
    if (clear)
        clear_fmt_buff(fb);

    fmt_buff(fb, "Getfilter ─── otypes(%zu):", filter->otypes.len);
    for (size_t i = 0; i < filter->otypes.len; i++) {
        uint8_t otype = filter->otypes.data[i];
        fmt_buff(fb, " %s", str_object_type(otype));
    }

    fmt_buff(fb, " vrfIds(%zu):", filter->vrfIds.len);
    for (size_t i = 0; i < filter->vrfIds.len; i++) {
        uint32_t vrfid = filter->vrfIds.data[i];
        fmt_buff(fb, " %u", vrfid);
    }
    return fb->buff;
}
char *fmt_rpcobject(struct fmt_buff *fb, bool clear, struct RpcObject *object)
{
    BUG(!fb || !object, NULL);

    switch (object->type) {
    case None:
        if (clear)
            clear_fmt_buff(fb);
        return fmt_buff(fb, "none");
    case ConnectInfo:
        return fmt_conninfo(fb, clear, &object->conn_info);
    case IfAddress:
        return fmt_ifaddress(fb, clear, &object->ifaddress);
    case Rmac:
        return fmt_rmac(fb, clear, &object->rmac);
    case IpRoute:
        return fmt_iproute(fb, clear, &object->route);
    case GetFilter:
        return fmt_getfilter(fb, clear, &object->get_filter);
    default:
        if (clear)
            clear_fmt_buff(fb);
        return fmt_buff(fb, "unknown object type '%u'", object->type);
    }
}

/* Msg formatters */
char *fmt_rpc_request(struct fmt_buff *fb, bool clear, struct RpcRequest *req)
{
    BUG(!fb || !req, NULL);
    if (clear)
        clear_fmt_buff(fb);

    fmt_buff(fb, "Request #%lu %s ", req->seqn, str_rpc_op(req->op));
    return fmt_rpcobject(fb, false, &req->object);
}
char *fmt_rpc_response(struct fmt_buff *fb, bool clear, struct RpcResponse *res)
{
    BUG(!fb || !res, NULL);
    if (clear)
        clear_fmt_buff(fb);

    fmt_buff(fb, "Response #%lu: %s", res->seqn, str_rescode(res->rescode));
    for (uint8_t i = 0; i < res->num_objects; i++) {
        fmt_buff(fb, " [%u]: ", i);
        fmt_rpcobject(fb, false, &res->objects[i]);
    }
    return fb->buff;
}
char *fmt_rpc_control(struct fmt_buff *fb, bool clear, struct RpcControl *ctl)
{
    BUG(!fb || !ctl, NULL);
    if (clear)
        clear_fmt_buff(fb);
    return fmt_buff(fb, "Control");
}
char *fmt_rpc_notification(struct fmt_buff *fb, bool clear, struct RpcNotification *ctl)
{
    BUG(!fb || !ctl, NULL);
    if (clear)
        clear_fmt_buff(fb);
    return fmt_buff(fb, "Notification");
}
char *fmt_rpc_msg(struct fmt_buff *fb, bool clear, struct RpcMsg *msg)
{
    BUG(!fb || !msg, NULL);
    if (clear)
        clear_fmt_buff(fb);
    switch (msg->type) {
    case Control:
        return fmt_rpc_control(fb, false, &msg->control);
    case Request:
        return fmt_rpc_request(fb, false, &msg->request);
    case Response:
        return fmt_rpc_response(fb, false, &msg->response);
    case Notification:
        return fmt_rpc_notification(fb, false, &msg->notification);
    default:
        return fmt_buff(fb, "Unknown msg type '%u'", msg->type);
    }
}
