#pragma once

#include "dp_objects.h"
#include "fmt_buff.h"
#include "proto.h"
#include <stdbool.h>

/* stringifiers */
const char *str_msg_type(MsgType type);
const char *str_object_type(ObjType type);
const char *str_rpc_op(RpcOp op);
const char *str_rescode(RpcResultCode code);
const char *err2str(int e);
const char *route_type_str(RouteType rt);

/* custom type formatters */
char *fmt_mac(struct fmt_buff *fb, bool clear, const char *prefix, struct mac_addr *mac);
char *fmt_ipaddr(struct fmt_buff *fb, bool clear, const char *disp_prefix, struct ip_address *ip);
char *fmt_prefix(struct fmt_buff *fb, bool clear, const char *disp_prefix, struct ip_address *ip, uint8_t pref_len);

/* object formatters */
char *fmt_verinfo(struct fmt_buff *fb, bool clear, struct ver_info *vinfo);
char *fmt_rmac(struct fmt_buff *fb, bool clear, struct rmac *rmac);
char *fmt_ifaddress(struct fmt_buff *fb, bool clear, struct ifaddress *ifaddr);
char *fmt_iproute(struct fmt_buff *fb, bool clear, struct ip_route *route);
char *fmt_getfilter(struct fmt_buff *fb, bool clear, struct get_filter *filter);
char *fmt_rpcobject(struct fmt_buff *fb, bool clear, struct RpcObject *object);
