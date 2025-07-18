// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#pragma once

#include "dp_msg.h"
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
char *fmt_conninfo(struct fmt_buff *fb, bool clear, struct conn_info *c);
char *fmt_rmac(struct fmt_buff *fb, bool clear, struct rmac *rmac);
char *fmt_ifaddress(struct fmt_buff *fb, bool clear, struct ifaddress *ifaddr);
char *fmt_iproute(struct fmt_buff *fb, bool clear, struct ip_route *route);
char *fmt_rpcobject(struct fmt_buff *fb, bool clear, struct RpcObject *object);

/* message formatters (in fmt_buff) */
char *fmt_rpc_request(struct fmt_buff *fb, bool clear, struct RpcRequest *req);
char *fmt_rpc_response(struct fmt_buff *fb, bool clear, struct RpcResponse *res);
char *fmt_rpc_control(struct fmt_buff *fb, bool clear, struct RpcControl *ctl);
char *fmt_rpc_notification(struct fmt_buff *fb, bool clear, struct RpcNotification *ctl);
char *fmt_rpc_msg(struct fmt_buff *fb, bool clear, struct RpcMsg *msg);
