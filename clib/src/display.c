#include "display.h"

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
  case VerInfo:
    return "Verinfo";
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
