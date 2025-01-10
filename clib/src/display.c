#include "display.h"
#include "errors.h"

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
