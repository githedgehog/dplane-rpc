#pragma once

#include "proto.h"

const char *str_msg_type(MsgType type);
const char *str_object_type(ObjType type);
const char *str_rpc_op(RpcOp op);
const char *str_rescode(RpcResultCode code);
const char *err2str(int e);
