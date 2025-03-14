// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#pragma once

#include "buffer.h"
#include "dp_objects.h"

struct RpcRequest {
    RpcOp op;
    MsgSeqn seqn;
    struct RpcObject object;
};

struct RpcResponse {
    RpcOp op;
    MsgSeqn seqn;
    RpcResultCode rescode;
    MsgNumObjects num_objects;
    struct RpcObject *objects;
};

struct RpcControl {
};

struct RpcNotification {
};

struct RpcMsg {
    MsgType type;
    union {
        struct RpcRequest request;
        struct RpcResponse response;
        struct RpcControl control;
        struct RpcNotification notification;
    };
};

/* messages: encode / decode */
int encode_msg(buff_t *buff, struct RpcMsg *msg);
int decode_msg(buff_t *buff, struct RpcMsg *msg);

/* utils */
int add_response_object(struct RpcResponse *response, struct RpcObject *object);
void msg_dispose(struct RpcMsg *msg);
