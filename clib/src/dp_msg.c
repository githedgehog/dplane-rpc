#include "dp_msg.h"
#include "common.h"
#include "wire.h"

/* msg:request */
static int encode_request(buff_t *buff, struct RpcRequest *req)
{
    int r;
    if ((r = put_u8(buff, req->op)))
        return r;
    if ((r = put_u64(buff, req->seqn)))
        return r;
    if ((r = encode_object(buff, &req->object)))
        return r;
    return E_OK;
}
static int decode_request(buff_t *buff, struct RpcRequest *req)
{
    int r;
    if ((r = get_u8(buff, &req->op)))
        return r;
    if ((r = get_u64(buff, &req->seqn)))
        return r;
    if ((r = decode_object(buff, &req->object)))
        return r;
    return E_OK;
}

/* msg:response */
static int encode_response(buff_t *buff, struct RpcResponse *resp)
{
    int r;

    if ((r = put_u8(buff, resp->op)))
        return r;
    if ((r = put_u64(buff, resp->seqn)))
        return r;
    if ((r = put_u8(buff, resp->rescode)))
        return r;
    if ((r = put_u8(buff, resp->num_objects)))
        return r;

    if (resp->num_objects && !resp->objects)
        return E_INVAL;

    for (MsgNumObjects i = 0; i < resp->num_objects; i++)
        if ((r = encode_object(buff, &resp->objects[i])) != E_OK)
            return r;

    return E_OK;
}
static int decode_response(buff_t *buff, struct RpcResponse *resp)
{
    int r;

    if ((r = get_u8(buff, &resp->op)))
        return r;
    if ((r = get_u64(buff, &resp->seqn)))
        return r;
    if ((r = get_u8(buff, &resp->rescode)))
        return r;
    if ((r = get_u8(buff, &resp->num_objects)))
        return r;

    /* we're done if response contains no objects */
    if (!resp->num_objects)
        return E_OK;

    /* allocate buffer to keep objects */
    resp->objects = (struct RpcObject *)calloc(resp->num_objects, sizeof(struct RpcObject));
    if (unlikely(!resp->objects)) {
        return E_OOM;
    }

    /* decode objects */
    for (MsgNumObjects i = 0; i < resp->num_objects; i++)
        if ((r = decode_object(buff, &resp->objects[i])) != E_OK)
            return r;

    return E_OK;
}

/* msg:control */
static int encode_control(buff_t *buff, struct RpcControl *ctl)
{
    // TODO
    return -1;
}
static int decode_control(buff_t *buff, struct RpcControl *ctl)
{
    // TODO
    return -1;
}

/* msg:notification */
static int encode_notification(buff_t *buff, struct RpcNotification *notif)
{
    return E_OK;
}
static int decode_notification(buff_t *buff, struct RpcNotification *notif)
{
    return E_OK;
}

/* encode / decode msg */
int encode_msg(buff_t *buff, struct RpcMsg *msg)
{
    BUG(!buff || !msg, E_BUG);
    int r;

    /* msg type */
    if ((r = put_u8(buff, msg->type)) != E_OK)
        return r;

    /* msg len: add room */
    index_t msglen_pos = buff_get_woff(buff);
    if ((r = put_u16(buff, 0)) != E_OK)
        return r;

    switch (msg->type) {
    case Control:
        r = encode_control(buff, &msg->control);
        break;
    case Request:
        r = encode_request(buff, &msg->request);
        break;
    case Response:
        r = encode_response(buff, &msg->response);
        break;
    case Notification:
        r = encode_notification(buff, &msg->notification);
        break;
    default:
        return -1;
    }
    if (r == 0)
        r = insert_u16(buff, msglen_pos, buff->w);

    return r;
}
int decode_msg(buff_t *buff, struct RpcMsg *msg)
{
    BUG(!buff || !msg, E_BUG);
    int r;

    /* msg type */
    if ((r = get_u8(buff, &msg->type)) != E_OK)
        return r;

    /* msg len */
    uint16_t msg_len = 0;
    if ((r = get_u16(buff, &msg_len)) != E_OK)
        return r;

    /* check consistency */
    if (msg_len != buff->w)
        return E_INCONSIST_LEN;

    switch (msg->type) {
    case Control:
        r = decode_control(buff, &msg->control);
        break;
    case Request:
        r = decode_request(buff, &msg->request);
        break;
    case Response:
        r = decode_response(buff, &msg->response);
        break;
    case Notification:
        r = decode_notification(buff, &msg->notification);
        break;
    default:
        return E_INVALID_MSG_TYPE;
    }
    /* check if there was data left over */
    if (r != E_OK) {
        if (buff->r != buff->w)
            return E_EXCESS_BYTES;
    }
    return r;
}

/* Response utils: add objects */
int add_response_object(struct RpcResponse *response, struct RpcObject *object)
{
    BUG(!response || !response->objects || !object, E_BUG);

    if (response->num_objects == MAX_NUM_OBJECTS)
        return E_TOO_MANY_OBJECTS;

    if (check_object_type(object->type) != E_OK)
        return E_INVAL;

    response->objects[response->num_objects++] = *object;
    return E_OK;
}

/* Response utils: free internal stuff */
static inline void msg_response_dispose(struct RpcResponse *response)
{
    if (response->objects) {
        free(response->objects);
        response->objects = NULL;
    }
}
void msg_dispose(struct RpcMsg *msg)
{
    BUG(!msg);
    switch (msg->type) {
    case Control:
        break;
    case Request:
        break;
    case Response:
        msg_response_dispose(&msg->response);
        break;
    case Notification:
        break;
    default:
        break;
    }
}
