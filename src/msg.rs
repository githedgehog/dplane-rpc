use crate::objects::*;
use crate::wire::WireError;

/* Msg definitions */
#[doc = "A request message"]
#[derive(Debug, PartialEq)]
pub struct RpcRequest {
    pub op: RpcOp,
    pub seqn: MsgSeqn,
    pub obj: Option<RpcObject>,
}

#[doc = "A response message"]
#[derive(Debug, PartialEq)]
pub struct RpcResponse {
    pub op: RpcOp,
    pub seqn: MsgSeqn,
    pub rescode: RpcResultCode,
    // wire: num objects
    pub objs: Vec<RpcObject>,
}

#[doc = "A control message"]
#[derive(Debug, PartialEq, Default)]
pub struct RpcControl {
    // Todo: not needed now
}

#[doc = "A notification message"]
#[derive(Debug, PartialEq, Default)]
pub struct RpcNotification {
    // Todo: not needed now
}

#[doc = "A generic message wrapping all possible message types"]
#[derive(Debug, PartialEq)]
pub enum RpcMsg {
    Control(RpcControl),
    Request(RpcRequest),
    Response(RpcResponse),
    Notification(RpcNotification),
}

/* Msg: utils */
impl RpcMsg {
    #[allow(dead_code)]
    pub(crate) fn get_control(&self) -> Result<&RpcControl, ()> {
        if let RpcMsg::Control(data) = self {
            Ok(data)
        } else {
            Err(()) // should panic instead ?
        }
    }

    #[allow(dead_code)]
    pub(crate) fn get_request(&self) -> Result<&RpcRequest, ()> {
        if let RpcMsg::Request(data) = self {
            Ok(data)
        } else {
            Err(()) // should panic instead ?
        }
    }

    #[allow(dead_code)]
    pub(crate) fn get_response(&self) -> Result<&RpcResponse, ()> {
        if let RpcMsg::Response(data) = self {
            Ok(data)
        } else {
            Err(()) // should panic instead ?
        }
    }

    #[allow(dead_code)]
    pub(crate) fn get_notification(&self) -> Result<&RpcNotification, ()> {
        if let RpcMsg::Notification(data) = self {
            Ok(data)
        } else {
            Err(()) // should panic instead ?
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_control(&self) -> bool {
        matches!(self, &RpcMsg::Control(_))
    }

    #[allow(dead_code)]
    pub(crate) fn is_request(&self) -> bool {
        matches!(self, &RpcMsg::Request(_))
    }

    #[allow(dead_code)]
    pub(crate) fn is_response(&self) -> bool {
        matches!(self, &RpcMsg::Response(_))
    }

    #[allow(dead_code)]
    pub(crate) fn is_notification(&self) -> bool {
        matches!(self, &RpcMsg::Notification(_))
    }
}

/* Request: utils */
impl RpcRequest {
    #[allow(dead_code)]
    pub fn new(op: RpcOp, seqn: u64) -> Self {
        Self {
            op,
            seqn,
            obj: None,
        }
    }
    #[allow(dead_code)]
    pub fn set_object(mut self, object: RpcObject) -> Self {
        self.obj = Some(object);
        self
    }
    #[allow(dead_code)]
    pub fn get_op(&self) -> RpcOp {
        self.op
    }
    #[allow(dead_code)]
    pub fn get_seqn(&self) -> u64 {
        self.seqn
    }
    #[allow(dead_code)]
    pub fn get_object(&self) -> Option<&RpcObject> {
        self.obj.as_ref()
    }
}

/* Response: utils */
impl RpcResponse {
    #[allow(dead_code)]
    pub fn new(op: RpcOp, seqn: u64, rescode: RpcResultCode) -> Self {
        Self {
            op,
            seqn,
            rescode,
            objs: vec![],
        }
    }
    #[allow(dead_code)]
    pub fn add_object(&mut self, object: RpcObject) -> Result<(), WireError> {
        if self.objs.len() == MsgNumObjects::MAX as usize {
            Err(WireError::TooManyObjects)
        } else {
            self.objs.push(object);
            Ok(())
        }
    }
}

#[doc = "Utility trait to help building `RpcMsgs` and encoding them.
Each message type may implement it. An implementation with generics may be possible too,
but this is simpler and more explicit."]
pub trait WrapMsg {
    #[doc = "Wraps a specific message into an RpcMsg, consuming it."]
    fn wrap_in_msg(self) -> RpcMsg;

    #[doc = "Tells what type an RpcMsg contains. The return value MsgType is already a wire type"]
    fn msg_type(&self) -> MsgType;
}
impl WrapMsg for RpcMsg {
    fn wrap_in_msg(self) -> RpcMsg {
        self
    }
    fn msg_type(&self) -> MsgType {
        match self {
            RpcMsg::Control(m) => m.msg_type(),
            RpcMsg::Request(m) => m.msg_type(),
            RpcMsg::Response(m) => m.msg_type(),
            RpcMsg::Notification(m) => m.msg_type(),
        }
    }
}
impl WrapMsg for RpcRequest {
    fn wrap_in_msg(self) -> RpcMsg {
        RpcMsg::Request(self)
    }
    fn msg_type(&self) -> MsgType {
        MsgType::Request
    }
}
impl WrapMsg for RpcResponse {
    fn wrap_in_msg(self) -> RpcMsg {
        RpcMsg::Response(self)
    }
    fn msg_type(&self) -> MsgType {
        MsgType::Response
    }
}
impl WrapMsg for RpcNotification {
    fn wrap_in_msg(self) -> RpcMsg {
        RpcMsg::Notification(self)
    }
    fn msg_type(&self) -> MsgType {
        MsgType::Notification
    }
}
impl WrapMsg for RpcControl {
    fn wrap_in_msg(self) -> RpcMsg {
        RpcMsg::Control(self)
    }
    fn msg_type(&self) -> MsgType {
        MsgType::Control
    }
}
