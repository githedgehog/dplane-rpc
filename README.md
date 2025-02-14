# Control-Plane-to-Data-plane Communications
This repository contains the specification and implementation of the **wire format** used to communicate the control plane (CP) and data plane (DP) of the Hedgehog Gateway.
A **binary** format has been chosen (instead of a text-based, human-readable one such as JSON) for performance reasons.
The format is proprietary to avoid depending on third-party solutions (like gRPC, Protobufs or Capn'proto).
Since the communication will happen between components written in distinct languages (C and Rust), the specification of a wire format implies that 2 implementations are needed (one per language).
However, it avoids the need to generate bindings from C to Rust or Rust to C, the dependency on additional tools (bindgen or cbindgen with their own limitations) and additional data-type conversions from the auto-generated code; which is usually not too ergonomic, may impose some penalty and also requires coding and maintenance effort.


It is expected that the communication happens locally over a unix socket, in a message (datagram) oriented fashion.
Still, the wire format is such that other transports could be used if needed.

## License

This package is licensed under the
[Apache License, Version 2.0](LICENSE).

## General considerations, patterns, semantics and rules
* The communication between the CP and DP can be thought of as an **RPC**  consisting, mostly, of **request-response** pairs.
To accommodate for future needs, the wire format has been conceived to allow for other message types (e.g.
**notifications** and **control** messages).
Also, while most exchanges may consist in the CP issuing requests for the DP, the format is such that any type of message may be easily parsed by either end so that no limits are introduced in the communication.
For instance, we may need the DP to issue some type of requests to the CP.


* Requests and responses are identified with a **sequence number** so that  requesters can match responses to requests.
This is not strictly needed in a lossless channel.
However, the communication should be such that multiple requests (and responses) can be in flight.
Sequencing should help pairing responses and logging and troubleshooting.

* All requests **MUST** be answered (as opposed to other messages like notifications or control).

* The handling of requests **MUST be ordered** to avoid race conditions: a peer may not execute request N before processing request K for any K<N.

* The interactions are expected to be mostly CRUD-like.
Hence, requests may include a certain **object** to be `added`, `deleted`,  `updated` or retrieved (`get`).
The  `get` operation is included so that this same wire format can be used to retrieve the internal state of the DP on request.
In addition, a `connect` operation is included as part of a request.
The purpose of this is to check that both ends use the same version of the protocol.


* Requests may carry **one object at the most**, the reason being that this significantly eases the handling of errors and transactionality: E.g.
if a request would carry, say, two routes A and B and the installation of A succeeded but that of B didn't, it would be harder to convey this result to the CP.
Wrapping each route in a separate request eases the handling of such a situation since two responses will be issued, each with its own sequence number and result code.
The wire format allows for requests not to carry any object at all, even if semantically this may be meaningless in a CRUD fashion.

* Responses may carry multiple objects to allow for state-retrieval operations.

* Since the communication may be local over a Unix socket, peers should know if the other end is alive / responsive.
Control messages are intended to suit that purpose (e.g.
by including some keepalive control message).

* There should be a way to "regain synchronization" in the unfortunate case where a message cannot be successfully decoded.
The notification messages are intended for that purpose; at least to report that a fatal condition occurred.

* Need to determine:
	* error handling and behaviors
	* these may be decided/specified later, irrespective of the wire format.
The importance is that the wire format does not limit possibilities.


## The wire format
On the wire, all messages start with a **Type** code and a message length (msglen).
Type indicates the type of message (Request, Response, Notification or Control) and msglen is used as a check for completeness.

Type has only one octet.
This allows for 256 message types, which should suffice in all cases.
A message length of 2 octets allows to encode messages of up to 64K, which should be sufficient in most cases.
The only case where that may impose a limit is in state-retrieval operations.
While we could extend it to 4 octets, sending huge messages may not be ideal for memory reasons at the receiving side.
In order to handle such a situation, we may just add some flag in a response (to a get operation) indicating if more response messages follow.

```
+-------+-----------+-------------------------- - - - -------------------+
|       |           |                                                    |
| Type  |  msglen   |    Contents and length depend on Type              |
|  (1)  |    (2)    |                                                    |
+-------+-----------+-------------------------- - - - -------------------+
```

The format of a request is as shown below:
```
+ - - - +  - - - -  +-----+--------------------+--------+----------------------------+
|       |           |     |                    |        |                            |
| Req   |  msglen   | op  |  sequence number   | oType  |          Object            |
|       |           | (1) |        (8)         |  (1)   |     (variable sized)       |
+- - - -+  - - - -  +-----+--------------------+--------+----------------------------+
```

where:

* **op**: 1 octet, indicates the type of request (Add, Delete, Update, Get)
* **sequence-number**: 8 octets, is the request number which may be unlimited in practice.

* **oType**: 1 octet, encodes the type of object that follows.
A special code denotes no object.
This allows for 256 distinct objects.

* **Object**: corresponds to a certain object (e.g.
an interface address, route or router-MAC).


The format of a response is
```
+- - - -+ - - - - +-----+--------------------+------+----------+----------+---------+----------+-------+- - - ------+
|       |         |     |                    |      |          |          |         |          |       |            |
| Resp  |  msglen | op  |  sequence number   |result| num-objs |   oType  | Object  |   oType  | Object|            |
|       |         | (1) |        (8)         |  (1) |    (1)   |    (2)   |         |    (2)   |       |            |
+- - - -+- - - - -+-----+--------------------+------+----------+----------+---------+----------+-------+- - - ------+
```

where:

* **op** and **sequence-number** match those of the corresponding request.

* **result** indicates the outcome of the request and consumes one octet, allowing for 255 distinct results.

* **num-objects** indicates the number of objects that follow.
In order to be able to send objects of distinct types, each object is preceded by its type on the wire.
1 octet is used, which allows sending 256 objects at a time, provided that they fit in the maximum message length of 64K.



### To TLV or not

The objects exchanged within request/responses may be of distinct sizes.
Moreover, objects may have a variable number of subobjects (e.g. routes may have a variable number of next-hops), or optional properties / fields.
For instance, next-hops may optionally include encapsulation information whose size and encoding may depend on the type of encapsulation.
One approach to encode such variability is defining a basic set of types and encoding each object as a collection of TLVs.
While valid, that approach may unnecessarily complicate (and slow down) the building and decoding of objects.
In the CP-DP communication, in most cases, objects will have a fixed set of properties without which they are meaningless.
For instance, a router-mac must have an IP address (v4 or v6), a MAC and a VNI.
Therefore, not using TLVs may be more efficient and faster: unlike with TLVs, object properties may have a fixed position within the wire format.
The caveat is that all of the fields, present or not, need to be encoded on the wire in order to unambiguously recreate the original object back.
To signal the presence of optional values (or their absence), a code will be used, whose value will indicate the size of the field.
For instance, next-hops may include a next-hop IP address or not (e.g. in directly-connected routes).
If present, the IP address may be either IPv4 or IPv6.
Whether a next-hop has an ip address or not, on the wire:

* an octet always indicates the type of address, where "no-address" is a valid value for an address.

* that same type of address implicitly indicates the size of the field on the wire, which is zero if "no-address".

* This gives 3 possible representations for an IP addresses on the wire:
```
+----+
| no |
| ne | 1 octet
+----+
+----+------------+
|    |  address   |
| v4 |  4 octets  | 5 octets
+----+------------+
+----+----------------------------------------------+
|    |  address                                     |
| v6 |  16 octets                                   | 17 octets
+----+----------------------------------------------+
```

Similarly, fields containing text or strings are represented by a variable-sized number of octets, preceded by their number (not including trailing \0), encoded as one octet, as shown next.
```
+----------+---------------+
| text-len |     text      |
|   (1)    |   (variab)    |
+----------+---------------+
```
Since one octet is used to encode the string length, only strings up to 255 characters are allowed.
The string length shall always be present, as occurs with IP address types.
Therefore, an empty string is encoded as a zero-valued octet.

### Endianness
The endianness for the fields in the wire format is currently **native**.
This is a natural choice considering that both CP and DP will run on the same platform.
Enforcing a particular endianness can be easily done if needed.


## Object types
Objects that we have identified so far include the following.
These may appear in requests (e.g. an object to be `add`ed) or in responses to a `get` request. They could also be added in other type of responses if that was needed.


### Interface address
**Purpose**: The IP address (IPv4 or IPv6) to be configured in an interface.
The dataplane should punt any traffic received that is destined to any of the IP addresses configured in the interfaces.


**format**.
The wire format is as follows, where the Ip address is encoded as described.
In this case, however, the decoder will complain if the address is no-address since, semantically, that is not allowed.


```
+------------+-----+----------+-----------+----------------+
| IpAddress  | len |  ifindex |  vrfid    |     ifname     |
|  (variab)  | (1) |    (4)   |   (4)     |    (variab)    |
+------------+-----+----------+-----------+----------------+
```

### Route
**Purpose**: Routes tell the dataplane how to reach to IP destinations in both the underlay and overlay.
Routes always include an IP prefix (IPv4 or IPv6) and prefix length, and one or more next-hops.
On the wire, the number of next-hops is encoded as one octet.
This limits the number of next-hops to 255, which should suffice in all cases.


**format**: The format is as follows.

```
+------------+-----+--------+-----------+-----+----+---------+-----+-----------+ - - -------+
|  Prefix    | len |  vrfid | tableid   |type | AD | metric  |numNH|  next-hop |  next-hop  |
| (address)  | (1) |   (4)  |    (4)    | (1) |(1) |  (4)    | (1) |           |            |
+------------+-----+--------+-----------+-----+----+---------+-----+-----------+ - - -------+
```
Prefix is encoded `exactly as an IP address` and is mandatory in routes.
Len is one octet.
The meaning of the rest of fields is the following:
  * `vrfid` is the Id of the VRF where the route resides.
  * `tableid` is the Id of the corresponding kernel table. This field is mostly for diagnostics.
  * `type` is the type of route (e.g. protocol) and admits several values (Connected, Static, Bgp...)
  * `AD` is administrative distance of the route.
  * `metric` is the protocol-dependant cost associated to the route.
  * `numNH` is the number of next-hops that this route has.

The encoding of each next-hop is as follows:
```
+-----+------------+----------+-----------+-------+----------+
|fwAct| IpAddress  | ifindex  |  vrfid    |encType|  encap   |
|     |  (variab)  |   (4)    |   (4)     |  (1)  | specific |
+-----+------------+----------+-----------+-------+----------+
```
  * `fwAct` indicates the action associated with the next-hop (should be `forward` in most cases, but `drop` is allowed too).
  * `IPAddress` is optional.
  * `ifindex` is optional.
  * `encType` indicates the type of encapsulation. The octets that follow depend on this type.
     Two types are defined so far: ``no-encap`` and ``VxLAN``.
     If ``VxLAN``, the encap-specific chunk is 4 octets in length and contains the VNI.



### Router MAC
**Purpose**: This is a tuple (IP, MAC, VNI) that the GW will need in order to VxLAN-encapsulate a packet towards a VPC.
The IP corresponds to a VTEP.
The outer header of the encapsulation will have IP as destination address.
The dataplane will need to recursively resolve how to reach that address according to the default VRF route (underlay).
In general, such a resolution should provide a next-hop address and outgoing interface.
The dataplane should determine the mac of the next-hop and the mac of the local outgoing interface in order to write the outer Ethernet header.


**format**: As with interface addresses, the IP address cannot be no-address.


```
+-----------+---------------+------------+
| IpAddress |  MAC address  |    VNI     |
|  (variab) |     (6)       |    (4)     |
+-----------+---------------+------------+
```

### GetFilter

**Purpose**: When performing a Get request, it may be desirable to retrieve only certain types of objects, or only those that meet some criteria.
The GetFilter is the object used to that end and includes optional lists of `match types`. A match type indicates a property of an object and the `GetFilter` can specify the set of values that such a property (and others) can have for objects to be eligible. For instance, if a match type is `VrfId` with its corresponding values (100, 200, 300), then only objects associated with those VRFs should be retrieved (logical OR). If more than a match type is specified, objects qualify when they match all of the match types, in other words, when they satisfy all the conditions (logical AND).

**format**: The format is as shown below. An octet (num Mtypes) indicates the number of distinct match types present, and appears once.
That number is followed by a match type code (Mtype), the number of 'allowed' values, and the values themselves.

```
+-------+-------+-----+----------++-------+-----+-----+-----+-----++-------+-----+-----+-----+
|  num  | Mtype | num | value(s) || Mtype | num |  values(s)      || Mtype | num | value(s)  |
| Mtypes|  (1)  | (1) |          ||  (1)  | (1) |                 ||  (1)  | (1) |           |
+-------+-------+-----+----------++-------+-----+-----+-----+-----++-------+-----+-----+-----+
   (1)
```
For instance, to retrieve only objects of type `route`, the wire encoding of the `GetFilter` would be:

```
+-------+-------+-----+-----+
|  1    | object| 1   |type |
|       | type  |     |route|
+-------+-------+-----+-----+
```
because there is only one match type `Mtype = Object-type` with one value `type route`.
If additional filtering was desired so that only the routes of VRFs 100, 200 and 300 were wanted, an additional match type `VrfId` could be added with those values and the encoding be would be:

```
+-------+-------+-----+-----++-------+-----+-----+-----+-----+
|  2    | object| 1   |type || vrfid |  3  | 100 | 200 | 300 |
|       | type  |     |route||       |     |     |     |     |
+-------+-------+-----+-----++-------+-----+-----+-----+-----+
```
Note:
* The order of match types does not matter, nor does that of the values within each match type.

* On the wire, the size of the **values** for a given match type is implied by the type of match. E.g. if a match type is a vrfId, the vrf Ids that follow are 4 octets in length since that is the size that is used throughout to encode VRF Ids.


## Code organization

[proto.rs](./src/proto.rs): contains the codes, constants and their sizes that the wire protocol relies on.
It does not contain any structured data nor wire layout, which is implicit in the respective encoding / decoding rust functions (see trait `Wire`).
This is the **source of truth** for the wire protocol constants and values.
This file is processed by cbindgen to produce a `C header` file with these definitions.
No code should be needed in this file.
The rest of the source files are for the implementation of the wire format in Rust.

[objects.rs](./src/objects.rs): contains type definitions for the `objects` exchanged between CP and DP.
The types chosen are rust-friendly and may be reused for the internals of the dataplane code.
Again, these types are not part of the wire format in that their layout, while related, is independent of the encoding.

[msg.rs](./src/msg.rs): contains definitions for the message types so far defined (e.g. Request, Response, etc..), some utilities to work with them and an auxiliary trait `WrapMsg` that eases some operations in the Rust implementation.

[wire.rs](./src/wire.rs) This contains the implementation of the `Wire` trait, which consists in two functions: `encode()` and `decode()`.
The trait is implemented for messages and objects in a somewhat hierarchical manner.
99% of the logic is here.


## Adding new message types

Adding new message types is simple and requires:

  * defining a type for the message (rust struct)
  * implementing a tiny trait `WrapMsg` for it
  * implementing the `Wire` trait.
  * adding a variant to enum `RpcMsg` and extending its `Wire` implementation by calling the new message `Wire` trait methods/functions.
  * adding a new variant to `MsgType`enum in proto.rs (plus other definitions if needed)

## Handling versioning, updates and backwards compatibility

For the time being an operation `Connect` within a request has been added.
This request contains the `name` of the connecting entity, its `pid` and a version information object (`VerInfo`) that the peer (e.g. DP) may use to double check that the CP uses the same version of the wire format/protocol.
The name (string) and pid are informational and may allow the DP to know if a peer has restarted.
The wire format of Verinfo is as follows:
```
+------------+---------+------------+
|   name     |  pid    |version info|
| (variable) |  (4)    |    (3)     |
+------------+---------+------------+
```
 .. where the version info is 3 octets (Major|Minor|Patch).


