/* Package version:  */

/* --- Do NOT edit this file -- */

#pragma once

/* Generated with cbindgen:0.27.0 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define VER_DP_MAJOR 0

#define VER_DP_MINOR 1

#define VER_DP_PATCH 0

#define MAC_LEN 6

#define IPV4_ADDR_LEN 4

#define IPV6_ADDR_LEN 16

/**
 *The type of encapsulation towards some next-hop. NoEncap if no encapsulation is used.
 */
enum EncapType {
  NoEncap = 0,
  VXLAN = 1,
};
typedef uint8_t EncapType;

/**
 *Ip version for an address or prefix. None if not present.
 */
enum IpVer {
  NONE = 0,
  IPV4 = 1,
  IPV6 = 2,
};
typedef uint8_t IpVer;

/**
 *A type of match indicated in a GetFilter object in a Get request.
 */
enum MatchType {
  MtNone = 0,
  MtObjType = 1,
  MtVrf = 2,
};
typedef uint8_t MatchType;

/**
 *Code for the type of a message
 */
enum MsgType {
  Control = 1,
  Request = 2,
  Response = 3,
  Notification = 4,
};
typedef uint8_t MsgType;

/**
 *The type of object that a request operation refers to, such as a route.
 */
enum ObjType {
  None = 0,
  VerInfo = 1,
  IfAddress = 2,
  Rmac = 3,
  IpRoute = 4,
  GetFilter = 5,
};
typedef uint8_t ObjType;

/**
 *A type of route.
 */
enum RouteType {
  Connected = 1,
  Static = 2,
  Bgp = 3,
  Other = 4,
};
typedef uint8_t RouteType;

/**
 *The operation to perform in a request.
 */
enum RpcOp {
  Connect = 1,
  Add = 2,
  Del = 3,
  Update = 4,
  Get = 5,
};
typedef uint8_t RpcOp;

/**
 *Code for the result within a response.
 */
enum RpcResultCode {
  Ok = 1,
  Failure = 2,
  InvalidOperation = 3,
  ExpectMore = 4,
};
typedef uint8_t RpcResultCode;

/**
 *Number of next-hops that a route has
 */
typedef uint8_t NumNhops;

/**
 *A type to indicate the number of objects within a response
 */
typedef uint8_t MsgNumObjects;

/**
 *The Id or sequence number of a message
 */
typedef uint64_t MsgSeqn;

/**
 *The length of a message in octets
 */
typedef uint16_t MsgLen;

/**
 *The admin distance of a route
 */
typedef uint8_t RouteDistance;

/**
 *The metric for a route, depending on its type
 */
typedef uint32_t RouteMetric;

/**
 *The Id of a routing table (kernel)
 */
typedef uint32_t RouteTableId;

/**
 *Ifindex of a network interface
 */
typedef uint32_t Ifindex;

/**
 *An IP address or prefix mask length
 */
typedef uint8_t MaskLen;

/**
 *An EVPN/VxLAN virtual network Id
 */
typedef uint32_t Vni;

/**
 *The Id for a VRF
 */
typedef uint32_t VrfId;

#define MAX_NUM_NHOPS UINT8_MAX

#define MAX_NUM_OBJECTS UINT8_MAX
