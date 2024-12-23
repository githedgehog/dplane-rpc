#pragma once

#include "proto.h"

/**
 * @brief Type to represent a MAC address.
 *
 * MAC addresses always consist of MAC_LEN octets.
 */
struct mac_addr {
    uint8_t bytes[MAC_LEN];
};

/**
 * @brief Main type to represent an IP address.
 *
 * IP addresses appear in routes, interfaces, next-hops and IP-MAC bindings.
 * If an address object should not contain an address, its ipver has to be set
 * to NONE.
 */
struct ip_address {
    IpVer ipver;
    union {
        uint32_t ipv4;
        uint8_t ipv6[IPV6_ADDR_LEN];
    } addr;
};
