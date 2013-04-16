/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef LLDP_STURCTS_H
#define LLDP_STURCTS_H

#include <inttypes.h>
#include <stdbool.h>

#define HEADER_SIZE 2
#define MANDATORY_HEADER_SIZE 12

enum TLV_types {
    CHASSIS_ID = 1,
    PORT_ID = 2,
    TTL = 3,
    PORT_DESC = 4,
    SYSTEM_NAME = 5,
    SYSTEM_DESC = 6,
    SYSTEM_CAP = 7,
    END_TLV = 0,
};

struct LLDPU_header {
    uint16_t type:7;
    uint16_t length:9;

    uint8_t data[0];
};

struct LLDPU_chassisId {
    uint8_t  subtype;

    uint16_t   data_length;
    uint8_t *data;
};

struct LLDPU_portId {
    uint8_t subtype;

    uint16_t data_length;
    uint8_t *data;
};

struct LLDPU_TTL {
    uint16_t seconds;
};

struct LLDPU_strings {
    uint16_t data_length;
    uint8_t *data;
};

struct LLDPU_capabilities {
    bool use_it;
    uint16_t capabilities;
    uint16_t enabled;
};

struct LLDPU {
    struct LLDPU_chassisId chassisId;
    struct LLDPU_portId    portId;
    struct LLDPU_TTL       TTL;

    struct LLDPU_strings port_desc;
    struct LLDPU_strings system_name;
    struct LLDPU_strings system_desc;
    struct LLDPU_capabilities system_capabilities;

    uint16_t length;
};

#endif /* LLDP_STURCTS_H */
