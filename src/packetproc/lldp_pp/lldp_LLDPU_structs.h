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
    CHASSIS_ID = 1,  //mandatory
    PORT_ID = 2,     //mandatory
    TTL = 3,         //mandatory
    PORT_DESC = 4,   //optional
    SYSTEM_NAME = 5, //optional
    SYSTEM_DESC = 6, //optional
    SYSTEM_CAP = 7,  //optional
    END_TLV = 0,     //optional
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

/* Internal description of an LLDP message. The second block of members can be omitted.
 * In that case the LLDPU_string data_length member is set to zero or, the LLDPU_capabilites
 * use_it member set to false */
struct LLDPU {
    /*****mandatory members*****/
    struct LLDPU_chassisId chassisId;
    struct LLDPU_portId    portId;
    struct LLDPU_TTL       TTL;

    /*****optional  members*****/
    struct LLDPU_strings port_desc;
    struct LLDPU_strings system_name;
    struct LLDPU_strings system_desc;
    struct LLDPU_capabilities system_capabilities;

    uint16_t length;
};

#endif /* LLDP_STURCTS_H */
