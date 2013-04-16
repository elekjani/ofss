/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef LLDP_MSG_H
#define LLDP_MSG_H 1

enum notifType {
    CHASSIS_INFO = 1,
    PORT_INFO    = 2,
    LINK_INFO    = 3,
};


struct notifData {
    uint8_t status:4;
    uint8_t notifType:4;

    size_t length;
};

struct chassisInfo {
    struct notifData notifData;
    enum LldpChassisIdSubtype chassisIdSubtype;
    char    *chassisId;
    char    *sysName;
    char    *sysDesc;
};

struct portInfo {
    struct notifData notifData;
    struct chassisInfo *chassis;
    uint16_t    portNumber;
    enum LldpPortIdSubtype portIdSubtype;
    char    *portId;
    char    *portDesc;
};

struct linkInfo { 
    struct notifData notifData;
    struct portInfo    *srcPort;
    struct portInfo    *dstPort;
};

void
notifyCtrl(struct LldpMIB *lldpMIB);

#endif /* LLDP_MSG_H */
