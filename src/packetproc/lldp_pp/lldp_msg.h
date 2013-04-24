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

/* The notification messages' header. The notifType member can be
 * any of the value of notifType enum. Every info struct (see below)
 * has this header, so it is safe to cast like the ofp_header type*/
struct notifData {
    uint8_t status:4;
    uint8_t notifType:4;

    size_t length;
};

/* Notification structure about a chassis */
struct chassisInfo {
    struct notifData notifData;
    enum LldpChassisIdSubtype chassisIdSubtype;
    char    *chassisId;
    char    *sysName;
    char    *sysDesc;
};

/* Notification structure about a port */
struct portInfo {
    struct notifData notifData;
    struct chassisInfo *chassis;
    uint16_t    portNumber;
    enum LldpPortIdSubtype portIdSubtype;
    char    *portId;
    char    *portDesc;
};

/* Notification structure about a link */
struct linkInfo { 
    struct notifData notifData;
    struct portInfo    *srcPort;
    struct portInfo    *dstPort;
};

/* If there is a change in the MIB, create and send one or more
 * notifData messages. Used by the MIB's notifTimer. */
void
notifyCtrl(struct LldpMIB *lldpMIB);

#endif /* LLDP_MSG_H */
