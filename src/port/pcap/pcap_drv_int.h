/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

/*
 * Common internal structures for the PCAP driver.
 */

#ifndef PCAP_DRV_INT_H
#define PCAP_DRV_INT_H 1

#include <ev.h>
#include <pthread.h>
#include <pcap.h>
#include <uthash/uthash.h>
#include "lib/message_box.h"
#include "lib/openflow.h"
#include "oflib/ofl_structs.h"

#define MAX_PORTS   16

struct linux_port_flags {
    uint16_t UP:1;
    uint16_t BROADCAST:1;
    uint16_t DEBUG:1;
    uint16_t LOOPBACK:1;
    uint16_t POINTOPOINT:1;
    uint16_t NOTRAILERS:1;
    uint16_t RUNNING:1;
    uint16_t NOARP:1;
    uint16_t PROMISC:1;
    uint16_t ALLMULTI:1;
    uint16_t MASTER:1;
    uint16_t SLAVE:1;
    uint16_t MULTICAST:1;
    uint16_t PORTSEL:1;
    uint16_t AUTOMEDIA:1;
    uint16_t DYNAMIC:1;
};

struct linux_port{
	char     name[20];
	int      linux_if_index;

    struct linux_port_flags flags;

    UT_hash_handle   hh;
};

struct pcap_port {
    struct pcap_drv       *drv;
    size_t                 id;
    char                  *name;
    struct logger         *logger;

    pcap_t                *pcap;
    int                    fd;
    ev_io                  *watcher;

    size_t                  dp_uid;
    of_port_no_t            dp_port_no;
    struct mbox            *pkt_mbox;
    pthread_rwlock_t       *rwlock;

    struct ofl_port        *of_port;
    struct ofl_port_stats  *of_stats;
    pthread_mutex_t        *stats_mutex;

    UT_hash_handle   hh;
};


struct pcap_drv {
    struct port_drv  *drv;

    struct logger   *logger;

    pthread_t        *thread;
    struct ev_loop   *loop;

    struct pcap_port  *ports_map;
    struct pcap_port  *ports[MAX_PORTS];
    size_t             ports_num;
    pthread_rwlock_t  *ports_rwlock;

    struct mbox       *notifier;

    struct pcap_drv_loop  *pcap_drv_loop;

	int					  netlinkfd;
	struct ev_io         *netlinkwatcher;

	struct linux_port   *linux_ports_map;
};

struct pcap_drv_loop {
    struct logger   *logger;

    struct ev_loop   *loop;

    struct pcap_drv  *pcap_drv;
};


void pcap_port_fill(struct pcap_port *pcap_port);

struct pcap_port_flags*
pcap_get_port_flags(const char *name, char *errbuf);

#endif /* PCAP_DRV_INT_H */
