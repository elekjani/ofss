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
 * Represents a port of the PCAP driver.
 */

#include <stdbool.h>
#include <stddef.h>
#include <ev.h>
#include <pthread.h>
#include <pcap.h>
#include "datapath/dp_mgr.h"
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "lib/pkt_buf.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "oflib/ofl_structs.h"
#include "pcap_drv_int.h"
#include "pcap_port.h"

#define PCAP_SNAPLEN 65535

static void
event_loop_packet_in_cb(struct ev_loop *loop, ev_io *w, int revents);

struct pcap_port*
pcap_reopen(struct pcap_port *pcap_port) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_drv *pcap_drv = pcap_port->drv;

    if (pcap_port->pcap != NULL) {
        pcap_close(pcap_port->pcap);
    }

    pcap_port->pcap = pcap_open_live(pcap_port->name, PCAP_SNAPLEN, true/*promisc*/, -1/*to_ms*/, errbuf);
    if (pcap_port->pcap == NULL) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to open device %s: %s.", pcap_port->name, errbuf);
        return NULL;
    }

    if(pcap_setnonblock(pcap_port->pcap, true, errbuf) != 0) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to set device to promisc %s: %s.", pcap_port->name, errbuf);
        return NULL;
    }

    if(pcap_setdirection(pcap_port->pcap, PCAP_D_IN) != 0) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to set device direction %s: %s.", pcap_port->name, pcap_geterr(pcap_port->pcap));
        return NULL;
    }

    pcap_port->fd      = pcap_fileno(pcap_port->pcap);

    ev_io_stop(pcap_port->drv->loop, pcap_port->watcher);
    free(pcap_port->watcher);

    pcap_port->watcher = malloc(sizeof(ev_io));
    pcap_port->watcher->data = pcap_port;
    ev_io_init(pcap_port->watcher, event_loop_packet_in_cb, pcap_port->fd, EV_READ);
    pcap_port_fill(pcap_port);

    return pcap_port;
}

struct pcap_port *
pcap_open(struct pcap_port *pcap_port) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_drv *pcap_drv = pcap_port->drv;

    pcap_t *pcap = NULL;
    pcap = pcap_open_live(pcap_port->name, PCAP_SNAPLEN, true/*promisc*/, -1/*to_ms*/, errbuf);
    if (pcap == NULL) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to open device %s: %s.", pcap_port->name, errbuf);
        return NULL;
    }

    if(pcap_setnonblock(pcap, true, errbuf) != 0) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to set device to promisc %s: %s.", pcap_port->name, errbuf);
        return NULL;
    }

    if(pcap_setdirection(pcap, PCAP_D_IN) != 0) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to set device direction %s: %s.", pcap_port->name, pcap_geterr(pcap));
        return NULL;
    }

    pcap_port->pcap    = pcap;
    pcap_port->fd      = pcap_fileno(pcap);

    pcap_port->watcher = malloc(sizeof(ev_io));
    pcap_port->watcher->data = pcap_port;
    ev_io_init(pcap_port->watcher, event_loop_packet_in_cb, pcap_port->fd, EV_READ);
    pcap_port_fill(pcap_port);

    return pcap_port;
}

/* Opens a port with the given name and uid. */
struct pcap_port * MALLOC_ATTR
pcap_port_open(struct pcap_drv *pcap_drv, size_t id, const char *name) {

    struct linux_port *linux_port;
    HASH_FIND_STR(pcap_drv->linux_ports_map, name, linux_port);
    if(linux_port == NULL) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to get interface flags");
        logger_log(pcap_drv->logger, LOG_ERR, "There is no linux port for %s", name);
        return NULL;
    }

    struct linux_port_flags *flags = &linux_port->flags;
    if (flags == NULL) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to get interface flags %s", name);
        return NULL;
    }

    struct pcap_port *pcap_port = malloc(sizeof(struct pcap_port));
    pcap_port->drv     = pcap_drv;
    pcap_port->id      = id;
    pcap_port->name    = strdup(name);
    pcap_port->logger  = logger_mgr_get(LOGGER_NAME_PORT_DRV_PCAP_PORT, id);


    pcap_port->dp_uid = 0; // invalidity marked by port_no
    pcap_port->dp_port_no = OF_NO_PORT;
    pcap_port->pkt_mbox = NULL;
    pcap_port->rwlock = malloc(sizeof(pthread_rwlock_t));
    pthread_rwlock_init(pcap_port->rwlock, NULL);

    pcap_port->of_port = malloc(sizeof(struct ofl_port));
    memset(pcap_port->of_port, '\0', sizeof(struct ofl_port));
    pcap_port->of_stats = malloc(sizeof(struct ofl_port_stats));
    memset(pcap_port->of_stats, '\0', sizeof(struct ofl_port_stats));
    pcap_port->of_port->name = strdup(name);

    pcap_port->stats_mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(pcap_port->stats_mutex, NULL);

    if(flags->UP && flags->RUNNING) {
        return pcap_open(pcap_port);
    } else {
        pcap_port->pcap = NULL;
        pcap_port->fd   = -1;

        pcap_port->watcher = NULL;
    }

    return pcap_port;
}



/* PCAP callback, where incoming packets are dispatched. */
static void
pcap_cb(uint8_t *port_, const struct pcap_pkthdr *header, const uint8_t *packet UNUSED_ATTR) {
    struct pcap_port *pcap_port = (struct pcap_port *)port_;

    //TODO is this needed?
    if (header->len != header->caplen) {
        logger_log(pcap_port->logger, LOG_INFO, "Dropping partial packet.");
        pthread_mutex_lock(pcap_port->stats_mutex);
        pcap_port->of_stats->rx_errors ++;
        pcap_port->of_stats->rx_dropped++;
        pthread_mutex_unlock(pcap_port->stats_mutex);
        return;
    }

    logger_log(pcap_port->logger, LOG_DEBUG, "Received packet of size %d on %s.", header->caplen, pcap_port->name);
    pthread_mutex_lock(pcap_port->stats_mutex);
    if ((pcap_port->of_port->config & OFPPC_NO_RECV) != 0) {
        logger_log(pcap_port->logger, LOG_DEBUG, "Dropping packet due to config.");
        pthread_mutex_unlock(pcap_port->stats_mutex);
        return;
    }

    pcap_port->of_stats->rx_bytes += header->caplen;
    pcap_port->of_stats->rx_packets ++;
    pthread_mutex_unlock(pcap_port->stats_mutex);

    //TODO: this should request a buffer from dp/port instead
    struct pkt_buf *pkt = pkt_buf_new(header->caplen);
    memcpy(pkt->data, packet, header->caplen);
    pkt->data_len = header->caplen;

    dp_mgr_dp_recv_pkt(pcap_port->dp_uid, pcap_port->dp_port_no, pkt);
}

/* Event loop callback when the PCAP port is readable. */
static void
event_loop_packet_in_cb(struct ev_loop *loop UNUSED_ATTR, ev_io *w, int revents UNUSED_ATTR) {
    struct pcap_port *pcap_port = (struct pcap_port *)(w->data);

    logger_log(pcap_port->logger, LOG_DEBUG, "pcap_drv_loop_packet_in_cb called on port %s.", pcap_port->name);

    int r = pcap_dispatch(pcap_port->pcap, -1/*cnt*/, pcap_cb, (uint8_t *)pcap_port);

    logger_log(pcap_port->logger, LOG_DEBUG, "dispatched %d packet(s).", r);
}
