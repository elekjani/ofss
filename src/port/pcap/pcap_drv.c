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
 * PCAP driver.
 */

#include <assert.h>
#include <stdlib.h>
#include <ev.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "lib/compiler.h"
#include "lib/message_box.h"
#include "lib/pkt_buf.h"
#include "lib/thread_id.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "pcap_drv.h"
#include "pcap_drv_int.h"
#include "pcap_port.h"

#define IFLIST_REPLY_BUFFER 65536

static bool event_loop_pkt_out_cb(void *pcap_port_, struct list_node *pkt_in_);

static void *event_loop(void *pcap_drv_loop_);

static void netlink_cb(struct ev_loop *l, struct ev_io *w, int revents);

void linux_add_port(struct nlmsghdr *h, struct pcap_drv*);

void linux_get_ports(struct pcap_drv*);

/* Static initializer for the driver. */
struct pcap_drv * MALLOC_ATTR
pcap_drv_init(struct port_drv *drv) {
    struct pcap_drv *pcap_drv = malloc(sizeof(struct pcap_drv));
    pcap_drv->drv = drv;
    pcap_drv->logger = logger_mgr_get(LOGGER_NAME_PORT_DRV_PCAP);

    pcap_drv->ports_map = NULL;
    size_t i;
    for (i=0; i<MAX_PORTS; i++) {
        pcap_drv->ports[i] = NULL;
    }
    pcap_drv->ports_num = 1;

    pcap_drv->ports_rwlock = malloc(sizeof(pthread_rwlock_t));
    pthread_rwlock_init(pcap_drv->ports_rwlock, NULL);

    struct pcap_drv_loop *pcap_drv_loop = malloc(sizeof(struct pcap_drv_loop));
    pcap_drv_loop->logger = logger_mgr_get(LOGGER_NAME_PORT_DRV_PCAP_IF);

    pcap_drv->pcap_drv_loop = pcap_drv_loop;
    pcap_drv_loop->pcap_drv = pcap_drv;

    pcap_drv->thread = malloc(sizeof(pthread_t));
    pcap_drv->loop = ev_loop_new(0/*flags*/);
    pcap_drv_loop->loop = pcap_drv->loop;

    ev_set_userdata(pcap_drv->loop, (void *)pcap_drv_loop);

    pcap_drv->notifier = mbox_new(pcap_drv->loop, NULL, NULL);

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid    = 0;
    sa.nl_groups = RTMGRP_LINK;

    pcap_drv->netlinkfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    bind(pcap_drv->netlinkfd, (struct sockaddr *) &sa, sizeof(sa));
 
    pcap_drv->netlinkwatcher = malloc(sizeof(struct ev_io));
    pcap_drv->netlinkwatcher->data = (void *)pcap_drv;
    ev_io_init(pcap_drv->netlinkwatcher, netlink_cb, pcap_drv->netlinkfd, EV_READ);
    ev_io_start(pcap_drv->loop, pcap_drv->netlinkwatcher);

    pcap_drv->linux_ports_map = NULL;
    linux_get_ports(pcap_drv);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int rc;
    if ((rc = pthread_create(pcap_drv->thread, &attr, event_loop, (void *)pcap_drv_loop)) != 0) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to create thread (%d).", rc);
        //TODO: free structures
        return NULL;
    }

    logger_log(pcap_drv->logger, LOG_INFO, "PCAP initialized.");

    return pcap_drv;
}

/* Opens a port with the driver. */
static ssize_t
open_port(struct pcap_drv *pcap_drv, const char *name) {
    pthread_rwlock_wrlock(pcap_drv->ports_rwlock);
    // double check the port was not created b/w the calls
    struct pcap_port *port;
    HASH_FIND_STR(pcap_drv->ports_map, name, port);
    if (port != NULL) {
        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return port->id;
    }

    if (pcap_drv->ports_num >= MAX_PORTS) {
        logger_log(pcap_drv->logger, LOG_ERR, "Cannot open more ports.");
        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return -1;
    }

    port = pcap_port_open(pcap_drv, pcap_drv->ports_num, name);

    if (port != NULL) {
        pcap_drv->ports[pcap_drv->ports_num] = port;
        pcap_drv->ports_num++;
        HASH_ADD_KEYPTR(hh, pcap_drv->ports_map, port->name, strlen(port->name), port);

        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return port->id;
    } else {
        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return -1;
    }
}

/* Returns an opened port's uid by name. */
ssize_t
pcap_drv_get_port(struct pcap_drv *pcap_drv, const char *name) {
    pthread_rwlock_rdlock(pcap_drv->ports_rwlock);
    struct pcap_port *port;
    HASH_FIND_STR(pcap_drv->ports_map, name, port);
    pthread_rwlock_unlock(pcap_drv->ports_rwlock);

    if (port != NULL) {
        return port->id;
    }

    return open_port(pcap_drv, name);
}


/* Assigns a DP (uid) and its port to the given PCAP port. */
bool
pcap_drv_assign_dp_port(struct pcap_drv *drv, size_t drv_port_no, size_t dp_uid, of_port_no_t dp_port_no) {
    pthread_rwlock_wrlock(drv->ports_rwlock);

    if (drv->ports[drv_port_no] == NULL) {
        pthread_rwlock_unlock(drv->ports_rwlock);
        return false;
    }

    pthread_rwlock_unlock(drv->ports_rwlock);
    struct pcap_port *pcap_port = drv->ports[drv_port_no];

    pthread_rwlock_wrlock(pcap_port->rwlock);

    if (pcap_port->dp_port_no != OF_NO_PORT) {
        // dp port already assigned
        pthread_rwlock_unlock(pcap_port->rwlock);
        pthread_rwlock_unlock(drv->ports_rwlock);
        return false;
    }


    pcap_port->dp_uid = dp_uid;
    pcap_port->dp_port_no = dp_port_no;
    pcap_port->of_port->port_no = dp_port_no;
    pcap_port->of_stats->port_no = dp_port_no;

    pcap_port->pkt_mbox = mbox_new(drv->loop, pcap_port, event_loop_pkt_out_cb);

    struct linux_port *tmp;
    HASH_FIND_STR(drv->linux_ports_map, pcap_port->name, tmp);
    if(tmp == NULL) {
        //TODO: error
    }
    if(tmp->flags.UP && tmp->flags.RUNNING) {
        ev_io_start(drv->loop, pcap_port->watcher);

        mbox_notify(drv->notifier); // needed for io watcher update on loop
    }

    pthread_rwlock_unlock(pcap_port->rwlock);
    return true;
}

/* Event loop callback for outgoing packets. */
static bool
event_loop_pkt_out_cb(void *pcap_port_, struct list_node *pkt_buf_) {
    struct pcap_port *pcap_port = (struct pcap_port *)pcap_port_;
    struct pkt_buf *pkt_buf = (struct pkt_buf *)pkt_buf_;
    struct pcap_drv *pcap_drv = pcap_port->drv;

    pthread_rwlock_rdlock(pcap_drv->ports_rwlock);
    struct linux_port *linux_port;
    HASH_FIND(hh, pcap_drv->linux_ports_map, pcap_port->name, strlen(pcap_port->name), linux_port);
    if (linux_port == NULL) {
        logger_log(pcap_port->logger, LOG_WARN, "Linux_port for interface %s is NULL", pcap_port->name);
        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return false;
    }

    if (pcap_port->pcap == NULL || !(linux_port->flags.UP && linux_port->flags.RUNNING)) {
        logger_log(pcap_port->logger, LOG_WARN, "Interface %s is down or not running", pcap_port->name);
        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return false;
    }
    pthread_rwlock_unlock(pcap_drv->ports_rwlock);

    int ret = pcap_inject(pcap_port->pcap, pkt_buf->data, pkt_buf->data_len);
    if (ret == -1) {
        logger_log(pcap_port->logger, LOG_WARN, "Error in pcap_inject: %s.", pcap_geterr(pcap_port->pcap));

        pthread_mutex_lock(pcap_port->stats_mutex);
        pcap_port->of_stats->tx_dropped++;
        pcap_port->of_stats->tx_errors++;
        pthread_mutex_unlock(pcap_port->stats_mutex);

        pkt_buf_free(pkt_buf);
        //TODO perhaps should buffer for later write
        return false; // wait a little with the next packet
    } else if ((ret - pkt_buf->data_len) != 0) {
        logger_log(pcap_port->logger, LOG_WARN, "Pcap_inject could not send the whole packet: %d (%d).",
                                                           ret, pkt_buf->data_len);
        pthread_mutex_lock(pcap_port->stats_mutex);
        pcap_port->of_stats->tx_dropped++;
        pcap_port->of_stats->tx_errors++;
        pthread_mutex_unlock(pcap_port->stats_mutex);

        pkt_buf_free(pkt_buf);
        return false; // wait a little with the next packet
    } else {
        logger_log(pcap_port->logger, LOG_DEBUG, "Sent packet of length %d.", pkt_buf->data_len);
        pthread_mutex_lock(pcap_port->stats_mutex);
        pcap_port->of_stats->tx_bytes += pkt_buf->data_len;
        pcap_port->of_stats->tx_packets++;
        pthread_mutex_unlock(pcap_port->stats_mutex);

        pkt_buf_free(pkt_buf);
        return true;
    }
}

/* The driver's event loop. */
static void *event_loop(void *pcap_drv_loop_) {
    assert(pcap_drv_loop_ != NULL);
    struct pcap_drv_loop *pcap_drv_loop = (struct pcap_drv_loop *)pcap_drv_loop_;

    thread_id_set();

    logger_log(pcap_drv_loop->logger, LOG_INFO, "Thread started for PCAP.");

    ev_ref(pcap_drv_loop->loop); //makes sure an empty loop stays alive
    ev_run(pcap_drv_loop->loop, 0/*flags*/);

    logger_log(pcap_drv_loop->logger, LOG_ERR, "Loop exited.");

    pthread_exit(NULL);
    return NULL;
}

/* Sends a packet on the driver's given port.
 * Can be used by other threads. */
bool
pcap_drv_send_pkt(struct pcap_drv *drv, size_t drv_port_no, struct pkt_buf *pkt_buf) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        mbox_send(port->pkt_mbox, (struct list_node *)pkt_buf); //TODO limit?
        return true;
    } else {
        return false;
    }
}

/* Returns a copy of the port's description. */
struct ofl_port * MALLOC_ATTR
pcap_drv_get_port_desc(struct pcap_drv *drv, size_t drv_port_no) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        pthread_mutex_lock(port->stats_mutex);
        struct ofl_port *ret = memcpy(malloc(sizeof(struct ofl_port)), port->of_port, sizeof(struct ofl_port));
        ret->name = strdup(port->of_port->name);
        pthread_mutex_unlock(port->stats_mutex);
        return ret;
    } else {
        return NULL;
    }
}

/* Returns a copy of the port's statistics description. */
struct ofl_port_stats * MALLOC_ATTR
pcap_drv_get_port_stats(struct pcap_drv *drv, size_t drv_port_no) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        pthread_mutex_lock(port->stats_mutex);
        struct ofl_port_stats *ret = memcpy(malloc(sizeof(struct ofl_port_stats)), port->of_stats, sizeof(struct ofl_port_stats));
        pthread_mutex_unlock(port->stats_mutex);
        return ret;
    } else {
        return NULL;
    }
}

/* Returns a reference to the port's HW address. */
const uint8_t *
pcap_drv_get_port_addr(struct pcap_drv *drv, size_t drv_port_no) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        //TODO: need lock?
        return port->of_port->hw_addr;
    } else {
        return NULL;
    }
}

/* Updates OpenFlow port config of the port. */
void
pcap_drv_port_mod(struct pcap_drv *drv, size_t drv_port_no, uint32_t config) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        pthread_mutex_lock(port->stats_mutex);
        port->of_port->config = config;
        pthread_mutex_unlock(port->stats_mutex);
    } else {
    }
}


static void
netlink_cb(struct ev_loop *l, struct ev_io *w, int revents) {
    struct pcap_drv *pcap_drv = (struct pcap_drv*)w->data;
    struct sockaddr_nl kernel;
    char reply[IFLIST_REPLY_BUFFER]; /* a large buffer */
    int len;
    struct nlmsghdr *msg_ptr;    /* pointer to current part */
    struct msghdr rtnl_reply;    /* generic msghdr structure */
    struct iovec io_reply;

    memset(&io_reply, 0, sizeof(io_reply));
    memset(&rtnl_reply, 0, sizeof(rtnl_reply));
    memset(&kernel, 0, sizeof(kernel));

    kernel.nl_family = AF_NETLINK;

    io_reply.iov_base = reply;
    io_reply.iov_len = IFLIST_REPLY_BUFFER;
    rtnl_reply.msg_iov = &io_reply;
    rtnl_reply.msg_iovlen = 1;
    rtnl_reply.msg_name = &kernel;
    rtnl_reply.msg_namelen = sizeof(kernel);

    len = recvmsg(w->fd, &rtnl_reply, 0); /* read lots of data */
    if (len) {
        for (msg_ptr = (struct nlmsghdr *) reply;
                NLMSG_OK(msg_ptr, len);
                msg_ptr = NLMSG_NEXT(msg_ptr, len)) {
            switch(msg_ptr->nlmsg_type) {
                case NLMSG_DONE:
                    logger_log(pcap_drv->logger, LOG_DEBUG, "Netlink msg done.");
                    break;
                case RTM_NEWLINK:
                    logger_log(pcap_drv->logger, LOG_DEBUG, "RTM_NEWLINK msg arrived.");
                    linux_add_port(msg_ptr, pcap_drv);
                    break;
                default:  
                    logger_log(pcap_drv->logger, LOG_DEBUG, "Netlink msg type %d, length %d\n",
                            msg_ptr->nlmsg_type, msg_ptr->nlmsg_len);
                    break;
            }
        }
    }
}

void
linux_add_port(struct nlmsghdr *h, struct pcap_drv *pcap_drv) {
    struct linux_port *tmp, *new_port = malloc(sizeof(struct linux_port));
    memset(new_port, 0, sizeof(struct linux_port));
    struct ifinfomsg *iface;
    struct rtattr *attribute;
    int len;


    iface = NLMSG_DATA(h);
    len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
    new_port->linux_if_index = iface->ifi_index;
    memcpy(&new_port->flags, &iface->ifi_flags, sizeof(struct linux_port_flags));

    for (attribute = IFLA_RTA(iface);
            RTA_OK(attribute, len);
            attribute = RTA_NEXT(attribute, len)) {
        switch(attribute->rta_type) {
            case IFLA_IFNAME: 
                strcpy(new_port->name, RTA_DATA(attribute));
                break;
            default:
                break;
        }
    }

    logger_log(pcap_drv->logger, LOG_DEBUG, "Netlink msg received for interface %d: %s", iface->ifi_index, new_port->name);

    pthread_rwlock_wrlock(pcap_drv->ports_rwlock);
    HASH_FIND_STR(pcap_drv->linux_ports_map, new_port->name, tmp);
    if(tmp == NULL) {
        logger_log(pcap_drv->logger, LOG_DEBUG, "Interface %s is new", new_port->name);
        HASH_ADD_KEYPTR(hh, pcap_drv->linux_ports_map, new_port->name, strlen(new_port->name), new_port);
    } else {
        struct pcap_port *port;
        HASH_FIND_STR(pcap_drv->ports_map, new_port->name, port);
        if (port == NULL) {
            logger_log(pcap_drv->logger, LOG_DEBUG, "There is no pcap_port for interface %s", new_port->name);
        } else if ((new_port->flags.UP != tmp->flags.UP) || (new_port->flags.RUNNING != tmp->flags.RUNNING)) {
            logger_log(pcap_drv->logger, LOG_DEBUG, "Status changed for interface %s:", new_port->name);
            if (new_port->flags.UP != tmp->flags.UP) {
                logger_log(pcap_drv->logger, LOG_DEBUG, new_port->flags.UP ? "Down -> Up" : "Up -> Down");
            }
            if (new_port->flags.RUNNING != tmp->flags.RUNNING) {
                logger_log(pcap_drv->logger, LOG_DEBUG, new_port->flags.RUNNING ? "Not running -> Running" : "Running -> Not Running");
            }

            if (new_port->flags.UP && new_port->flags.RUNNING) {
                if (port->pcap == NULL) {
                    pcap_open(port);
                } else {
                    pcap_reopen(port);
                }

                ev_io_start(pcap_drv->loop, port->watcher);
                mbox_notify(pcap_drv->notifier);
            }
        }
        memcpy(&tmp->flags, &new_port->flags, sizeof(struct linux_port_flags));
    }
    pthread_rwlock_unlock(pcap_drv->ports_rwlock);
}

void
linux_get_ports(struct pcap_drv *pcap_drv) {
    int sequence_number = 0;
    struct nl_req_s {
        struct nlmsghdr hdr;
        struct rtgenmsg gen;
    } req;
    struct sockaddr_nl kernel;
    struct msghdr rtnl_msg;
    struct iovec io;

    memset(&rtnl_msg, 0, sizeof(rtnl_msg));
    memset(&kernel, 0, sizeof(kernel));
    memset(&req, 0, sizeof(req));

    kernel.nl_family = AF_NETLINK;

    req.hdr.nlmsg_len    = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_type   = RTM_GETLINK;
    req.hdr.nlmsg_flags  = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq    = ++sequence_number;
    req.hdr.nlmsg_pid    = 0;
    req.gen.rtgen_family = AF_UNSPEC;

    io.iov_base = &req;
    io.iov_len = req.hdr.nlmsg_len;
    rtnl_msg.msg_iov = &io;
    rtnl_msg.msg_iovlen = 1;
    rtnl_msg.msg_name = &kernel;
    rtnl_msg.msg_namelen = sizeof(kernel);

    if(sendmsg(pcap_drv->netlinkfd, (struct msghdr *) &rtnl_msg, 0) < 0) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to send netlink msg");
    }

    netlink_cb(pcap_drv->loop, pcap_drv->netlinkwatcher, 0);

    return;
}
