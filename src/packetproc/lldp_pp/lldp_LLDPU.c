/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */


#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "logger/logger.h"
#include "lib/openflow.h"
#include "datapath/dp_int.h"
#include "lib/packets.h"
#include "lldp_mib_structs.h"
#include "port/port_drv_int.h"
#include "port/pcap/pcap_drv_int.h"

#include "lldp_LLDPU_structs.h"
#include "lldp_LLDPU.h"

ssize_t
parse_LLDPU(struct LLDPU *LLDPU, uint8_t *msg, size_t length, char* errbuf) {
    LLDPU->port_desc.data_length = 0;
    LLDPU->system_name.data_length = 0;
    LLDPU->system_desc.data_length = 0;
    LLDPU->system_capabilities.use_it = false;
    LLDPU->length = 0;

	size_t size = sizeof(struct eth_header);
    if(size > length) {
        sprintf(errbuf, "Invalid ethernet header");
        return -1;
    }
    struct eth_header *eth_header = (struct eth_header*)msg;
    eth_header->eth_type = ntohs(eth_header->eth_type);

    if( eth_header->eth_type != 0x88cc) {
        sprintf(errbuf, "Ethernet type is not LLDP");
        return -1;
    }

	struct LLDPU_header *header = (struct LLDPU_header*)(msg + size);
    size += HEADER_SIZE;
    if(size > length) {
        sprintf(errbuf, "Invalid LLDP header");
        return -1;
    }
	bool isEnd = false;
	while(!isEnd) {
        NTOH_HEADER(header);
        if((size + header->length) > length) {
            sprintf(errbuf, "Invalid LLDP header");
            //TODO: free 
            return -1;
        }
		switch(header->type) {
			case CHASSIS_ID: {
                LLDPU->chassisId.data_length = header->length - 1;
                LLDPU->chassisId.subtype = *((uint8_t*)header->data);
				LLDPU->chassisId.data = malloc(LLDPU->chassisId.data_length);
				memcpy(LLDPU->chassisId.data, header->data + 1, LLDPU->chassisId.data_length);
				break;
			}
			case PORT_ID: {
                LLDPU->portId.data_length = header->length - 1;
                LLDPU->portId.subtype = *((uint8_t*)header->data);
				LLDPU->portId.data = malloc(LLDPU->portId.data_length);
				memcpy(LLDPU->portId.data, header->data + 1, LLDPU->portId.data_length);
				break;
			}
			case TTL: {
                LLDPU->TTL.seconds = ntohs(*((uint16_t*)header->data));
				break;
			}
			case PORT_DESC: {
                LLDPU->port_desc.data_length = header->length;
				LLDPU->port_desc.data = malloc(LLDPU->port_desc.data_length);
				memcpy(LLDPU->port_desc.data, header->data, LLDPU->port_desc.data_length);
				break;
			}
			case SYSTEM_NAME: {
                LLDPU->system_name.data_length = header->length;
				LLDPU->system_name.data = malloc(LLDPU->system_name.data_length);
				memcpy(LLDPU->system_name.data, header->data, LLDPU->system_name.data_length);
				break;
			}
			case SYSTEM_DESC: {
                LLDPU->system_desc.data_length = header->length;
				LLDPU->system_desc.data = malloc(LLDPU->system_desc.data_length);
				memcpy(LLDPU->system_desc.data, header->data, LLDPU->system_desc.data_length);
				break;
			}
			case SYSTEM_CAP: {
				memcpy(&(LLDPU->system_capabilities.capabilities), header->data, 2);
                LLDPU->system_capabilities.capabilities = *((uint16_t*)header->data);
                LLDPU->system_capabilities.enabled = *((uint16_t*)(header->data + sizeof(uint16_t)));
                LLDPU->system_capabilities.use_it = true;
				break;
			}
			case END_TLV: {
				isEnd = true;
				break;
			}
		}
		size += header->length;
        header = (struct LLDPU_header*)(msg + size);
        size += HEADER_SIZE;
        if(size > length && !isEnd) {
            sprintf(errbuf, "Invalid LLDP header");
            return -1;
        }
	}
    LLDPU->length = size;

    return size;
}

struct LLDPU*
create_LLDPU_from_TLV(uint8_t *msg, size_t data_len, char *errbuf) {
	struct LLDPU *LLDPU = malloc(sizeof(struct LLDPU));
	if(parse_LLDPU(LLDPU, msg, data_len, errbuf) < 0) {
        return NULL;
    }

	return LLDPU;
}

void
create_TLV_from_LLDPU(struct LldpMIB *lldpMIB, struct LLDPU *LLDPU, size_t port_num, uint8_t **msg, size_t *length) {
    struct dp *dp = lldpMIB->lldp_pp->dp;
    struct dp_port *dp_port = dp->ports[port_num];
    struct pcap_drv *pcap_drv = dp_port->drv->private;
    //struct ofl_port *of_port = pcap_drv_get_port_desc(dp_port->drv->private, port_num);

    *length = MANDATORY_HEADER_SIZE + sizeof(struct eth_header);
    *length += LLDPU->chassisId.data_length + LLDPU->portId.data_length;
    if(LLDPU->port_desc.data_length > 0) *length += LLDPU->port_desc.data_length + HEADER_SIZE;
    if(LLDPU->system_name.data_length > 0) *length += LLDPU->system_name.data_length + HEADER_SIZE;
    if(LLDPU->system_desc.data_length > 0) *length += LLDPU->system_desc.data_length + HEADER_SIZE;
    if(LLDPU->system_capabilities.use_it) *length += 2 * sizeof(uint16_t) + HEADER_SIZE;

   *msg = malloc(*length);
   *length = 0;
    struct eth_header *eth_header = (struct eth_header*)(*msg + *length);
    ETH_ADDR_SET(eth_header->eth_dst, 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E);
    memcpy(eth_header->eth_src, pcap_drv_get_port_addr(pcap_drv, port_num), OFP_ETH_ALEN);
    eth_header->eth_type = htons(0x88CC);
   *length += sizeof(struct eth_header);

    struct LLDPU_header *header = (struct LLDPU_header*)(*msg + *length);
	header->type = CHASSIS_ID;
    header->length = sizeof(uint8_t) + LLDPU->chassisId.data_length;
   *header->data = LLDPU->chassisId.subtype;
    memcpy(header->data + sizeof(uint8_t), LLDPU->chassisId.data, LLDPU->chassisId.data_length);
   *length += HEADER_SIZE + header->length;
    HTON_HEADER(header);

    header = (struct LLDPU_header*)(*msg + *length);
	header->type = PORT_ID;
    header->length = sizeof(uint8_t) + LLDPU->portId.data_length;
   *header->data = LLDPU->portId.subtype;
    memcpy(header->data + sizeof(uint8_t), LLDPU->portId.data, LLDPU->portId.data_length);
   *length += HEADER_SIZE + header->length;
    HTON_HEADER(header);

    header = (struct LLDPU_header*)(*msg + *length);
	header->type = TTL;
    header->length = sizeof(uint16_t);
    *((uint16_t*)header->data) = htons(LLDPU->TTL.seconds);
    *length += HEADER_SIZE + header->length;
    HTON_HEADER(header);

    if(LLDPU->port_desc.data_length > 0){
        header = (struct LLDPU_header*)(*msg + *length);
        header->type = PORT_DESC;
        header->length = LLDPU->port_desc.data_length;
        memcpy(header->data, LLDPU->port_desc.data, LLDPU->port_desc.data_length);
        *length += HEADER_SIZE + header->length;
        HTON_HEADER(header);
    }
    if(LLDPU->system_name.data_length > 0){
        header = (struct LLDPU_header*)(*msg + *length);
        header->type = SYSTEM_NAME;
        header->length = LLDPU->system_name.data_length;
        memcpy(header->data, LLDPU->system_name.data, LLDPU->system_name.data_length);
        *length += HEADER_SIZE + header->length;
        HTON_HEADER(header);
    }
    if(LLDPU->system_desc.data_length > 0){
        header = (struct LLDPU_header*)(*msg + *length);
        header->type = SYSTEM_DESC;
        header->length = LLDPU->system_desc.data_length;
        memcpy(header->data, LLDPU->system_desc.data, LLDPU->system_desc.data_length);
        *length += HEADER_SIZE + header->length;
        HTON_HEADER(header);
    }
    if(LLDPU->system_capabilities.use_it){
        header = (struct LLDPU_header*)(*msg + *length);
        header->type = SYSTEM_CAP;
        header->length = 2 * sizeof(uint16_t);
        *((uint16_t*)header->data) = LLDPU->system_capabilities.capabilities;
        *((uint16_t*)(header->data + sizeof(uint16_t))) = LLDPU->system_capabilities.enabled;
        *length += HEADER_SIZE + header->length;
        HTON_HEADER(header);
    }

    header = (struct LLDPU_header*)(*msg + *length);
	header->type = END_TLV;
    header->length = 0;
    *length += HEADER_SIZE;
    HTON_HEADER(header);

    return;
}

void
free_LLDPU(struct LLDPU* LLDPU) { 
    free(LLDPU->chassisId.data);
    free(LLDPU->portId.data);

    if (LLDPU->port_desc.data_length != 0) free(LLDPU->port_desc.data);
    if (LLDPU->system_name.data_length != 0) free(LLDPU->system_name.data);
    if (LLDPU->system_desc.data_length != 0) free(LLDPU->system_desc.data);

    free(LLDPU);

    return;
}
