/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#include <netinet/in.h>

#include "gre_pkt.h"

#include "lib/pkt_buf.h"
#include "lib/packets.h"

uint16_t cksum(uint8_t *data, uint16_t len){
	uint32_t sum = 0; 

    uint16_t offset = 0;
	while(len > 1){
		sum += *(((uint16_t*) data) + offset);
		if(sum & 0x80000000) 
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
        offset++;
	}

	if(len)
		sum += (uint16_t) *(data + 2 * offset);

	while(sum>>16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}


uint8_t*
add_gre_header(struct pkt_buf *pkt_buf, struct gre_pp *gre_pp, uint16_t *length) {
	struct eth_header *orig_eth = (struct eth_header*)pkt_buf->data;
	struct ipv4_header *orig_ipv4 = (struct ipv4_header*)(pkt_buf->data + sizeof(struct eth_header));

	uint8_t *data = malloc(pkt_buf->data_len + sizeof(struct ipv4_header) + sizeof(struct gre_header));
	memcpy(data, pkt_buf->data, sizeof(struct eth_header));
	uint16_t offset = sizeof(struct eth_header);

	struct ipv4_header *ipv4 = (struct ipv4_header*)(data + offset);
	ipv4->ip_ihl_ver = orig_ipv4->ip_ihl_ver;
	ipv4->ip_tos = orig_ipv4->ip_tos;
	ipv4->ip_tot_len = htons(ntohs(orig_ipv4->ip_tot_len) + sizeof(struct gre_header) + sizeof(struct ipv4_header));
	ipv4->ip_id = 0;
	ipv4->ip_frag_off = 0;
	ipv4->ip_ttl = 255;
	ipv4->ip_proto = IP_TYPE_GRE;
	ipv4->ip_csum = 0;
	ipv4->ip_src = htonl(gre_pp->local_ip);
	ipv4->ip_dst = htonl(gre_pp->remote_ip);
	offset += sizeof(struct ipv4_header);

	struct gre_header *gre = (struct gre_header*)(data + offset);
	gre->flags_version = htons(1 << 15);
	gre->protocol_type = htons(0x800);
	gre->reserved = 0;
	gre->checksum = 0;
	offset += sizeof(struct gre_header);

	memcpy(data + offset, orig_ipv4, ntohs(orig_ipv4->ip_tot_len));
	offset += ntohs(orig_ipv4->ip_tot_len);

	gre->checksum = cksum((uint8_t*)gre, ntohs(orig_ipv4->ip_tot_len) + sizeof(struct gre_header));
	ipv4->ip_csum = cksum((uint8_t*)ipv4, ntohs(ipv4->ip_tot_len));

	*length = offset;

	return data;
}

uint8_t*
del_gre_header(struct pkt_buf *pkt_buf, struct gre_pp *gre_pp, uint16_t *length) {
    uint16_t offset = 0;
	struct eth_header *eth = (struct eth_header*)pkt_buf->data;
    offset += sizeof(struct eth_header);
	struct ipv4_header *tun_ipv4 = (struct ipv4_header*)(pkt_buf->data + offset);
    offset += sizeof(struct ipv4_header);
    struct gre_header  *gre = (struct gre_header*)(pkt_buf->data + offset);
    offset += sizeof(struct gre_header);
    struct ipv4_header *orig_ipv4 = (struct ipv4_header*)(pkt_buf->data + offset);
    offset += sizeof(struct ipv4_header);

	uint8_t *data = malloc(sizeof(struct eth_header) + ntohs(orig_ipv4->ip_tot_len));
	memcpy(data, pkt_buf->data, sizeof(struct eth_header));
    offset = sizeof(struct eth_header);
    memcpy(data + offset, orig_ipv4, ntohs(orig_ipv4->ip_tot_len));
    offset += ntohs(orig_ipv4->ip_tot_len);

	*length = offset;

	return data;
}
