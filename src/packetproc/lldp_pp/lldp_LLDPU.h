/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef LLDP_LLDPU_H
#define LLDP_LLDPU_H 1

#include "lldp_LLDPU_structs.h"

#define HTON_HEADER(header) *((uint16_t*)header) = htons( (((uint16_t)header->type) << 9) + header->length)
#define NTOH_HEADER(header) header->type = (ntohs( *((uint16_t*)header)) >> 9) & 0x01FF;  \
                            header->length = ntohs( *((uint16_t*)header)) & 0x007F

/* Convert incoming LLDP messages from TLV to internal LLDPU type */
struct LLDPU*
create_LLDPU_from_TLV(uint8_t *msg, size_t data_len, char* errbuf);

/* Create an LLDP message from LLDPU type, that can be send out on a LLDP port */
void
create_TLV_from_LLDPU(struct LldpMIB *lldpMIB, struct LLDPU *LLDPU, size_t port_num, uint8_t **msg, size_t *length);

/* Free the allocated memory spaces */
void
free_LLDPU(struct LLDPU*);


#endif /* LLDP_LLDPU_H */
