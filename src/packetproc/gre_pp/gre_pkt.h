/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Elek Janos <janos.elek@ericsson.com>
 */

#ifndef GRE_GREU_H
#define GRE_GREU_H 1

#include "lib/pkt_buf.h"
#include "gre_structs.h"

uint8_t*
add_gre_header(struct pkt_buf *pkt_buf, struct gre_pp *gre_pp, uint16_t *length);

uint8_t*
del_gre_header(struct pkt_buf *pkt_buf, struct gre_pp *gre_pp, uint16_t *length);

#endif /* GRE_GREU_H */
