/***************************************************************************
 *   Copyright (C) 2013-2015,2019 Synopsys, Inc.                           *
 *   Frank Dols <frank.dols@synopsys.com>                                  *
 *   Mischa Jonker <mischa.jonker@synopsys.com>                            *
 *   Anton Kolesov <anton.kolesov@synopsys.com>                            *
 *   Evgeniy Didin <didin@synopsys.com>
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifndef ARC_H
#define ARC_H

#include <helper/time_support.h>
#include <jtag/jtag.h>

#include "algorithm.h"
#include "breakpoints.h"
#include "jtag/interface.h"
#include "register.h"
#include "target.h"
#include "target_request.h"
#include "target_type.h"

#define ARC_COMMON_MAGIC	0xB32EB324  /* just a unique number */

struct arc_common {
	uint32_t common_magic;
	void *arch_info;

  /* TODO: uncomment this as jtag functionality as introduced */
	//struct arc_jtag jtag_info;

	struct reg_cache *core_cache;

	/* working area for fastdata access */
	struct working_area *fast_data_area;

	int bp_scanned;

	/* Actionpoints */
	unsigned int actionpoints_num;
	unsigned int actionpoints_num_avail;
	struct arc_comparator *actionpoints_list;

	/* Cache control */
	bool has_dcache;
	/* If true, then D$ has been already flushed since core has been
	 * halted. */
	bool dcache_flushed;
	/* If true, then caches have been already flushed since core has been
	 * halted. */
	bool cache_invalidated;

	/* Whether DEBUG.SS bit is present. This is a unique feature of ARC 600. */
	bool has_debug_ss;

	/* Workaround for a problem with ARC 600 - writing RA | IS | SS will not
	 * step an instruction - it must be only a (IS | SS). However RA is set by
	 * the processor itself and since OpenOCD does read-modify-write of DEBUG
	 * register when stepping, it is required to explicitly disable RA before
	 * stepping. */
	bool on_step_reset_debug_ra;

	/* CCM memory regions (optional). */
	uint32_t iccm0_start;
	uint32_t iccm0_end;
	uint32_t iccm1_start;
	uint32_t iccm1_end;
	uint32_t dccm_start;
	uint32_t dccm_end;

	/* Register descriptions */
	struct list_head reg_data_types;
	struct list_head core_reg_descriptions;
	struct list_head aux_reg_descriptions;
	struct list_head bcr_reg_descriptions;
	unsigned long num_regs;
	unsigned long num_core_regs;
	unsigned long num_aux_regs;
	unsigned long num_bcr_regs;
	unsigned long last_general_reg;

	/* PC register location in register cache. */
	unsigned long pc_index_in_cache;
	/* DEBUG register location in register cache. */
	unsigned long debug_index_in_cache;
};

/* Borrowed from nds32.h */
#define CHECK_RETVAL(action)			\
	do {					\
		int __retval = (action);	\
		if (__retval != ERROR_OK) {	\
			LOG_DEBUG("error while calling \"%s\"",	\
				# action);     \
			return __retval;	\
		}				\
	} while (0)

#define JIM_CHECK_RETVAL(action)		\
	do {					\
		int __retval = (action);	\
		if (__retval != JIM_OK) {	\
			LOG_DEBUG("error while calling \"%s\"",	\
				# action);     \
			return __retval;	\
		}				\
	} while (0)

/* ----- Exported functions ------------------------------------------------ */
int arc_init_arch_info(struct target *target, struct arc_common *arc,
	struct jtag_tap *tap);

#endif /* ARC_H */
