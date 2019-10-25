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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "arc.h"

void arc_add_reg_data_type(struct target *target,
               struct arc_reg_data_type *data_type)
{
	LOG_DEBUG("Adding %s reg_data_type", data_type->data_type.id);
	struct arc_common *arc = target_to_arc(target);
	assert(arc);

	list_add_tail(&data_type->list, &arc->reg_data_types);
}


/* Initialize arc_common structure, which passes to openocd target instance */
int arc_init_arch_info(struct target *target, struct arc_common *arc,
	struct jtag_tap *tap)
{
	arc->common_magic = ARC_COMMON_MAGIC;
	target->arch_info = arc;

	arc->fast_data_area = NULL;

	/* TODO: jtag functionality */

	/* has breakpoint/watchpoint unit been scanned */
	arc->bp_scanned = 0;

	/* We don't know how many actionpoints are in the core yet. */
	arc->actionpoints_num_avail = 0;
	arc->actionpoints_num = 0;
	arc->actionpoints_list = NULL;

	/* Flush D$ by default. It is safe to assume that D$ is present,
	 * because if it isn't, there will be no error, just a slight
	 * performance penalty from unnecessary JTAG operations. */
	arc->has_dcache = true;

	/* TODO: uncomment this as this function be introduced */
	//arc_reset_caches_states(target);

        /* Add standard GDB data types */
	INIT_LIST_HEAD(&arc->reg_data_types);
	struct arc_reg_data_type *std_types = calloc(ARRAY_SIZE(standard_gdb_types),
		sizeof(struct arc_reg_data_type));
	if (!std_types) {
	LOG_ERROR("Cannot allocate memory");
		return ERROR_FAIL;
	}
	for (unsigned int i = 0; i < ARRAY_SIZE(standard_gdb_types); i++) {
		std_types[i].data_type.type = standard_gdb_types[i].type;
		std_types[i].data_type.id = standard_gdb_types[i].id;
		arc_add_reg_data_type(target, &(std_types[i]));
	}


	/* Fields related to target descriptions */
	INIT_LIST_HEAD(&arc->core_reg_descriptions);
	INIT_LIST_HEAD(&arc->aux_reg_descriptions);
	INIT_LIST_HEAD(&arc->bcr_reg_descriptions);
	arc->num_regs = 0;
	arc->num_core_regs = 0;
	arc->num_aux_regs = 0;
	arc->num_bcr_regs = 0;
	arc->last_general_reg = ULONG_MAX;
	arc->pc_index_in_cache = ULONG_MAX;
	arc->debug_index_in_cache = ULONG_MAX;

	return ERROR_OK;
}
