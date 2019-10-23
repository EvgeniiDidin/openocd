/***************************************************************************
 *   Copyright (C) 2013-2014 Synopsys, Inc.                                *
 *   Frank Dols <frank.dols@synopsys.com>                                  *
 *   Mischa Jonker <mischa.jonker@synopsys.com>                            *
 *   Anton Kolesov <anton.kolesov@synopsys.com>                            *
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

/* ----- Supporting functions ---------------------------------------------- */
static bool arc_mem_is_slow_memory(struct arc_common *arc, uint32_t addr,
	uint32_t size, uint32_t count)
{
	uint32_t addr_end = addr + size * count;
	/* `_end` field can overflow - it points to the first byte after the end,
	 * therefore if DCCM is right at the end of memory address space, then
	 * dccm_end will be 0. */
	assert(addr_end >= addr || addr_end == 0);

	return !((addr >= arc->dccm_start && addr_end <= arc->dccm_end) ||
		(addr >= arc->iccm0_start && addr_end <= arc->iccm0_end) ||
		(addr >= arc->iccm1_start && addr_end <= arc->iccm1_end));
}

static int arc_mem_read_block(struct target *target, target_addr_t addr,
	uint32_t size, uint32_t count, void *buf)
{
	struct arc_common *arc = target_to_arc(target);

	LOG_DEBUG("Read memory: addr=0x%08" TARGET_PRIxADDR ", size=%" PRIu32
			", count=%" PRIu32, addr, size, count);
	assert(!(addr & 3));
	assert(size == 4);

	/* Always call D$ flush, it will decide whether to perform actual
	 * flush.  */
	/* TODO: introduce arc_dcache_flush function */
	//CHECK_RETVAL(arc32_dcache_flush(target));
	CHECK_RETVAL(arc_jtag_read_memory(&arc->jtag_info, addr, count, buf,
		    arc_mem_is_slow_memory(arc, addr, size, count)));

	return ERROR_OK;
}

int arc_mem_read(struct target *target, target_addr_t address, uint32_t size,
	uint32_t count, uint8_t *buffer)
{
	int retval = ERROR_OK;

	LOG_DEBUG("Read memory: addr=0x%08" TARGET_PRIxADDR ", size=%" PRIu32
			", count=%" PRIu32, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* Sanitize arguments */
	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
	    return ERROR_TARGET_UNALIGNED_ACCESS;

	void *tunnel_he;
	uint8_t *tunnel_te;
	uint32_t words_to_read, bytes_to_read;

	/* TODO: This function might be made much more clear if it
	 * would be splitted onto three based on size (4/2/1). That would
	 * duplicate some logic, but it would be much easier to understand it,
	 * those bit operations are just asking for a trouble. And they emulate
	 * size-specific logic, that is smart, but dangerous.  */
	/* Reads are word-aligned, so padding might be required if count > 1.
	 * NB: +3 is a padding for the last word (in case it's not aligned;
	 * addr&3 is a padding for the first word (since address can be
	 * unaligned as well).  */
	bytes_to_read = (count * size + 3 + (address & 3u)) & ~3u;
	words_to_read = bytes_to_read >> 2;
	tunnel_he = malloc(bytes_to_read);
	tunnel_te = malloc(bytes_to_read);
	if (!tunnel_he || !tunnel_te) {
		LOG_ERROR("Out of memory");
		return ERROR_FAIL;
	}

	/* We can read only word-aligned words. */
	retval = arc_mem_read_block(target, address & ~3u, sizeof(uint32_t),
		words_to_read, tunnel_he);

	/* arc_..._read_mem with size 4/2 returns uint32_t/uint16_t in host */
	/* endianness, but byte array should represent target endianness      */

	if (ERROR_OK == retval) {
		switch (size) {
		case 4:
			target_buffer_set_u32_array(target, buffer, count,
				tunnel_he);
			break;
		case 2:
			target_buffer_set_u32_array(target, tunnel_te,
				words_to_read, tunnel_he);
			/* Will that work properly with count > 1 and big endian? */
			memcpy(buffer, tunnel_te + (address & 3u),
				count * sizeof(uint16_t));
			break;
		case 1:
			target_buffer_set_u32_array(target, tunnel_te,
				words_to_read, tunnel_he);
			/* Will that work properly with count > 1 and big endian? */
			memcpy(buffer, tunnel_te + (address & 3u), count);
			break;
		default:
			LOG_DEBUG("Incorrect size of read");
			return ERROR_FAIL;
		}
	}

	free(tunnel_he);
	free(tunnel_te);

	return retval;
}
