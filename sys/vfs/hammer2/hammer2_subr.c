/*
 * Copyright (c) 2011-2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 * by Venkatesh Srinivas <vsrinivas@dragonflybsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/uuid.h>
#include <sys/dirent.h>

#include "hammer2.h"

/*
 * HAMMER2 inode locks
 *
 * HAMMER2 offers shared locks and exclusive locks on inodes.
 *
 * An inode's ip->chain pointer is resolved and stable while an inode is
 * locked, and can be cleaned out at any time (become NULL) when an inode
 * is not locked.
 *
 * The underlying chain is also locked and returned.
 *
 * NOTE: We don't combine the inode/chain lock because putting away an
 *       inode would otherwise confuse multiple lock holders of the inode.
 */
hammer2_chain_t *
hammer2_inode_lock_ex(hammer2_inode_t *ip)
{
	hammer2_chain_t *chain;

	hammer2_inode_ref(ip);
	ccms_thread_lock(&ip->topo_cst, CCMS_STATE_EXCLUSIVE);

	chain = ip->chain;
	KKASSERT(chain != NULL);	/* for now */
	hammer2_chain_lock(ip->hmp, chain, HAMMER2_RESOLVE_ALWAYS);

	return (chain);
}

void
hammer2_inode_unlock_ex(hammer2_inode_t *ip, hammer2_chain_t *chain)
{
	/*
	 * XXX this will catch parent directories too which we don't
	 *     really want.
	 */
	if (ip->chain && (ip->chain->flags & (HAMMER2_CHAIN_MODIFIED |
					      HAMMER2_CHAIN_SUBMODIFIED))) {
		atomic_set_int(&ip->flags, HAMMER2_INODE_MODIFIED);
	}
	if (chain)
		hammer2_chain_unlock(ip->hmp, chain);
	ccms_thread_unlock(&ip->topo_cst);
	hammer2_inode_drop(ip);
}

/*
 * NOTE: We don't combine the inode/chain lock because putting away an
 *       inode would otherwise confuse multiple lock holders of the inode.
 *
 *	 Shared locks are especially sensitive to having too many shared
 *	 lock counts (from the same thread) on certain paths which might
 *	 need to upgrade them.  Only one count of a shared lock can be
 *	 upgraded.
 */
hammer2_chain_t *
hammer2_inode_lock_sh(hammer2_inode_t *ip)
{
	hammer2_chain_t *chain;

	hammer2_inode_ref(ip);
	ccms_thread_lock(&ip->topo_cst, CCMS_STATE_SHARED);

	chain = ip->chain;
	KKASSERT(chain != NULL);	/* for now */
	hammer2_chain_lock(ip->hmp, chain, HAMMER2_RESOLVE_ALWAYS |
					   HAMMER2_RESOLVE_SHARED);
	return (chain);
}

void
hammer2_inode_unlock_sh(hammer2_inode_t *ip, hammer2_chain_t *chain)
{
	if (chain)
		hammer2_chain_unlock(ip->hmp, chain);
	ccms_thread_unlock(&ip->topo_cst);
	hammer2_inode_drop(ip);
}

ccms_state_t
hammer2_inode_lock_temp_release(hammer2_inode_t *ip)
{
	return(ccms_thread_lock_temp_release(&ip->topo_cst));
}

ccms_state_t
hammer2_inode_lock_upgrade(hammer2_inode_t *ip)
{
	return(ccms_thread_lock_upgrade(&ip->topo_cst));
}

void
hammer2_inode_lock_restore(hammer2_inode_t *ip, ccms_state_t ostate)
{
	ccms_thread_lock_restore(&ip->topo_cst, ostate);
}

/*
 * Mount-wide locks
 */

void
hammer2_mount_exlock(hammer2_mount_t *hmp)
{
	ccms_thread_lock(&hmp->vchain.cst, CCMS_STATE_EXCLUSIVE);
}

void
hammer2_mount_shlock(hammer2_mount_t *hmp)
{
	ccms_thread_lock(&hmp->vchain.cst, CCMS_STATE_SHARED);
}

void
hammer2_mount_unlock(hammer2_mount_t *hmp)
{
	ccms_thread_unlock(&hmp->vchain.cst);
}

void
hammer2_voldata_lock(hammer2_mount_t *hmp)
{
	lockmgr(&hmp->voldatalk, LK_EXCLUSIVE);
}

void
hammer2_voldata_unlock(hammer2_mount_t *hmp)
{
	lockmgr(&hmp->voldatalk, LK_RELEASE);
}

/*
 * Return the directory entry type for an inode.
 *
 * ip must be locked sh/ex.
 */
int
hammer2_get_dtype(hammer2_chain_t *chain)
{
	uint8_t type;

	KKASSERT(chain->bref.type == HAMMER2_BREF_TYPE_INODE);

	if ((type = chain->data->ipdata.type) == HAMMER2_OBJTYPE_HARDLINK)
		type = chain->data->ipdata.target_type;

	switch(type) {
	case HAMMER2_OBJTYPE_UNKNOWN:
		return (DT_UNKNOWN);
	case HAMMER2_OBJTYPE_DIRECTORY:
		return (DT_DIR);
	case HAMMER2_OBJTYPE_REGFILE:
		return (DT_REG);
	case HAMMER2_OBJTYPE_FIFO:
		return (DT_FIFO);
	case HAMMER2_OBJTYPE_CDEV:	/* not supported */
		return (DT_CHR);
	case HAMMER2_OBJTYPE_BDEV:	/* not supported */
		return (DT_BLK);
	case HAMMER2_OBJTYPE_SOFTLINK:
		return (DT_LNK);
	case HAMMER2_OBJTYPE_HARDLINK:	/* (never directly associated w/vp) */
		return (DT_UNKNOWN);
	case HAMMER2_OBJTYPE_SOCKET:
		return (DT_SOCK);
	case HAMMER2_OBJTYPE_WHITEOUT:	/* not supported */
		return (DT_UNKNOWN);
	default:
		return (DT_UNKNOWN);
	}
	/* not reached */
}

/*
 * Return the directory entry type for an inode
 */
int
hammer2_get_vtype(hammer2_chain_t *chain)
{
	KKASSERT(chain->bref.type == HAMMER2_BREF_TYPE_INODE);

	switch(chain->data->ipdata.type) {
	case HAMMER2_OBJTYPE_UNKNOWN:
		return (VBAD);
	case HAMMER2_OBJTYPE_DIRECTORY:
		return (VDIR);
	case HAMMER2_OBJTYPE_REGFILE:
		return (VREG);
	case HAMMER2_OBJTYPE_FIFO:
		return (VFIFO);
	case HAMMER2_OBJTYPE_CDEV:	/* not supported */
		return (VCHR);
	case HAMMER2_OBJTYPE_BDEV:	/* not supported */
		return (VBLK);
	case HAMMER2_OBJTYPE_SOFTLINK:
		return (VLNK);
	case HAMMER2_OBJTYPE_HARDLINK:	/* XXX */
		return (VBAD);
	case HAMMER2_OBJTYPE_SOCKET:
		return (VSOCK);
	case HAMMER2_OBJTYPE_WHITEOUT:	/* not supported */
		return (DT_UNKNOWN);
	default:
		return (DT_UNKNOWN);
	}
	/* not reached */
}

u_int8_t
hammer2_get_obj_type(enum vtype vtype)
{
	switch(vtype) {
	case VDIR:
		return(HAMMER2_OBJTYPE_DIRECTORY);
	case VREG:
		return(HAMMER2_OBJTYPE_REGFILE);
	case VFIFO:
		return(HAMMER2_OBJTYPE_FIFO);
	case VSOCK:
		return(HAMMER2_OBJTYPE_SOCKET);
	case VCHR:
		return(HAMMER2_OBJTYPE_CDEV);
	case VBLK:
		return(HAMMER2_OBJTYPE_BDEV);
	case VLNK:
		return(HAMMER2_OBJTYPE_SOFTLINK);
	default:
		return(HAMMER2_OBJTYPE_UNKNOWN);
	}
	/* not reached */
}

/*
 * Convert a hammer2 64-bit time to a timespec.
 */
void
hammer2_time_to_timespec(u_int64_t xtime, struct timespec *ts)
{
	ts->tv_sec = (unsigned long)(xtime / 1000000);
	ts->tv_nsec = (unsigned int)(xtime % 1000000) * 1000L;
}

u_int64_t
hammer2_timespec_to_time(struct timespec *ts)
{
	u_int64_t xtime;

	xtime = (unsigned)(ts->tv_nsec / 1000) +
		(unsigned long)ts->tv_sec * 1000000ULL;
	return(xtime);
}

/*
 * Convert a uuid to a unix uid or gid
 */
u_int32_t
hammer2_to_unix_xid(uuid_t *uuid)
{
	return(*(u_int32_t *)&uuid->node[2]);
}

void
hammer2_guid_to_uuid(uuid_t *uuid, u_int32_t guid)
{
	bzero(uuid, sizeof(*uuid));
	*(u_int32_t *)&uuid->node[2] = guid;
}

/*
 * Borrow HAMMER1's directory hash algorithm #1 with a few modifications.
 * The filename is split into fields which are hashed separately and then
 * added together.
 *
 * Differences include: bit 63 must be set to 1 for HAMMER2 (HAMMER1 sets
 * it to 0), this is because bit63=0 is used for hidden hardlinked inodes.
 * (This means we do not need to do a 0-check/or-with-0x100000000 either).
 *
 * Also, the iscsi crc code is used instead of the old crc32 code.
 */
hammer2_key_t
hammer2_dirhash(const unsigned char *name, size_t len)
{
	const unsigned char *aname = name;
	uint32_t crcx;
	uint64_t key;
	size_t i;
	size_t j;

	key = 0;

	/*
	 * m32
	 */
	crcx = 0;
	for (i = j = 0; i < len; ++i) {
		if (aname[i] == '.' ||
		    aname[i] == '-' ||
		    aname[i] == '_' ||
		    aname[i] == '~') {
			if (i != j)
				crcx += hammer2_icrc32(aname + j, i - j);
			j = i + 1;
		}
	}
	if (i != j)
		crcx += hammer2_icrc32(aname + j, i - j);

	/*
	 * The directory hash utilizes the top 32 bits of the 64-bit key.
	 * Bit 63 must be set to 1.
	 */
	crcx |= 0x80000000U;
	key |= (uint64_t)crcx << 32;

	/*
	 * l16 - crc of entire filename
	 *
	 * This crc reduces degenerate hash collision conditions
	 */
	crcx = hammer2_icrc32(aname, len);
	crcx = crcx ^ (crcx << 16);
	key |= crcx & 0xFFFF0000U;

	/*
	 * Set bit 15.  This allows readdir to strip bit 63 so a positive
	 * 64-bit cookie/offset can always be returned, and still guarantee
	 * that the values 0x0000-0x7FFF are available for artificial entries.
	 * ('.' and '..').
	 */
	key |= 0x8000U;

	return (key);
}

/*
 * Return the power-of-2 radix greater or equal to
 * the specified number of bytes.
 *
 * Always returns at least the minimum media allocation
 * size radix, HAMMER2_MIN_RADIX (10), which is 1KB.
 */
int
hammer2_allocsize(size_t bytes)
{
	int radix;

	if (bytes < HAMMER2_MIN_ALLOC)
		bytes = HAMMER2_MIN_ALLOC;
	if (bytes == HAMMER2_PBUFSIZE)
		radix = HAMMER2_PBUFRADIX;
	else if (bytes >= 16384)
		radix = 14;
	else if (bytes >= 1024)
		radix = 10;
	else
		radix = HAMMER2_MIN_RADIX;

	while (((size_t)1 << radix) < bytes)
		++radix;
	return (radix);
}

/*
 * ip must be locked sh/ex
 */
int
hammer2_calc_logical(hammer2_inode_t *ip, hammer2_off_t uoff,
		     hammer2_key_t *lbasep, hammer2_key_t *leofp)
{
	hammer2_inode_data_t *ipdata = &ip->chain->data->ipdata;
	int radix;

	*lbasep = uoff & ~HAMMER2_PBUFMASK64;
	*leofp = ipdata->size & ~HAMMER2_PBUFMASK64;
	KKASSERT(*lbasep <= *leofp);
	if (*lbasep == *leofp /*&& *leofp < 1024 * 1024*/) {
		radix = hammer2_allocsize((size_t)(ipdata->size - *leofp));
		if (radix < HAMMER2_MINALLOCRADIX)
			radix = HAMMER2_MINALLOCRADIX;
		*leofp += 1U << radix;
		return (1U << radix);
	} else {
		return (HAMMER2_PBUFSIZE);
	}
}

void
hammer2_update_time(uint64_t *timep)
{
	struct timeval tv;

	getmicrotime(&tv);
	*timep = (unsigned long)tv.tv_sec * 1000000 + tv.tv_usec;
}
