/*
 * Copyright (c) 2011-2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
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

#include <sys/types.h>
#include <sys/diskslice.h>
#include <sys/diskmbr.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <vfs/hammer2/hammer2_disk.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <err.h>
#include <uuid.h>

#define hammer2_icrc32(buf, size)	iscsi_crc32((buf), (size))
#define hammer2_icrc32c(buf, size, crc)	iscsi_crc32_ext((buf), (size), (crc))
uint32_t iscsi_crc32(const void *buf, size_t size);
uint32_t iscsi_crc32_ext(const void *buf, size_t size, uint32_t ocrc);

static hammer2_off_t check_volume(const char *path, int *fdp);
static int64_t getsize(const char *str, int64_t minval, int64_t maxval, int pw);
static const char *sizetostr(hammer2_off_t size);
static uint64_t nowtime(void);
static void usage(void);

static void format_hammer2(int fd, hammer2_off_t total_space,
				hammer2_off_t free_space);
static void alloc_direct(hammer2_off_t *basep, hammer2_blockref_t *bref,
				size_t bytes);
static hammer2_key_t dirhash(const unsigned char *name, size_t len);

static int Hammer2Version = -1;
static int ForceOpt = 0;
static uuid_t Hammer2_FSType;	/* static filesystem type id for HAMMER2 */
static uuid_t Hammer2_FSId;	/* unique filesystem id in volu header */
static uuid_t Hammer2_SPFSId;	/* PFS id in super-root inode */
static uuid_t Hammer2_RPFSId;	/* PFS id in root inode */
static const char *Label = "ROOT";
static hammer2_off_t BootAreaSize;
static hammer2_off_t AuxAreaSize;

#define GIG	((hammer2_off_t)1024*1024*1024)

int
main(int ac, char **av)
{
	uint32_t status;
	hammer2_off_t total_space;
	hammer2_off_t free_space;
	hammer2_off_t reserved_space;
	int ch;
	int fd = -1;
	char *fsidstr;
	char *spfsidstr;
	char *rpfsidstr;

	/*
	 * Sanity check basic filesystem structures.  No cookies for us
	 * if it gets broken!
	 */
	assert(sizeof(hammer2_volume_data_t) == HAMMER2_VOLUME_BYTES);
	assert(sizeof(hammer2_inode_data_t) == HAMMER2_INODE_BYTES);
	assert(sizeof(hammer2_blockref_t) == HAMMER2_BLOCKREF_BYTES);

	/*
	 * Generate a filesystem id and lookup the filesystem type
	 */
	srandomdev();
	uuidgen(&Hammer2_FSId, 1);
	uuidgen(&Hammer2_SPFSId, 1);
	uuidgen(&Hammer2_RPFSId, 1);
	uuid_from_string(HAMMER2_UUID_STRING, &Hammer2_FSType, &status);
	/*uuid_name_lookup(&Hammer2_FSType, "DragonFly HAMMER2", &status);*/
	if (status != uuid_s_ok) {
		errx(1, "uuids file does not have the DragonFly "
			"HAMMER filesystem type");
	}

	/*
	 * Parse arguments
	 */
	while ((ch = getopt(ac, av, "fL:b:m:r:V:")) != -1) {
		switch(ch) {
		case 'f':
			ForceOpt = 1;
			break;
		case 'L':
			Label = optarg;
			if (strlen(Label) > HAMMER2_INODE_MAXNAME) {
				errx(1, "Root directory label too long "
					"(64 chars max)\n");
			}
			break;
		case 'b':
			BootAreaSize = getsize(optarg,
					 HAMMER2_NEWFS_ALIGN,
					 HAMMER2_BOOT_MAX_BYTES, 2);
			break;
		case 'r':
			AuxAreaSize = getsize(optarg,
					 HAMMER2_NEWFS_ALIGN,
					 HAMMER2_REDO_MAX_BYTES, 2);
			break;
		case 'V':
			Hammer2Version = strtol(optarg, NULL, 0);
			if (Hammer2Version < HAMMER2_VOL_VERSION_MIN ||
			    Hammer2Version >= HAMMER2_VOL_VERSION_WIP) {
				errx(1,
				     "I don't understand how to format "
				     "HAMMER2 version %d\n",
				     Hammer2Version);
			}
			break;
		default:
			usage();
			break;
		}
	}

	if (Hammer2Version < 0) {
		size_t olen = sizeof(Hammer2Version);
		Hammer2Version = HAMMER2_VOL_VERSION_DEFAULT;
		if (sysctlbyname("vfs.hammer2.supported_version",
				 &Hammer2Version, &olen, NULL, 0) == 0) {
			if (Hammer2Version >= HAMMER2_VOL_VERSION_WIP) {
				Hammer2Version = HAMMER2_VOL_VERSION_WIP - 1;
				fprintf(stderr,
					"newfs_hammer: WARNING: HAMMER2 VFS "
					"supports higher version than I "
					"understand,\n"
					"using version %d\n",
					Hammer2Version);
			}
		} else {
			fprintf(stderr,
				"newfs_hammer: WARNING: HAMMER2 VFS not "
				"loaded, cannot get version info.\n"
				"Using version %d\n",
				HAMMER2_VOL_VERSION_DEFAULT);
		}
	}

	/*
	 * Collect volume information.
	 */
	ac -= optind;
	av += optind;

	if (ac != 1) {
		fprintf(stderr, "Exactly one disk device must be specified\n");
		exit(1);
	}
	total_space = check_volume(av[0], &fd);

	/*
	 * ~typically 8MB alignment to avoid edge cases for reserved blocks
	 * and so raid stripes (if any) operate efficiently.
	 */
	total_space &= ~HAMMER2_VOLUME_ALIGNMASK64;

	/*
	 * Calculate defaults for the boot area size and round to the
	 * volume alignment boundary.
	 */
	if (BootAreaSize == 0) {
		BootAreaSize = HAMMER2_BOOT_NOM_BYTES;
		while (BootAreaSize > total_space / 20)
			BootAreaSize >>= 1;
		if (BootAreaSize < HAMMER2_BOOT_MIN_BYTES)
			BootAreaSize = HAMMER2_BOOT_MIN_BYTES;
	} else if (BootAreaSize < HAMMER2_BOOT_MIN_BYTES) {
		BootAreaSize = HAMMER2_BOOT_MIN_BYTES;
	}
	BootAreaSize = (BootAreaSize + HAMMER2_VOLUME_ALIGNMASK64) &
		       ~HAMMER2_VOLUME_ALIGNMASK64;

	/*
	 * Calculate defaults for the redo area size and round to the
	 * volume alignment boundary.
	 */
	if (AuxAreaSize == 0) {
		AuxAreaSize = HAMMER2_REDO_NOM_BYTES;
		while (AuxAreaSize > total_space / 20)
			AuxAreaSize >>= 1;
		if (AuxAreaSize < HAMMER2_REDO_MIN_BYTES)
			AuxAreaSize = HAMMER2_REDO_MIN_BYTES;
	} else if (AuxAreaSize < HAMMER2_REDO_MIN_BYTES) {
		AuxAreaSize = HAMMER2_REDO_MIN_BYTES;
	}
	AuxAreaSize = (AuxAreaSize + HAMMER2_VOLUME_ALIGNMASK64) &
		       ~HAMMER2_VOLUME_ALIGNMASK64;

	/*
	 * We'll need to stuff this in the volume header soon.
	 */
	uuid_to_string(&Hammer2_FSId, &fsidstr, &status);
	uuid_to_string(&Hammer2_SPFSId, &spfsidstr, &status);
	uuid_to_string(&Hammer2_RPFSId, &rpfsidstr, &status);

	/*
	 * Calculate the amount of reserved space.  HAMMER2_ZONE_SEG (4MB)
	 * is reserved at the beginning of every 2GB of storage, rounded up.
	 * Thus a 200MB filesystem will still have a 4MB reserve area.
	 *
	 * We also include the boot and redo areas in the reserve.  The
	 * reserve is used to help 'df' calculate the amount of available
	 * space.
	 */
	reserved_space = ((total_space + HAMMER2_ZONE_MASK64) /
			  HAMMER2_ZONE_BYTES64) * HAMMER2_ZONE_SEG64;

	free_space = total_space - reserved_space -
		     BootAreaSize - AuxAreaSize;

	format_hammer2(fd, total_space, free_space);
	fsync(fd);
	close(fd);

	printf("---------------------------------------------\n");
	printf("total-size:       %s (%jd bytes)\n",
	       sizetostr(total_space),
	       (intmax_t)total_space);
	printf("root-label:       %s\n", Label);
	printf("version:            %d\n", Hammer2Version);
	printf("boot-area-size:   %s\n", sizetostr(BootAreaSize));
	printf("aux-area-size:    %s\n", sizetostr(AuxAreaSize));
	printf("topo-reserved:	  %s\n", sizetostr(reserved_space));
	printf("free-space:       %s\n", sizetostr(free_space));
	printf("fsid:             %s\n", fsidstr);
	printf("supr-pfsid:       %s\n", spfsidstr);
	printf("root-pfsid:       %s\n", rpfsidstr);
	printf("\n");

	return(0);
}

static
void
usage(void)
{
	fprintf(stderr,
		"usage: newfs_hammer -L label [-f] [-b bootsize] "
		"[-r redosize] [-V version] special ...\n"
	);
	exit(1);
}

/*
 * Convert the size in bytes to a human readable string.
 */
static
const char *
sizetostr(hammer2_off_t size)
{
	static char buf[32];

	if (size < 1024 / 2) {
		snprintf(buf, sizeof(buf), "%6.2f", (double)size);
	} else if (size < 1024 * 1024 / 2) {
		snprintf(buf, sizeof(buf), "%6.2fKB",
			(double)size / 1024);
	} else if (size < 1024 * 1024 * 1024LL / 2) {
		snprintf(buf, sizeof(buf), "%6.2fMB",
			(double)size / (1024 * 1024));
	} else if (size < 1024 * 1024 * 1024LL * 1024LL / 2) {
		snprintf(buf, sizeof(buf), "%6.2fGB",
			(double)size / (1024 * 1024 * 1024LL));
	} else {
		snprintf(buf, sizeof(buf), "%6.2fTB",
			(double)size / (1024 * 1024 * 1024LL * 1024LL));
	}
	return(buf);
}

/*
 * Convert a string to a 64 bit signed integer with various requirements.
 */
static int64_t
getsize(const char *str, int64_t minval, int64_t maxval, int powerof2)
{
	int64_t val;
	char *ptr;

	val = strtoll(str, &ptr, 0);
	switch(*ptr) {
	case 't':
	case 'T':
		val *= 1024;
		/* fall through */
	case 'g':
	case 'G':
		val *= 1024;
		/* fall through */
	case 'm':
	case 'M':
		val *= 1024;
		/* fall through */
	case 'k':
	case 'K':
		val *= 1024;
		break;
	default:
		errx(1, "Unknown suffix in number '%s'\n", str);
		/* not reached */
	}
	if (ptr[1]) {
		errx(1, "Unknown suffix in number '%s'\n", str);
		/* not reached */
	}
	if (val < minval) {
		errx(1, "Value too small: %s, min is %s\n",
		     str, sizetostr(minval));
		/* not reached */
	}
	if (val > maxval) {
		errx(1, "Value too large: %s, max is %s\n",
		     str, sizetostr(maxval));
		/* not reached */
	}
	if ((powerof2 & 1) && (val ^ (val - 1)) != ((val << 1) - 1)) {
		errx(1, "Value not power of 2: %s\n", str);
		/* not reached */
	}
	if ((powerof2 & 2) && (val & HAMMER2_NEWFS_ALIGNMASK)) {
		errx(1, "Value not an integral multiple of %dK: %s",
		     HAMMER2_NEWFS_ALIGN / 1024, str);
		/* not reached */
	}
	return(val);
}

static uint64_t
nowtime(void)
{
	struct timeval tv;
	uint64_t xtime;

	gettimeofday(&tv, NULL);
	xtime = tv.tv_sec * 1000000LL + tv.tv_usec;
	return(xtime);
}

/*
 * Figure out how big the volume is.
 */
static
hammer2_off_t
check_volume(const char *path, int *fdp)
{
	struct partinfo pinfo;
	struct stat st;
	hammer2_off_t size;

	/*
	 * Get basic information about the volume
	 */
	*fdp = open(path, O_RDWR);
	if (*fdp < 0)
		err(1, "Unable to open %s R+W", path);
	if (ioctl(*fdp, DIOCGPART, &pinfo) < 0) {
		/*
		 * Allow the formatting of regular files as HAMMER2 volumes
		 */
		if (fstat(*fdp, &st) < 0)
			err(1, "Unable to stat %s", path);
		size = st.st_size;
	} else {
		/*
		 * When formatting a block device as a HAMMER2 volume the
		 * sector size must be compatible.  HAMMER2 uses 64K
		 * filesystem buffers but logical buffers for direct I/O
		 * can be as small as HAMMER2_LOGSIZE (16KB).
		 */
		if (pinfo.reserved_blocks) {
			errx(1, "HAMMER cannot be placed in a partition "
				"which overlaps the disklabel or MBR");
		}
		if (pinfo.media_blksize > HAMMER2_PBUFSIZE ||
		    HAMMER2_PBUFSIZE % pinfo.media_blksize) {
			errx(1, "A media sector size of %d is not supported",
			     pinfo.media_blksize);
		}
		size = pinfo.media_size;
	}
	printf("Volume %-15s size %s\n", path, sizetostr(size));
	return (size);
}

/*
 * Create the volume header, the super-root directory inode, and
 * the writable snapshot subdirectory (named via the label) which
 * is to be the initial mount point, or at least the first mount point.
 *
 * [----reserved_area----][boot_area][aux_area]
 * [[vol_hdr]...         ]                      [sroot][root]
 *
 * The sroot and root inodes eat 512 bytes each.  newfs labels can only be
 * 64 bytes so the root (snapshot) inode does not need to extend past 512
 * bytes.  We use the correct hash slot correct but note that because
 * directory hashes are chained 16x, any slot in the inode will work.
 *
 * Also format the allocation map.
 *
 * NOTE: The passed total_space is 8MB-aligned to avoid edge cases.
 */
static
void
format_hammer2(int fd, hammer2_off_t total_space, hammer2_off_t free_space)
{
	char *buf = malloc(HAMMER2_PBUFSIZE);
	hammer2_volume_data_t *vol;
	hammer2_inode_data_t *rawip;
	hammer2_blockref_t sroot_blockref;
	hammer2_blockref_t root_blockref;
	hammer2_blockref_t freemap_blockref;
	uint64_t now;
	hammer2_off_t volu_base = 0;
	hammer2_off_t boot_base = HAMMER2_ZONE_SEG;
	hammer2_off_t aux_base = boot_base + BootAreaSize;
	hammer2_off_t alloc_base = aux_base + AuxAreaSize;
	hammer2_off_t tmp_base;
	size_t n;
	int i;

	/*
	 * Clear the entire reserve for the first 2G segment and
	 * make sure we can write to the last block.
	 */
	bzero(buf, HAMMER2_PBUFSIZE);
	tmp_base = volu_base;
	for (i = 0; i < HAMMER2_ZONE_BLOCKS_SEG; ++i) {
		n = pwrite(fd, buf, HAMMER2_PBUFSIZE, tmp_base);
		if (n != HAMMER2_PBUFSIZE) {
			perror("write");
			exit(1);
		}
		tmp_base += HAMMER2_PBUFSIZE;
	}

	n = pwrite(fd, buf, HAMMER2_PBUFSIZE,
		   volu_base + total_space - HAMMER2_PBUFSIZE);
	if (n != HAMMER2_PBUFSIZE) {
		perror("write (at-end-of-volume)");
		exit(1);
	}

	/*
	 * Make sure alloc_base won't cross the reserved area at the
	 * beginning of each 2GB zone.
	 *
	 * Reserve space for the super-root inode and the root inode.
	 * Make sure they are in the same 64K block to simplify our code.
	 */
	assert((alloc_base & HAMMER2_PBUFMASK) == 0);
	assert(alloc_base < HAMMER2_ZONE_BYTES64 - HAMMER2_ZONE_SEG);

	alloc_base &= ~HAMMER2_PBUFMASK64;
	alloc_direct(&alloc_base, &sroot_blockref, HAMMER2_INODE_BYTES);
	alloc_direct(&alloc_base, &root_blockref, HAMMER2_INODE_BYTES);
	assert(((sroot_blockref.data_off ^ root_blockref.data_off) &
		HAMMER2_OFF_MASK_HI) == 0);

	bzero(buf, HAMMER2_PBUFSIZE);
	now = nowtime();

	/*
	 * Format the root directory inode, which is left empty.
	 */
	rawip = (void *)(buf + (HAMMER2_OFF_MASK_LO & root_blockref.data_off));
	rawip->version = HAMMER2_INODE_VERSION_ONE;
	rawip->ctime = now;
	rawip->mtime = now;
	/* rawip->atime = now; NOT IMPL MUST BE ZERO */
	rawip->btime = now;
	rawip->type = HAMMER2_OBJTYPE_DIRECTORY;
	rawip->mode = 0755;
	rawip->inum = 1;		/* root inode, inumber 1 */
	rawip->nlinks = 1; 		/* directory link count compat */

	rawip->name_len = strlen(Label);
	bcopy(Label, rawip->filename, rawip->name_len);
	rawip->name_key = dirhash(rawip->filename, rawip->name_len);

	/*
	 * Compression mode and supported copyids.
	 */
	rawip->comp_algo = HAMMER2_COMP_AUTOZERO;

	rawip->pfs_clid = Hammer2_RPFSId;
	rawip->pfs_type = HAMMER2_PFSTYPE_MASTER;
	rawip->op_flags |= HAMMER2_OPFLAG_PFSROOT;

	/* rawip->u.blockset is left empty */

	/*
	 * The root blockref will be stored in the super-root inode as
	 * the only directory entry.  The copyid here is the actual copyid
	 * of the storage ref.
	 *
	 * The key field for a directory entry's blockref is essentially
	 * the name key for the entry.
	 */
	root_blockref.key = rawip->name_key;
	root_blockref.copyid = HAMMER2_COPYID_LOCAL;
	root_blockref.keybits = 0;
	root_blockref.check.iscsi32.value =
			hammer2_icrc32(rawip, sizeof(*rawip));
	root_blockref.type = HAMMER2_BREF_TYPE_INODE;
	root_blockref.methods = HAMMER2_ENC_CHECK(HAMMER2_CHECK_ISCSI32) |
				HAMMER2_ENC_COMP(HAMMER2_COMP_AUTOZERO);

	/*
	 * Format the super-root directory inode, giving it one directory
	 * entry (root_blockref) and fixup the icrc method.
	 *
	 * The superroot contains one directory entry pointing at the root
	 * inode (named via the label).  Inodes contain one blockset which
	 * is fully associative so we can put the entry anywhere without
	 * having to worry about the hash.  Use index 0.
	 */
	rawip = (void *)(buf + (HAMMER2_OFF_MASK_LO & sroot_blockref.data_off));
	rawip->version = HAMMER2_INODE_VERSION_ONE;
	rawip->ctime = now;
	rawip->mtime = now;
	/* rawip->atime = now; NOT IMPL MUST BE ZERO */
	rawip->btime = now;
	rawip->type = HAMMER2_OBJTYPE_DIRECTORY;
	rawip->mode = 0700;		/* super-root - root only */
	rawip->inum = 0;		/* super root inode, inumber 0 */
	rawip->nlinks = 2; 		/* directory link count compat */

	rawip->name_len = 0;		/* super-root is unnamed */
	rawip->name_key = 0;

	rawip->comp_algo = HAMMER2_COMP_AUTOZERO;

	/*
	 * The super-root is flagged as a PFS and typically given its own
	 * random FSID, making it possible to mirror an entire HAMMER2 disk
	 * snapshots and all if desired.  PFS ids are used to match up
	 * mirror sources and targets and cluster copy sources and targets.
	 */
	rawip->pfs_clid = Hammer2_SPFSId;
	rawip->pfs_type = HAMMER2_PFSTYPE_MASTER;
	rawip->op_flags |= HAMMER2_OPFLAG_PFSROOT;

	/*
	 * The super-root has one directory entry pointing at the named
	 * root inode.
	 */
	rawip->u.blockset.blockref[0] = root_blockref;

	/*
	 * The sroot blockref will be stored in the volume header.
	 */
	sroot_blockref.copyid = HAMMER2_COPYID_LOCAL;
	sroot_blockref.keybits = 0;
	sroot_blockref.check.iscsi32.value =
					hammer2_icrc32(rawip, sizeof(*rawip));
	sroot_blockref.type = HAMMER2_BREF_TYPE_INODE;
	sroot_blockref.methods = HAMMER2_ENC_CHECK(HAMMER2_CHECK_ISCSI32) |
			         HAMMER2_ENC_COMP(HAMMER2_COMP_AUTOZERO);
	rawip = NULL;

	/*
	 * Write out the 64K HAMMER2 block containing the root and sroot.
	 */
	n = pwrite(fd, buf, HAMMER2_PBUFSIZE,
		   root_blockref.data_off & HAMMER2_OFF_MASK_HI);
	if (n != HAMMER2_PBUFSIZE) {
		perror("write");
		exit(1);
	}

	/*
	 * Set up the freemap blockref.  This blockref must point to the
	 * appropriate reserved block (ZONE_FREEMAP_A + ZONEFM_LAYER0).
	 * We use a special check method CHECK_FREEMAP which is basically
	 * just CHECK_ISCSI32 but contains additional hinting fields to
	 * help the allocator.
	 *
	 * Even though the freemap is multi-level, all newfs2_hammer2 needs
	 * to do is set up an empty root freemap indirect block.  The HAMMER2
	 * VFS will populate the remaining layers and leaf(s) on the fly.
	 *
	 * The root freemap indirect block must represent a space large enough
	 * to cover the whole filesystem.  Since we are using normal
	 * blockref's, each indirect freemap block represents
	 * FREEMAP_NODE_RADIX (10) bits of address space.  A 64KB leaf block
	 * represents FREEMAP_LEAF_REP (256MB) bytes of storage.
	 *
	 * For now we install a MAXIMAL key range to (potentially) support
	 * a sparse storage map by default.  Only certain keybits values
	 * are allowed for the freemap root (64, 54, 44, or 34).
	 */
	bzero(buf, HAMMER2_PBUFSIZE);
	bzero(&freemap_blockref, sizeof(freemap_blockref));
	freemap_blockref.vradix = HAMMER2_PBUFRADIX;
	freemap_blockref.data_off = (HAMMER2_ZONE_FREEMAP_A +
				     HAMMER2_ZONEFM_LAYER0) |
				    HAMMER2_PBUFRADIX;
	freemap_blockref.copyid = HAMMER2_COPYID_LOCAL;
	freemap_blockref.keybits = 64;
	freemap_blockref.type = HAMMER2_BREF_TYPE_FREEMAP_ROOT;
	freemap_blockref.methods = HAMMER2_ENC_CHECK(HAMMER2_CHECK_FREEMAP) |
				   HAMMER2_ENC_COMP(HAMMER2_COMP_AUTOZERO);

	/*
	 * check union also has hinting fields.  We can just set the (biggest)
	 * heuristic to a maximal value and let the allocator adjust it,
	 * and we must initialize (avail) properly (taking into account
	 * reserved blocks) so auto-initialized sub-trees/leafs match up
	 * to expected values.
	 */
	freemap_blockref.check.freemap.icrc32 =
					hammer2_icrc32(buf, HAMMER2_PBUFSIZE);
	freemap_blockref.check.freemap.biggest = 64;
	freemap_blockref.check.freemap.avail = free_space;

	n = pwrite(fd, buf, HAMMER2_PBUFSIZE,
		   freemap_blockref.data_off & HAMMER2_OFF_MASK_HI);
	if (n != HAMMER2_PBUFSIZE) {
		perror("write");
		exit(1);
	}

	/*
	 * Format the volume header.
	 *
	 * The volume header points to sroot_blockref.  Also be absolutely
	 * sure that allocator_beg is set.
	 */
	bzero(buf, HAMMER2_PBUFSIZE);
	vol = (void *)buf;

	vol->magic = HAMMER2_VOLUME_ID_HBO;
	vol->boot_beg = boot_base;
	vol->boot_end = boot_base + BootAreaSize;
	vol->aux_beg = aux_base;
	vol->aux_end = aux_base + AuxAreaSize;
	vol->volu_size = total_space;
	vol->version = Hammer2Version;
	vol->flags = 0;

	vol->fsid = Hammer2_FSId;
	vol->fstype = Hammer2_FSType;

	vol->peer_type = HAMMER2_PEER_HAMMER2;	/* LNK_CONN identification */

	vol->allocator_size = free_space;
	vol->allocator_free = free_space;
	vol->allocator_beg = alloc_base;

	vol->sroot_blockset.blockref[0] = sroot_blockref;
	vol->freemap_blockref = freemap_blockref;
	vol->mirror_tid = 0;
	vol->alloc_tid = 16;
	vol->icrc_sects[HAMMER2_VOL_ICRC_SECT1] =
			hammer2_icrc32((char *)vol + HAMMER2_VOLUME_ICRC1_OFF,
				       HAMMER2_VOLUME_ICRC1_SIZE);

	/*
	 * Set ICRC_SECT0 after all remaining elements of sect0 have been
	 * populated in the volume header.  Note hat ICRC_SECT* (except for
	 * SECT0) are part of sect0.
	 */
	vol->icrc_sects[HAMMER2_VOL_ICRC_SECT0] =
			hammer2_icrc32((char *)vol + HAMMER2_VOLUME_ICRC0_OFF,
				       HAMMER2_VOLUME_ICRC0_SIZE);
	vol->icrc_volheader =
			hammer2_icrc32((char *)vol + HAMMER2_VOLUME_ICRCVH_OFF,
				       HAMMER2_VOLUME_ICRCVH_SIZE);

	/*
	 * Write the volume header and all alternates.
	 */
	for (i = 0; i < HAMMER2_NUM_VOLHDRS; ++i) {
		if (i * HAMMER2_ZONE_BYTES64 >= total_space)
			break;
		n = pwrite(fd, buf, HAMMER2_PBUFSIZE,
			   volu_base + i * HAMMER2_ZONE_BYTES64);
		if (n != HAMMER2_PBUFSIZE) {
			perror("write");
			exit(1);
		}
	}

	/*
	 * Cleanup
	 */
	free(buf);
}

static void
alloc_direct(hammer2_off_t *basep, hammer2_blockref_t *bref, size_t bytes)
{
	int radix;

	radix = 0;
	assert(bytes);
	while ((bytes & 1) == 0) {
		bytes >>= 1;
		++radix;
	}
	assert(bytes == 1);
	if (radix < HAMMER2_MIN_RADIX)
		radix = HAMMER2_MIN_RADIX;

	bzero(bref, sizeof(*bref));
	bref->data_off = *basep | radix;
	bref->vradix = radix;

	*basep += 1U << radix;
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
static hammer2_key_t
dirhash(const unsigned char *name, size_t len)
{
	const unsigned char *aname = name;
	uint32_t crcx;
	uint64_t key;
	size_t i;
	size_t j;

	/*
	 * Filesystem version 6 or better will create directories
	 * using the ALG1 dirhash.  This hash breaks the filename
	 * up into domains separated by special characters and
	 * hashes each domain independently.
	 *
	 * We also do a simple sub-sort using the first character
	 * of the filename in the top 5-bits.
	 */
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
