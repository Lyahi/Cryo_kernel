/*
 * Copyright (C) 2015 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/buffer_head.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/device-mapper.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/of.h>
#include <linux/reboot.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/setup.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <crypto/public_key.h>
#include <crypto/sha.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>

#include "dm-verity.h"
#include "dm-android-verity.h"

static char verifiedbootstate[VERITY_COMMANDLINE_PARAM_LENGTH];
static char veritymode[VERITY_COMMANDLINE_PARAM_LENGTH];
static char veritykeyid[VERITY_DEFAULT_KEY_ID_LENGTH];
static char buildvariant[BUILD_VARIANT];

static bool target_added;
static bool verity_enabled = true;
struct dentry *debug_dir;
static int android_verity_ctr(struct dm_target *ti, unsigned argc, char **argv);

static struct target_type android_verity_target = {
	.name                   = "android-verity",
	.version                = {1, 0, 0},
	.module                 = THIS_MODULE,
	.ctr                    = android_verity_ctr,
	.dtr                    = verity_dtr,
	.map                    = verity_map,
	.status                 = verity_status,
	.prepare_ioctl          = verity_prepare_ioctl,
	.iterate_devices        = verity_iterate_devices,
	.io_hints               = verity_io_hints,
};

static int __init verified_boot_state_param(char *line)
{
	strlcpy(verifiedbootstate, line, sizeof(verifiedbootstate));
	return 1;
}

__setup("androidboot.verifiedbootstate=", verified_boot_state_param);

static int __init verity_mode_param(char *line)
{
	strlcpy(veritymode, line, sizeof(veritymode));
	return 1;
}

__setup("androidboot.veritymode=", verity_mode_param);

static int __init verity_keyid_param(char *line)
{
	strlcpy(veritykeyid, line, sizeof(veritykeyid));
	return 1;
}

__setup("veritykeyid=", verity_keyid_param);

static int __init verity_buildvariant(char *line)
{
	strlcpy(buildvariant, line, sizeof(buildvariant));
	return 1;
}

__setup("buildvariant=", verity_buildvariant);

static inline bool default_verity_key_id(void)
{
	return veritykeyid[0] != '\0';
}

static inline bool is_eng(void)
{
	static const char typeeng[]  = "eng";

	return !strncmp(buildvariant, typeeng, sizeof(typeeng));
}

static inline bool is_userdebug(void)
{
	static const char typeuserdebug[]  = "userdebug";

	return !strncmp(buildvariant, typeuserdebug, sizeof(typeuserdebug));
}

static inline bool is_unlocked(void)
{
	static const char unlocked[] = "orange";

	return !strncmp(verifiedbootstate, unlocked, sizeof(unlocked));
}

static int read_block_dev(struct bio_read *payload, struct block_device *bdev,
		sector_t offset, int length)
{
	struct bio *bio;
	int err = 0, i;

	payload->number_of_pages = DIV_ROUND_UP(length, PAGE_SIZE);

	bio = bio_alloc(GFP_KERNEL, payload->number_of_pages);
	if (!bio) {
		DMERR("Error while allocating bio");
		return -ENOMEM;
	}

	bio_set_dev(bio, bdev);
	bio->bi_iter.bi_sector = offset;
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	payload->page_io = kzalloc(sizeof(struct page *) *
		payload->number_of_pages, GFP_KERNEL);
	if (!payload->page_io) {
		DMERR("page_io array alloc failed");
		err = -ENOMEM;
		goto free_bio;
	}

	for (i = 0; i < payload->number_of_pages; i++) {
		payload->page_io[i] = alloc_page(GFP_KERNEL);
		if (!payload->page_io[i]) {
			DMERR("alloc_page failed");
			err = -ENOMEM;
			goto free_pages;
		}
		if (!bio_add_page(bio, payload->page_io[i], PAGE_SIZE, 0)) {
			DMERR("bio_add_page error");
			err = -EIO;
			goto free_pages;
		}
	}

	if (!submit_bio_wait(bio))
		/* success */
		goto free_bio;
	DMERR("bio read failed");
	err = -EIO;

free_pages:
	for (i = 0; i < payload->number_of_pages; i++)
		if (payload->page_io[i])
			__free_page(payload->page_io[i]);
	kfree(payload->page_io);
free_bio:
	bio_put(bio);
	return err;
}

static inline u64 fec_div_round_up(u64 x, u64 y)
{
	u64 remainder;

	return div64_u64_rem(x, y, &remainder) +
		(remainder > 0 ? 1 : 0);
}

static inline void populate_fec_metadata(struct fec_header *header,
				struct fec_ecc_metadata *ecc)
{
	ecc->blocks = fec_div_round_up(le64_to_cpu(header->inp_size),
			FEC_BLOCK_SIZE);
	ecc->roots = le32_to_cpu(header->roots);
	ecc->start = le64_to_cpu(header->inp_size);
}

static inline int validate_fec_header(struct fec_header *header, u64 offset)
{
	/* move offset to make the sanity check work for backup header
	 * as well. */
	offset -= offset % FEC_BLOCK_SIZE;
	if (le32_to_cpu(header->magic) != FEC_MAGIC ||
		le32_to_cpu(header->version) != FEC_VERSION ||
		le32_to_cpu(header->size) != sizeof(struct fec_header) ||
		le32_to_cpu(header->roots) == 0 ||
		le32_to_cpu(header->roots) >= FEC_RSM)
		return -EINVAL;

	return 0;
}

static int extract_fec_header(dev_t dev, struct fec_header *fec,
				struct fec_ecc_metadata *ecc)
{
	u64 device_size;
	struct bio_read payload;
	int i, err = 0;
	struct block_device *bdev;

	bdev = blkdev_get_by_dev(dev, FMODE_READ, NULL);

	if (IS_ERR_OR_NULL(bdev)) {
		DMERR("bdev get error");
		return PTR_ERR(bdev);
	}

	device_size = i_size_read(bdev->bd_inode);

	/* fec metadata size is a power of 2 and PAGE_SIZE
	 * is a power of 2 as well.
	 */
	BUG_ON(FEC_BLOCK_SIZE > PAGE_SIZE);
	/* 512 byte sector alignment */
	BUG_ON(((device_size - FEC_BLOCK_SIZE) % (1 << SECTOR_SHIFT)) != 0);

	err = read_block_dev(&payload, bdev, (device_size -
		FEC_BLOCK_SIZE) / (1 << SECTOR_SHIFT), FEC_BLOCK_SIZE);
	if (err) {
		DMERR("Error while reading verity metadata");
		goto error;
	}

	BUG_ON(sizeof(struct fec_header) > PAGE_SIZE);
	memcpy(fec, page_address(payload.page_io[0]),
			sizeof(*fec));

	ecc->valid = true;
	if (validate_fec_header(fec, device_size - FEC_BLOCK_SIZE)) {
		/* Try the backup header */
		memcpy(fec, page_address(payload.page_io[0]) + FEC_BLOCK_SIZE
			- sizeof(*fec) ,
			sizeof(*fec));
		if (validate_fec_header(fec, device_size -
			sizeof(struct fec_header)))
			ecc->valid = false;
	}

	if (ecc->valid)
		populate_fec_metadata(fec, ecc);

	for (i = 0; i < payload.number_of_pages; i++)
		__free_page(payload.page_io[i]);
	kfree(payload.page_io);

error:
	blkdev_put(bdev, FMODE_READ);
	return err;
}
static void find_metadata_offset(struct fec_header *fec,
		struct block_device *bdev, u64 *metadata_offset)
{
	u64 device_size;

	device_size = i_size_read(bdev->bd_inode);

	if (le32_to_cpu(fec->magic) == FEC_MAGIC)
		*metadata_offset = le64_to_cpu(fec->inp_size) -
					VERITY_METADATA_SIZE;
	else
		*metadata_offset = device_size - VERITY_METADATA_SIZE;
}

static int find_size(dev_t dev, u64 *device_size)
{
	struct block_device *bdev;

	bdev = blkdev_get_by_dev(dev, FMODE_READ, NULL);
	if (IS_ERR_OR_NULL(bdev)) {
		DMERR("blkdev_get_by_dev failed");
		return PTR_ERR(bdev);
	}

	*device_size = i_size_read(bdev->bd_inode);
	*device_size >>= SECTOR_SHIFT;

	DMINFO("blkdev size in sectors: %llu", *device_size);
	blkdev_put(bdev, FMODE_READ);
	return 0;
}

static int verify_header(struct android_metadata_header *header)
{
	int retval = -EINVAL;

	if (is_userdebug() && le32_to_cpu(header->magic_number) ==
			VERITY_METADATA_MAGIC_DISABLE)
		return VERITY_STATE_DISABLE;

	if (!(le32_to_cpu(header->magic_number) ==
			VERITY_METADATA_MAGIC_NUMBER) ||
			(le32_to_cpu(header->magic_number) ==
			VERITY_METADATA_MAGIC_DISABLE)) {
		DMERR("Incorrect magic number");
		return retval;
	}

	if (le32_to_cpu(header->protocol_version) !=
			VERITY_METADATA_VERSION) {
		DMERR("Unsupported version %u",
			le32_to_cpu(header->protocol_version));
		return retval;
	}

	return 0;
}

static int extract_metadata(dev_t dev, struct fec_header *fec,
				struct android_metadata **metadata,
				bool *verity_enabled)
{
	struct block_device *bdev;
	struct android_metadata_header *header;
	int i;
	u32 table_length, copy_length, offset;
	u64 metadata_offset;
	struct bio_read payload;
	int err = 0;

	bdev = blkdev_get_by_dev(dev, FMODE_READ, NULL);

	if (IS_ERR_OR_NULL(bdev)) {
		DMERR("blkdev_get_by_dev failed");
		return -ENODEV;
	}

	find_metadata_offset(fec, bdev, &metadata_offset);

	/* Verity metadata size is a power of 2 and PAGE_SIZE
	 * is a power of 2 as well.
	 * PAGE_SIZE is also a multiple of 512 bytes.
	*/
	if (VERITY_METADATA_SIZE > PAGE_SIZE)
		BUG_ON(VERITY_METADATA_SIZE % PAGE_SIZE != 0);
	/* 512 byte sector alignment */
	BUG_ON(metadata_offset % (1 << SECTOR_SHIFT) != 0);

	err = read_block_dev(&payload, bdev, metadata_offset /
		(1 << SECTOR_SHIFT), VERITY_METADATA_SIZE);
	if (err) {
		DMERR("Error while reading verity metadata");
		goto blkdev_release;
	}

	header = kzalloc(sizeof(*header), GFP_KERNEL);
	if (!header) {
		DMERR("kzalloc failed for header");
		err = -ENOMEM;
		goto free_payload;
	}

	memcpy(header, page_address(payload.page_io[0]),
		sizeof(*header));

	DMINFO("bio magic_number:%u protocol_version:%d table_length:%u",
		le32_to_cpu(header->magic_number),
		le32_to_cpu(header->protocol_version),
		le32_to_cpu(header->table_length));

	err = verify_header(header);

	if (err == VERITY_STATE_DISABLE) {
		DMERR("Mounting root with verity disabled");
		*verity_enabled = false;
		/* we would still have to read the metadata to figure out
		 * the data blocks size. Or may be could map the entire
		 * partition similar to mounting the device.
		 *
		 * Reset error as well as the verity_enabled flag is changed.
		 */
		err = 0;
	} else if (err)
		goto free_header;

	*metadata = kzalloc(sizeof(**metadata), GFP_KERNEL);
	if (!*metadata) {
		DMERR("kzalloc for metadata failed");
		err = -ENOMEM;
		goto free_header;
	}

	(*metadata)->header = header;
	table_length = le32_to_cpu(header->table_length);

	if (table_length == 0 ||
		table_length > (VERITY_METADATA_SIZE -
			sizeof(struct android_metadata_header))) {
		DMERR("table_length too long");
		err = -EINVAL;
		goto free_metadata;
	}

	(*metadata)->verity_table = kzalloc(table_length + 1, GFP_KERNEL);

	if (!(*metadata)->verity_table) {
		DMERR("kzalloc verity_table failed");
		err = -ENOMEM;
		goto free_metadata;
	}

	if (sizeof(struct android_metadata_header) +
			table_length <= PAGE_SIZE) {
		memcpy((*metadata)->verity_table,
			page_address(payload.page_io[0])
			+ sizeof(struct android_metadata_header),
			table_length);
	} else {
		copy_length = PAGE_SIZE -
			sizeof(struct android_metadata_header);
		memcpy((*metadata)->verity_table,
			page_address(payload.page_io[0])
			+ sizeof(struct android_metadata_header),
			copy_length);
		table_length -= copy_length;
		offset = copy_length;
		i = 1;
		while (table_length != 0) {
			if (table_length > PAGE_SIZE) {
				memcpy((*metadata)->verity_table + offset,
					page_address(payload.page_io[i]),
					PAGE_SIZE);
				offset += PAGE_SIZE;
				table_length -= PAGE_SIZE;
			} else {
				memcpy((*metadata)->verity_table + offset,
					page_address(payload.page_io[i]),
					table_length);
				table_length = 0;
			}
			i++;
		}
	}
	(*metadata)->verity_table[table_length] = '\0';

	DMINFO("verity_table: %s", (*metadata)->verity_table);
	goto free_payload;

free_metadata:
	kfree(*metadata);
free_header:
	kfree(header);
free_payload:
	for (i = 0; i < payload.number_of_pages; i++)
		if (payload.page_io[i])
			__free_page(payload.page_io[i]);
	kfree(payload.page_io);
blkdev_release:
	blkdev_put(bdev, FMODE_READ);
	return err;
}

/* helper functions to extract properties from dts */
const char *find_dt_value(const char *name)
{
	struct device_node *firmware;
	const char *value;

	firmware = of_find_node_by_path("/firmware/android");
	if (!firmware)
		return NULL;
	value = of_get_property(firmware, name, NULL);
	of_node_put(firmware);

	return value;
}

static int verity_mode(void)
{
	static const char enforcing[] = "enforcing";
	static const char verified_mode_prop[] = "veritymode";
	const char *value;

	value = find_dt_value(verified_mode_prop);
	if (!value)
		value = veritymode;
	if (!strncmp(value, enforcing, sizeof(enforcing) - 1))
		return DM_VERITY_MODE_RESTART;

	return DM_VERITY_MODE_EIO;
}

static void handle_error(void)
{
	int mode = verity_mode();
	if (mode == DM_VERITY_MODE_RESTART) {
		DMERR("triggering restart");
		kernel_restart("dm-verity device corrupted");
	} else {
		DMERR("Mounting verity root failed");
	}
}

static struct public_key_signature *table_make_digest(
						enum hash_algo hash,
						const void *table,
						unsigned long table_len)
{
	struct public_key_signature *pks = NULL;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t digest_size, desc_size;
	int ret;

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	tfm = crypto_alloc_shash(hash_algo_name[hash], 0, 0);
	if (IS_ERR(tfm))
		return ERR_CAST(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	digest_size = crypto_shash_digestsize(tfm);

	/* We allocate the hash operational data storage on the end of out
	 * context data and the digest output buffer on the end of that.
	 */
	ret = -ENOMEM;
	pks = kzalloc(digest_size + sizeof(*pks) + desc_size, GFP_KERNEL);
	if (!pks)
		goto error;

	pks->pkey_algo = "rsa";
	pks->hash_algo = hash_algo_name[hash];
	pks->digest = (u8 *)pks + sizeof(*pks) + desc_size;
	pks->digest_size = digest_size;

	desc = (struct shash_desc *)(pks + 1);
	desc->tfm = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	ret = crypto_shash_finup(desc, table, table_len, pks->digest);
	if (ret < 0)
		goto error;

	crypto_free_shash(tfm);
	return pks;

error:
	kfree(pks);
	crypto_free_shash(tfm);
	return ERR_PTR(ret);
}


static int verify_verity_signature(char *key_id,
		struct android_metadata *metadata)
{
	struct public_key_signature *pks = NULL;
	int retval = -EINVAL;

	if (!key_id)
		goto error;

	pks = table_make_digest(HASH_ALGO_SHA256,
			(const void *)metadata->verity_table,
			le32_to_cpu(metadata->header->table_length));
	if (IS_ERR(pks)) {
		DMERR("hashing failed");
		retval = PTR_ERR(pks);
		pks = NULL;
		goto error;
	}

	pks->s = kmemdup(&metadata->header->signature[0], RSANUMBYTES, GFP_KERNEL);
	if (!pks->s) {
		DMERR("Error allocating memory for signature");
		goto error;
	}
	pks->s_size = RSANUMBYTES;

	retval = verify_signature_one(pks, NULL, key_id);
	kfree(pks->s);
error:
	kfree(pks);
	return retval;
}

static inline bool test_mult_overflow(sector_t a, u32 b)
{
	sector_t r = (sector_t)~0ULL;

	sector_div(r, b);
	return a > r;
}

static int add_as_linear_device(struct dm_target *ti, char *dev)
{
	/*Move to linear mapping defines*/
	char *linear_table_args[DM_LINEAR_ARGS] = {dev,
					DM_LINEAR_TARGET_OFFSET};
	int err = 0;

	android_verity_target.dtr = dm_linear_dtr,
	android_verity_target.map = dm_linear_map,
	android_verity_target.status = dm_linear_status,
	android_verity_target.end_io = dm_linear_end_io,
	android_verity_target.prepare_ioctl = dm_linear_prepare_ioctl,
	android_verity_target.iterate_devices = dm_linear_iterate_devices,
        android_verity_target.direct_access = dm_linear_dax_direct_access,
        android_verity_target.dax_copy_from_iter = dm_linear_dax_copy_from_iter,
	android_verity_target.io_hints = NULL;

	set_disk_ro(dm_disk(dm_table_get_md(ti->table)), 0);

	err = dm_linear_ctr(ti, DM_LINEAR_ARGS, linear_table_args);

	if (!err) {
		DMINFO("Added android-verity as a linear target");
		target_added = true;
	} else
		DMERR("Failed to add android-verity as linear target");

	return err;
}

static int create_linear_device(struct dm_target *ti, dev_t dev,
				char *target_device)
{
	u64 device_size = 0;
	int err = find_size(dev, &device_size);

	if (err) {
		DMERR("error finding bdev size");
		handle_error();
		return err;
	}

	ti->len = device_size;
	err = add_as_linear_device(ti, target_device);
	if (err) {
		handle_error();
		return err;
	}
	verity_enabled = false;
	return 0;
}

/*
 * Target parameters:
 *	<key id>	Key id of the public key in the system keyring.
 *			Verity metadata's signature would be verified against
 *			this. If the key id contains spaces, replace them
 *			with '#'.
 *	<block device>	The block device for which dm-verity is being setup.
 */
static int android_verity_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	dev_t uninitialized_var(dev);
	struct android_metadata *metadata;
	int err = 0, i, mode;
	char *key_id = NULL, *table_ptr, dummy, *target_device;
	char *verity_table_args[VERITY_TABLE_ARGS + 2 + VERITY_TABLE_OPT_FEC_ARGS];
	/* One for specifying number of opt args and one for mode */
	sector_t data_sectors;
	u32 data_block_size;
	unsigned int no_of_args = VERITY_TABLE_ARGS + 2 + VERITY_TABLE_OPT_FEC_ARGS;
	struct fec_header uninitialized_var(fec);
	struct fec_ecc_metadata uninitialized_var(ecc);
	char buf[FEC_ARG_LENGTH], *buf_ptr;
	unsigned long long tmpll;

	if (argc == 1) {
		/* Use the default keyid */
		if (default_verity_key_id())
			key_id = veritykeyid;
		else if (!is_eng()) {
			DMERR("veritykeyid= is not set");
			handle_error();
			return -EINVAL;
		}
		target_device = argv[0];
	} else if (argc == 2) {
		key_id = argv[0];
		target_device = argv[1];
	} else {
		DMERR("Incorrect number of arguments");
		handle_error();
		return -EINVAL;
	}

	dev = name_to_dev_t(target_device);
	if (!dev) {
		DMERR("no dev found for %s", target_device);
		handle_error();
		return -EINVAL;
	}

	if (is_eng())
		return create_linear_device(ti, dev, target_device);

	strreplace(key_id, '#', ' ');

	DMINFO("key:%s dev:%s", key_id, target_device);

	if (extract_fec_header(dev, &fec, &ecc)) {
		DMERR("Error while extracting fec header");
		handle_error();
		return -EINVAL;
	}

	err = extract_metadata(dev, &fec, &metadata, &verity_enabled);

	if (err) {
		/* Allow invalid metadata when the device is unlocked */
		if (is_unlocked()) {
			DMWARN("Allow invalid metadata when unlocked");
			return create_linear_device(ti, dev, target_device);
		}
		DMERR("Error while extracting metadata");
		handle_error();
		return err;
	}

	if (verity_enabled) {
		err = verify_verity_signature(key_id, metadata);

		if (err) {
			DMERR("Signature verification failed");
			handle_error();
			goto free_metadata;
		} else
			DMINFO("Signature verification success");
	}

	table_ptr = metadata->verity_table;

	for (i = 0; i < VERITY_TABLE_ARGS; i++) {
		verity_table_args[i] = strsep(&table_ptr, " ");
		if (verity_table_args[i] == NULL)
			break;
	}

	if (i != VERITY_TABLE_ARGS) {
		DMERR("Verity table not in the expected format");
		err = -EINVAL;
		handle_error();
		goto free_metadata;
	}

	if (sscanf(verity_table_args[5], "%llu%c", &tmpll, &dummy)
							!= 1) {
		DMERR("Verity table not in the expected format");
		handle_error();
		err = -EINVAL;
		goto free_metadata;
	}

	if (tmpll > ULONG_MAX) {
		DMERR("<num_data_blocks> too large. Forgot to turn on CONFIG_LBDAF?");
		handle_error();
		err = -EINVAL;
		goto free_metadata;
	}

	data_sectors = tmpll;

	if (sscanf(verity_table_args[3], "%u%c", &data_block_size, &dummy)
								!= 1) {
		DMERR("Verity table not in the expected format");
		handle_error();
		err = -EINVAL;
		goto free_metadata;
	}

	if (test_mult_overflow(data_sectors, data_block_size >>
							SECTOR_SHIFT)) {
		DMERR("data_sectors too large");
		handle_error();
		err = -EOVERFLOW;
		goto free_metadata;
	}

	data_sectors *= data_block_size >> SECTOR_SHIFT;
	DMINFO("Data sectors %llu", (unsigned long long)data_sectors);

	/* update target length */
	ti->len = data_sectors;

	/* Setup linear target and free */
	if (!verity_enabled) {
		err = add_as_linear_device(ti, target_device);
		goto free_metadata;
	}

	/*substitute data_dev and hash_dev*/
	verity_table_args[1] = target_device;
	verity_table_args[2] = target_device;

	mode = verity_mode();

	if (ecc.valid && IS_BUILTIN(CONFIG_DM_VERITY_FEC)) {
		if (mode) {
			err = snprintf(buf, FEC_ARG_LENGTH,
				"%u %s " VERITY_TABLE_OPT_FEC_FORMAT,
				1 + VERITY_TABLE_OPT_FEC_ARGS,
				mode == DM_VERITY_MODE_RESTART ?
					VERITY_TABLE_OPT_RESTART :
					VERITY_TABLE_OPT_LOGGING,
				target_device,
				ecc.start / FEC_BLOCK_SIZE, ecc.blocks,
				ecc.roots);
		} else {
			err = snprintf(buf, FEC_ARG_LENGTH,
				"%u " VERITY_TABLE_OPT_FEC_FORMAT,
				VERITY_TABLE_OPT_FEC_ARGS, target_device,
				ecc.start / FEC_BLOCK_SIZE, ecc.blocks,
				ecc.roots);
		}
	} else if (mode) {
		err = snprintf(buf, FEC_ARG_LENGTH,
			"2 " VERITY_TABLE_OPT_IGNZERO " %s",
			mode == DM_VERITY_MODE_RESTART ?
			VERITY_TABLE_OPT_RESTART : VERITY_TABLE_OPT_LOGGING);
	} else {
		err = snprintf(buf, FEC_ARG_LENGTH, "1 %s",
				 "ignore_zero_blocks");
	}

	if (err < 0 || err >= FEC_ARG_LENGTH)
		goto free_metadata;

	buf_ptr = buf;

	for (i = VERITY_TABLE_ARGS; i < (VERITY_TABLE_ARGS +
		VERITY_TABLE_OPT_FEC_ARGS + 2); i++) {
		verity_table_args[i] = strsep(&buf_ptr, " ");
		if (verity_table_args[i] == NULL) {
			no_of_args = i;
			break;
		}
	}

	err = verity_ctr(ti, no_of_args, verity_table_args);
	if (err) {
		DMERR("android-verity failed to create a verity target");
	} else {
		target_added = true;
		DMINFO("android-verity created as verity target");
	}

free_metadata:
	kfree(metadata->header);
	kfree(metadata->verity_table);

	kfree(metadata);

	return err;
}

static int __init dm_android_verity_init(void)
{
	int r;
	struct dentry *file;

	r = dm_register_target(&android_verity_target);
	if (r < 0)
		DMERR("register failed %d", r);

	/* Tracks the status of the last added target */
	debug_dir = debugfs_create_dir("android_verity", NULL);

	if (IS_ERR_OR_NULL(debug_dir)) {
		DMERR("Cannot create android_verity debugfs directory: %ld",
			PTR_ERR(debug_dir));
		goto end;
	}

	file = debugfs_create_bool("target_added", S_IRUGO, debug_dir,
				&target_added);

	if (IS_ERR_OR_NULL(file)) {
		DMERR("Cannot create android_verity debugfs directory: %ld",
			PTR_ERR(debug_dir));
		debugfs_remove_recursive(debug_dir);
		goto end;
	}

	file = debugfs_create_bool("verity_enabled", S_IRUGO, debug_dir,
				&verity_enabled);

	if (IS_ERR_OR_NULL(file)) {
		DMERR("Cannot create android_verity debugfs directory: %ld",
			PTR_ERR(debug_dir));
		debugfs_remove_recursive(debug_dir);
	}

end:
	return r;
}

static void __exit dm_android_verity_exit(void)
{
	if (!IS_ERR_OR_NULL(debug_dir))
		debugfs_remove_recursive(debug_dir);

	dm_unregister_target(&android_verity_target);
}

module_init(dm_android_verity_init);
module_exit(dm_android_verity_exit);
