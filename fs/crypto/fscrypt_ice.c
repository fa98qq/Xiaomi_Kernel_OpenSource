/* Copyright (c) 2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "fscrypt_ice.h"
#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/siphash.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

extern int fscrypt_get_mode_key_size(int mode);

/* Diagnostic: override the ICE data unit number. 0 = untouched. */
int ksdun_mode __read_mostly;
EXPORT_SYMBOL(ksdun_mode);

static u8 ksd_hkdf_key[16];
static int ksd_hkdf_done;
static DEFINE_MUTEX(ksd_hkdf_lock);

/*
 * HKDF-Expand(HKDF-Extract(0, ikm), "fscrypt\0" || ctx, info) -> 16 bytes,
 * using HMAC-SHA512, matching fs/crypto/hkdf.c from the Android-11 generation.
 */
static int ksd_hkdf16(const u8 *ikm, unsigned int ikmlen, u8 ctx,
		      const u8 *info, unsigned int infolen, u8 out[16])
{
	struct crypto_shash *tfm;
	u8 prk[SHA512_DIGEST_SIZE];
	u8 tmp[SHA512_DIGEST_SIZE];
	u8 zeros[SHA512_DIGEST_SIZE];
	u8 prefix[9];
	u8 ctr = 1;
	int err;
	SHASH_DESC_ON_STACK(desc, tfm);

	tfm = crypto_alloc_shash("hmac(sha512)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	memset(zeros, 0, sizeof(zeros));
	err = crypto_shash_setkey(tfm, zeros, sizeof(zeros));
	if (err)
		goto out;
	desc->tfm = tfm;
	desc->flags = 0;
	err = crypto_shash_digest(desc, ikm, ikmlen, prk);
	if (err)
		goto out;

	err = crypto_shash_setkey(tfm, prk, sizeof(prk));
	if (err)
		goto out;
	memcpy(prefix, "fscrypt\0", 8);
	prefix[8] = ctx;

	err = crypto_shash_init(desc);
	if (err)
		goto out;
	err = crypto_shash_update(desc, prefix, sizeof(prefix));
	if (err)
		goto out;
	if (infolen) {
		err = crypto_shash_update(desc, info, infolen);
		if (err)
			goto out;
	}
	err = crypto_shash_finup(desc, &ctr, 1, tmp);
	if (err)
		goto out;
	memcpy(out, tmp, 16);
out:
	memzero_explicit(prk, sizeof(prk));
	memzero_explicit(tmp, sizeof(tmp));
	crypto_free_shash(tfm);
	return err;
}

static void ksd_hkdf_prepare(const struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;
	unsigned int size;
	int err;

	if (ksd_hkdf_done || !ci)
		return;

	mutex_lock(&ksd_hkdf_lock);
	if (!ksd_hkdf_done) {
		size = fscrypt_get_mode_key_size(ci->ci_data_mode);
		if (size == 0 || size > FS_MAX_KEY_SIZE)
			size = FS_MAX_KEY_SIZE;
		err = ksd_hkdf16(ci->ci_raw_key, size, 7, NULL, 0,
				 ksd_hkdf_key);
		ksd_hkdf_done = 1;
		pr_info("KSDHKDF: size=%u err=%d key=%*phN\n", size, err,
			16, ksd_hkdf_key);
	}
	mutex_unlock(&ksd_hkdf_lock);
}

/* Diagnostic override of the DUN handed to the ICE hardware. */
static u64 ksd_override_dun(const struct inode *inode, u64 dun)
{
	struct fscrypt_info *ci = inode->i_crypt_info;
	u32 lblk = (u32)(dun & 0xffffffffULL);
	u32 nd = lblk;
	siphash_key_t k;

	if (!ci || !ksdun_mode)
		return dun;

	switch (ksdun_mode) {
	case 1:
		nd = lblk;
		break;
	case 2:
		nd = (u32)inode->i_ino + lblk;
		break;
	case 3:
		nd = (u32)inode->i_ino;
		break;
	case 4:
		memcpy(&k, &ci->ci_raw_key[0], sizeof(k));
		nd = (u32)siphash_1u64(inode->i_ino, &k) + lblk;
		break;
	case 5:
		memcpy(&k, &ci->ci_raw_key[32], sizeof(k));
		nd = (u32)siphash_1u64(inode->i_ino, &k) + lblk;
		break;
	case 6:
		memcpy(&k, &ci->ci_raw_key[48], sizeof(k));
		nd = (u32)siphash_1u64(inode->i_ino, &k) + lblk;
		break;
	case 7:
		ksd_hkdf_prepare(inode);
		memcpy(&k, ksd_hkdf_key, sizeof(k));
		nd = (u32)siphash_1u64(inode->i_ino, &k) + lblk;
		break;
	default:
		nd = lblk;
		break;
	}
	return (u64)nd;
}

int fscrypt_using_hardware_encryption(const struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;

	return S_ISREG(inode->i_mode) && ci &&
		ci->ci_data_mode == FS_ENCRYPTION_MODE_PRIVATE;
}
EXPORT_SYMBOL(fscrypt_using_hardware_encryption);

size_t fscrypt_get_ice_encryption_key_size(const struct inode *inode)
{
	struct fscrypt_info *ci = NULL;

	if (inode)
		ci = inode->i_crypt_info;
	if (!ci)
		return 0;

	return fscrypt_get_mode_key_size(ci->ci_data_mode) / 2;
}

size_t fscrypt_get_ice_encryption_salt_size(const struct inode *inode)
{
	struct fscrypt_info *ci = NULL;

	if (inode)
		ci = inode->i_crypt_info;
	if (!ci)
		return 0;

        return fscrypt_get_mode_key_size(ci->ci_data_mode) / 2;
}

/*
 * Retrieves encryption key from the inode
 */
char *fscrypt_get_ice_encryption_key(const struct inode *inode)
{
	struct fscrypt_info *ci = NULL;

	if (!inode)
		return NULL;

	ci = inode->i_crypt_info;
	if (!ci)
		return NULL;

	return &(ci->ci_raw_key[0]);
}

/*
 * Retrieves encryption salt from the inode
 */
char *fscrypt_get_ice_encryption_salt(const struct inode *inode)
{
	struct fscrypt_info *ci = NULL;
	int size = 0;

	if (!inode)
		return NULL;

	ci = inode->i_crypt_info;
	if (!ci)
		return NULL;

	size = fscrypt_get_ice_encryption_key_size(inode);
	if (!size)
		return NULL;

	return &(ci->ci_raw_key[size]);
}

/*
 * returns true if the cipher mode in inode is AES XTS
 */
int fscrypt_is_aes_xts_cipher(const struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;

	if (!ci)
		return 0;

	return (ci->ci_data_mode == FS_ENCRYPTION_MODE_PRIVATE);
}

/*
 * returns true if encryption info in both inodes is equal
 */
bool fscrypt_is_ice_encryption_info_equal(const struct inode *inode1,
					const struct inode *inode2)
{
	char *key1 = NULL;
	char *key2 = NULL;
	char *salt1 = NULL;
	char *salt2 = NULL;

	if (!inode1 || !inode2)
		return false;

	if (inode1 == inode2)
		return true;

	/* both do not belong to ice, so we don't care, they are equal
	 *for us
	 */
	if (!fscrypt_should_be_processed_by_ice(inode1) &&
			!fscrypt_should_be_processed_by_ice(inode2))
		return true;

	/* one belongs to ice, the other does not -> not equal */
	if (fscrypt_should_be_processed_by_ice(inode1) ^
			fscrypt_should_be_processed_by_ice(inode2))
		return false;

	key1 = fscrypt_get_ice_encryption_key(inode1);
	key2 = fscrypt_get_ice_encryption_key(inode2);
	salt1 = fscrypt_get_ice_encryption_salt(inode1);
	salt2 = fscrypt_get_ice_encryption_salt(inode2);

	/* key and salt should not be null by this point */
	if (!key1 || !key2 || !salt1 || !salt2 ||
		(fscrypt_get_ice_encryption_key_size(inode1) !=
		 fscrypt_get_ice_encryption_key_size(inode2)) ||
		(fscrypt_get_ice_encryption_salt_size(inode1) !=
		 fscrypt_get_ice_encryption_salt_size(inode2)))
		return false;

	if ((memcmp(key1, key2,
			fscrypt_get_ice_encryption_key_size(inode1)) == 0) &&
		(memcmp(salt1, salt2,
			fscrypt_get_ice_encryption_salt_size(inode1)) == 0))
		return true;

	return false;
}

void fscrypt_set_ice_dun(const struct inode *inode, struct bio *bio, u64 dun)
{
	static atomic_t ksu_ice_cnt = ATOMIC_INIT(0);

	if (fscrypt_should_be_processed_by_ice(inode)) {
		u64 odun = ksd_override_dun(inode, dun);

		bio->bi_iter.bi_dun = odun;
		if (atomic_inc_return(&ksu_ice_cnt) <= 400)
			pr_info("KSUICE: ino=%lu dun=%llu odun=%llu mode=%d hw=%d\n",
				inode->i_ino, dun, odun, ksdun_mode,
				fscrypt_using_hardware_encryption(inode));
	}
}
EXPORT_SYMBOL(fscrypt_set_ice_dun);

void fscrypt_set_ice_skip(struct bio *bio, int bi_crypt_skip)
{
#ifdef CONFIG_DM_DEFAULT_KEY
	bio->bi_crypt_skip = bi_crypt_skip;
#endif
}
EXPORT_SYMBOL(fscrypt_set_ice_skip);

/*
 * This function will be used for filesystem when deciding to merge bios.
 * Basic assumption is, if inline_encryption is set, single bio has to
 * guarantee consecutive LBAs as well as ino|pg->index.
 */
bool fscrypt_mergeable_bio(struct bio *bio, u64 dun, bool bio_encrypted,
						int bi_crypt_skip)
{
	if (!bio)
		return true;

#ifdef CONFIG_DM_DEFAULT_KEY
	if (bi_crypt_skip != bio->bi_crypt_skip)
		return false;
#endif
	/* if both of them are not encrypted, no further check is needed */
	if (!bio_dun(bio) && !bio_encrypted)
		return true;

	/* Diagnostic mode rewrites the DUN per page, so never merge. */
	if (ksdun_mode && bio_encrypted)
		return false;

	/* ICE allows only consecutive iv_key stream. */
	return bio_end_dun(bio) == dun;
}
EXPORT_SYMBOL(fscrypt_mergeable_bio);
