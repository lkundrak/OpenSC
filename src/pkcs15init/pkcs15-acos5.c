/*
 * acos5 specific operations for PKCS15 initialization
 * (from pkcs15-myeid.c)
 *
 * Copyright (C) 2008-2009 Aventra Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

#define ACOS5_EXPONENT 3

static sc_pkcs15_id_t acos5_tmp_pubkey_id;

/*
 * Card initialization.
 */
static int
acos5_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	sc_path_t	path;
	sc_file_t	*file;
	int		r;

	/* could create MF here if card is really blank, I think */

	sc_format_path("3F00", &path);
	if ((r = sc_select_file(p15card->card, &path, &file)) < 0) {
		return r;
	}

	sc_file_free(file);

	return (0);
}

#define ACOS_MAIN_SE_FILE 0x6021

/*
 * Initialize the Application DF
 */
static int 
acos5_create_dir(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	int r;
	u8 sec_attr[100], *p;
	int sec_attr_len;
	u8 type_attr[100];
	int type_attr_len;
	sc_file_t *pinfile;

	r = sc_create_file (p15card->card, df);
	if (r == SC_ERROR_FILE_ALREADY_EXISTS)
		r = 0;
	LOG_TEST_RET (ctx, r, "can't create appdir");

	if (0) {
		/* create SE file */
		p = sec_attr;
		*p++ = 0x8d;
		*p++ = 2;
		*p++ = (ACOS_MAIN_SE_FILE >> 8) & 0xff;
		*p++ = ACOS_MAIN_SE_FILE & 0xff;
		/* later will put Security Attributes Compact here too */
		sec_attr_len = p - sec_attr;
		
		sc_file_set_sec_attr (df, sec_attr,  sec_attr_len);
		
		r = sc_create_file (p15card->card, df);
		SC_TEST_RET (ctx, SC_LOG_DEBUG_NORMAL,
			     r, "can't create fresh appdir");
	}
	
	return (r);
}

static int acos5_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df, sc_pkcs15_object_t *pin_obj,
	const u8 *pin, size_t pin_len, const u8 *puk, size_t puk_len)
{
	/* df is for the appdir */
	/* ideas from pkcs15-setcos.c */

	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	int r;
	sc_file_t *pinfile;
	int dlen;
	u8 data[100];
	int i;
	sc_apdu_t apdu;
	u8 *p;
	u8 type_attr[100];
	int type_attr_len;
	int refnum;

	r = sc_profile_get_file (profile, "pinfile", &pinfile);
	SC_TEST_RET (ctx, SC_LOG_DEBUG_NORMAL, r, "Cannot get pinfile from profile");

	r = sc_select_file (card, &pinfile->path, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_debug (ctx, SC_LOG_DEBUG_NORMAL, "creating pinfile");
		
		r = sc_profile_get_file (profile, "pinfile", &pinfile);
		SC_TEST_RET (ctx, SC_LOG_DEBUG_NORMAL, r, "Cannot get pinfile from profile");

		p = type_attr;
		*p++ = 0x82;
		*p++ = 0x05;
		*p++ = 0x0c; /* fdb linear variable ef */
		*p++ = 0x01; /* dcb, unused in acos5 */
		*p++ = 0x00; /* must be 0 */
		*p++ = 18; /* mrl: max record len */
		*p++ = 4; /* nor: number of records */

		*p++ = 0x88; /* set sfi to 1 */
		*p++ = 0x01;
		*p++ = 0x01; 
	
		type_attr_len = p - type_attr;
		sc_file_set_type_attr (pinfile, type_attr, type_attr_len);
	
		r = sc_create_file (p15card->card, pinfile);
		SC_TEST_RET (ctx, SC_LOG_DEBUG_NORMAL, r, "pinfile creation failed");

		r = sc_select_file (card, &pinfile->path, NULL);
	}
	SC_TEST_RET (ctx, SC_LOG_DEBUG_NORMAL, r, "select pinfile failed");

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "pinfile->status:%X", pinfile->status);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "create PIN with reference:%X, flags:%X, path:%s",
			auth_info->attrs.pin.reference, auth_info->attrs.pin.flags, sc_print_path(&auth_info->path));

	if (pin_len < 1 || pin_len > 16) {
		sc_debug (ctx, SC_LOG_DEBUG_NORMAL, "invalid pin length");
		return (SC_ERROR_INTERNAL);
	}

	refnum = auth_info->attrs.pin.reference;
	if (refnum < 1 || refnum > 4) {
		sc_debug (ctx, SC_LOG_DEBUG_NORMAL, "pin reference num must be 1..4; got %d", refnum);
		return (SC_ERROR_INTERNAL);
	}

	/* manual section 3.1.1 PIN Data Structure */
	dlen = 0;
	data[dlen++] = 0x80 | refnum;
	data[dlen++] = 0xff; /* don't use pin fail counter for now */
	for (i = 0; i < pin_len; i++)
		data[dlen++] = pin[i];

	sc_format_apdu (card, &apdu, SC_APDU_CASE_3_SHORT, 0xdc, refnum, 4);
	apdu.lc = dlen;
	apdu.datalen = dlen;
	apdu.data = data;
	r = sc_transmit_apdu (card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");	
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	
	sc_file_free (pinfile); /* XXX leaked above */

	return (0);
}

static int
acos5_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *obj)
{
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	struct sc_file	*keyfile = NULL;
	size_t		bytes, mod_len, exp_len, prv_len, pub_len;
	int		r, algo;
	struct sc_file *found = NULL;

	/* The caller is supposed to have chosen a key file path for us */
	if (key_info->path.len == 0 || key_info->modulus_length == 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* Get the file we're supposed to create */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &keyfile);
	if (r < 0)
		return r;

	keyfile->size = key_info->modulus_length / 8;

	if ((r = sc_pkcs15init_fixup_file(profile, p15card, keyfile)) < 0)
		goto done;

	r = sc_select_file (p15card->card, &keyfile->path, &found);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		r = sc_pkcs15init_create_file(profile, p15card, keyfile);
		if (r >= 0)
			r = sc_select_file (p15card->card, &keyfile->path, &found);
	}

	if (r >= 0)
		r = sc_pkcs15init_authenticate (profile, p15card, keyfile, SC_AC_OP_UPDATE);

done:
	if (found)
		sc_file_free (found);

	if (keyfile)
		sc_file_free(keyfile);
	return r;
}

static int
clear_mse (sc_card_t *card)
{
	const u8 id[2] = { 0x3f, 0xff };
	sc_apdu_t apdu;
	int r;

	sc_format_apdu (card, &apdu, SC_APDU_CASE_3_SHORT, 0xa4, 0, 0);
	apdu.lc = sizeof (id);
	apdu.datalen = sizeof (id);
	apdu.data = id;
	r = sc_transmit_apdu (card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");	
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	return (0);
}
	
static int
set_dst (sc_card_t *card, sc_pkcs15_id_t *id, int qual_byte)
{
	int dlen;
	u8 data[1000]; /* XXX */
	sc_apdu_t apdu;
	int i;
	int r;

	dlen = 0;

	/* select algo (sect 4.2.1) */
	data[dlen++] = 0x80;
	data[dlen++] = 0x01;
	data[dlen++] = 0x10;

	data[dlen++] = 0x81;
	data[dlen++] = id->len;
	for (i = 0; i < id->len; i++)
		data[dlen++] = id->value[i];

	data[dlen++] = 0x85;
	data[dlen++] = 0x01;
	data[dlen++] = qual_byte;

	sc_format_apdu (card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x01, 0xb6);
	apdu.lc = dlen;
	apdu.datalen = dlen;
	apdu.data = data;
	r = sc_transmit_apdu (card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");	
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	return (0);
}

#define ACOS5_TMP_PUBKEY 0x9ace

static int
acos5_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, 
		struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	int r;
	int dlen;
	u8 data[50];
	sc_apdu_t apdu;
	
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	/* Check that the card supports the requested modulus length */
	if (sc_card_find_rsa_alg(p15card->card, key_info->modulus_length) == NULL)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS, "Unsupported key size");

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "store key with ID:%s and path:%s", 
			sc_pkcs15_print_id(&key_info->id), sc_print_path(&key_info->path));


	acos5_tmp_pubkey_id.len = 2;
	acos5_tmp_pubkey_id.value[0] = (ACOS5_TMP_PUBKEY >> 8) & 0xff;
	acos5_tmp_pubkey_id.value[1] = ACOS5_TMP_PUBKEY & 0xff;


	file = sc_file_new ();
	file->path.len = p15card->app->path.len;
	memcpy (file->path.value, p15card->app->path.value, 
		p15card->app->path.len);
	sc_append_file_id (&file->path, ACOS5_TMP_PUBKEY);
	file->type = SC_FILE_TYPE_INTERNAL_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->id = ACOS5_TMP_PUBKEY;
	file->size = 0x200;
	file->status = SC_FILE_STATUS_CREATION;
	r = sc_create_file(card, file);
	if (r < 0 && r != SC_ERROR_FILE_ALREADY_EXISTS) 
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "can't make temporary pubkey file");
	sc_file_free (file);


	r = sc_select_file(card, &key_info->path, &file);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "Cannot store key: select key file failed");
	
	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_GENERATE);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "No authorisation to generate private key");

	r = clear_mse (card);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "can't clear_mse");	

	r = set_dst (card, &key_info->id, 0x40);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "can't set_dst for priv key");

	r = set_dst (card, &acos5_tmp_pubkey_id, 0x80);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "can't set_dst for pub key");

	dlen = 0;
	data[dlen++] = key_info->modulus_length / 128;

	unsigned int val = ACOS5_EXPONENT, i;
	for (i = 0; i < 8; i++) {
		data[dlen++] = val;
		val >>= 8;
	}

	sc_format_apdu (card, &apdu, SC_APDU_CASE_3_SHORT, 0x46, 0x80, 0x00);
	apdu.lc = dlen;
	apdu.datalen = dlen;
	apdu.data = data;
	r = sc_transmit_apdu (card, &apdu);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "generate key failed");
	

	if (file) 
		sc_file_free(file);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, r);
}


static int acos5_do_authenticate(sc_profile_t *profile, sc_pkcs15_card_t *p15card, 
	const sc_path_t *path, int op)
{
	int r;
	sc_file_t *prkey = NULL;
	r = sc_profile_get_file_by_path(profile, path, &prkey);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to find file in profile");
		return r;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, prkey, op);
	sc_file_free(prkey);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to authenticate");
		return r;
	}
	return SC_SUCCESS;	
}

static int acos5_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;
	int       r;
	sc_cardctl_acos5_store_key_t	skdata;
	struct sc_pkcs15_prkey_rsa *rsakey;

	/* authenticate if necessary */
	if (obj->auth_id.len != 0) {
		r = acos5_do_authenticate(profile, p15card, &kinfo->path, SC_AC_OP_UPDATE);
		if (r != SC_SUCCESS) 
			return r;
	}

	/* select the rsa private key */
	r = sc_select_file(p15card->card, &kinfo->path, NULL);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to select rsa key file");
		return r;
	}

	memset (&skdata, 0, sizeof skdata);
	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "only RSA is currently supported");
		return SC_ERROR_NOT_SUPPORTED;
	}
	rsakey = &key->u.rsa;

	skdata.key_type = 1;
	skdata.modulus = rsakey->modulus.data;
	skdata.modulus_len = rsakey->modulus.len;
	skdata.d = rsakey->d.data;
	skdata.d_len = rsakey->d.len;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_ACOS5_STORE_KEY, &skdata);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to store key data");
		return r;
	}
	
	return SC_SUCCESS;
}

static struct sc_pkcs15init_operations sc_pkcs15init_acos5_operations = {
	NULL, /* erase_card */
	acos5_init_card, /* init_card */
	acos5_create_dir, /* create_dir (required) */
	NULL, /* create_domain */
	NULL, /* select_pin_reference */
	acos5_create_pin, /* create_pin (required) */
	NULL, /* select_key_reference */
	acos5_create_key, /* create_key */
	acos5_store_key, /* store_key */
	acos5_generate_key, /* generate_key */
	NULL, /* encode_private_key */
	NULL, /* encode_public_key */
	NULL, /* finalize_card */
	NULL, /* delete_object */
	NULL, /* emu_update_dir */
	NULL, /* emu_update_any_df */
	NULL, /* emu_update_tokeninfo */
	NULL, /* emu_write_info */
	NULL, /* emu_store_data */
	NULL, /* sanity_check */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_acos5_ops(void)
{
	return &sc_pkcs15init_acos5_operations;
}
