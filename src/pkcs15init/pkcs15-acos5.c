/*
 * acos5 specific operations for PKCS15 initialization
 *
 * Copyright (c) 2011 Pace Willisson <pace@alum.mit.edu>
 * and includes elements from many of the
 * OpenSC/pkcs15init/pkcs15-*.c examples
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

/*
 * the manual section numbers refer to 
 * the ACOS5_Reference_Manual.pdf version 1.9
 * which comes on the CDROM in the ACOS5 Software Development Kit
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

/* manual secction 2.2 */
#define ACOS5_LIFE_CYCLE_FUSE 0x3088

#define CONFMEM_BASE 0x3080
#define CONFMEM_SIZE (0x30d0 - CONFMEM_BASE)

/* to be removed before merge upstream */
static void
acos5_display_confmem(sc_card_t *card)
{
	struct sc_context *ctx = card->ctx;
	sc_apdu_t apdu;
	int i;
	u8 confmem[CONFMEM_SIZE];
	int r;

	/* display current config memory */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
		       0xb0, /* read binary */
		       (CONFMEM_BASE >> 8) & 0xff,
		       CONFMEM_BASE & 0xff);
	memset(confmem, 0x55, sizeof confmem);
	apdu.resp = confmem;
	apdu.resplen = sizeof confmem;
	apdu.le = apdu.resplen;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
			 "can't read confmem\n");
		exit(1);
	}

	for (i = 0; i < CONFMEM_SIZE; i++) {
		if (i % 16 == 0)
			printf("\n%04x", CONFMEM_BASE + i);
		else if (i % 8 == 0)
			printf(" ");
		printf(" %02x", confmem[i]);
	}
	printf("\n");
}

static int
acos5_read_confmem(sc_card_t *card, int offset, u8 *data, int len)
{
	struct sc_context *ctx = card->ctx;
	sc_apdu_t apdu;
	int i;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
		       0xb0, /* read binary */
		       (offset >> 8) & 0xff,
		       offset & 0xff);
	memset(data, 0x55, len);
	apdu.resp = data;
	apdu.resplen = len;
	apdu.le = apdu.resplen;
	return sc_transmit_apdu(card, &apdu);
}

static int
acos5_write_confmem(sc_card_t *card, int offset, u8 *data, int len)
{
	struct sc_context *ctx = card->ctx;
	sc_apdu_t apdu;
	int i;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
		       0xd6, /* update binary */
		       (offset >> 8) & 0xff,
		       offset & 0xff);
	apdu.data = data;
	apdu.datalen = len;
	apdu.lc = len;
	return sc_transmit_apdu(card, &apdu);
}

static u8 init_3080[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x37, 0xe0,
};

static void
acos5_finish_clear(struct sc_card *card)
{
	acos5_write_confmem(card, 0x3080, init_3080, sizeof init_3080);
}

static int
acos5_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	sc_path_t	path;
	sc_file_t	*file;
	int		r;
	sc_apdu_t apdu;
	u8 data[256];
	int dlen;
	int i;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	/* if MF can be selected, nothing further to do */
	sc_format_path("3F00", &path);
	if (sc_select_file(card, &path, NULL) == 0) {
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
	}

	/* see if User EEPROM Limit is set, if not, fixup the conf block */
	data[0] = 0;
	acos5_read_confmem(card, 0x308c, data, 1);
	if (data[0] != 0xff)
		acos5_finish_clear(card);

	/* clear the flag that prevents future erases (manual sect 2.2) */
	dlen = 0;
	data[dlen++] = 0;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
		       0xd6,
		       (ACOS5_LIFE_CYCLE_FUSE >> 8) & 0xff,
		       ACOS5_LIFE_CYCLE_FUSE & 0xff);
	apdu.data = data;
	apdu.datalen = dlen;
	apdu.lc = dlen;
	r = sc_transmit_apdu(card, &apdu);
	if (r == 0) {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
			 "card erasing enabled\n");
	} else {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
			 "card may not be erasable in the future\n");
	}

	/* create MF by hand: see manual section 7.0 */
	dlen = 0;
	data[dlen++] = 0x62;
	data[dlen++] = 0x00; /* will patch length at end */
	data[dlen++] = 0x82;
	data[dlen++] = 0x02;
	data[dlen++] = 0x3f;
	data[dlen++] = 0xff;
	data[dlen++] = 0x83;
	data[dlen++] = 0x02;
	data[dlen++] = 0x3f;
	data[dlen++] = 0x00;
	data[1] = dlen - 2;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
		       0xe0, 0, 0);
	apdu.data = data;
	apdu.datalen = dlen;
	apdu.lc = dlen;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_VERBOSE, r, "Cannot create MF");

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

/*
 * TODO: convert uses of ACOS5_MAIN_SE_FILE to 
 * sc_profile_get_file(..,"sefile",..) 
 */
#define ACOS5_MAIN_SE_FILE 0x6004

/*
 * Initialize the Application DF (the 5015 directory)
 */
static int 
acos5_create_dir(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		 struct sc_file *df)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	int r;
	u8 sec_attr[100], *p;
	int sec_attr_len;
	u8 type_attr[100];
	int type_attr_len;
	int dlen;
	u8 data[256];
	sc_apdu_t apdu;
	sc_file_t *sefile;

	/* the argument "df" describes the appdir we need to create */

	/* add SE file ID field */
	p = sec_attr;
	*p++ = 0x8d;
	*p++ = 2;
	*p++ = (ACOS5_MAIN_SE_FILE >> 8) & 0xff;
	*p++ = ACOS5_MAIN_SE_FILE & 0xff;
	/* may need to add Security Attributes Compact here too */
	sec_attr_len = p - sec_attr;
	sc_file_set_sec_attr(df, sec_attr,  sec_attr_len);

	r = sc_create_file(card, df);
	if (r == SC_ERROR_FILE_ALREADY_EXISTS)
		r = 0;
	LOG_TEST_RET(ctx, r, "can't create appdir");
	
	r = sc_select_file(card, &df->path, NULL);
	LOG_TEST_RET(ctx, r, "can't select appdir");

	/* now create the SE file within the appdir */
	r = sc_profile_get_file(profile, "sefile", &sefile);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "Cannot get sefile from profile");

	p = type_attr;
	/* create file parameters: see section 5.1 */
	*p++ = 0x82;
	*p++ = 0x05;
	*p++ = 0x0c; /* fdb: linear variable EF */
	*p++ = 0x01; /* dcb: unused in acos5 */
	*p++ = 0x00; /* must be 0 */
	*p++ = 0x11; /* mrl: max record len */
	*p++ = 0x04; /* nor: number of records */

	/* Security Attributes Compact */
	*p++ = 0x8c; /* allow everything for now */
	*p++ = 0x08;
	*p++ = 0x7f;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;

	type_attr_len = p - type_attr;
	sc_file_set_type_attr(sefile, type_attr, type_attr_len);
	
	r = sc_create_file(card, sefile);
	if (r == SC_ERROR_FILE_ALREADY_EXISTS)
		r = 0;
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "sefile creation failed");

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

static int
acos5_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		 sc_file_t *df, sc_pkcs15_object_t *pin_obj,
		 const u8 *pin, size_t pin_len, const u8 *puk, size_t puk_len)
{
	/* df is for the appdir */
	/* ideas from pkcs15-setcos.c */

	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	sc_pkcs15_auth_info_t *auth_info
		= (sc_pkcs15_auth_info_t *) pin_obj->data;
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

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	r = sc_profile_get_file(profile, "pinfile", &pinfile);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "Cannot get pinfile from profile");

	r = sc_select_file(card, &pinfile->path, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "creating pinfile");
		
		p = type_attr;
		*p++ = 0x82;
		*p++ = 0x05;
		*p++ = 0x0c; /* fdb: linear variable EF */
		*p++ = 0x01; /* dcb: unused in acos5 */
		*p++ = 0x00; /* must be 0 */
		*p++ = 18;   /* mrl: max record len */
		*p++ = 4;    /* nor: number of records */

		*p++ = 0x88; /* set sfi to 1 */
		*p++ = 0x01;
		*p++ = 0x01; 
	
		type_attr_len = p - type_attr;
		sc_file_set_type_attr(pinfile, type_attr, type_attr_len);
	
		r = sc_create_file(card, pinfile);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r,
			    "pinfile creation failed");

		r = sc_select_file(card, &pinfile->path, NULL);
	}
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "select pinfile failed");

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
		 "pinfile->status:%X", pinfile->status);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
		 "create PIN with reference:%X, flags:%X, path:%s",
		 auth_info->attrs.pin.reference,
		 auth_info->attrs.pin.flags,
		 sc_print_path(&auth_info->path));

	if (pin_len < 1 || pin_len > 16) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "invalid pin length");
		return SC_ERROR_INTERNAL;
	}

	refnum = auth_info->attrs.pin.reference;
	if (refnum < 1 || refnum > 4) {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
			 "pin reference num must be 1..4; got %d", refnum);
		return SC_ERROR_INTERNAL;
	}

	/* manual section 3.1.1 PIN Data Structure */
	dlen = 0;
	data[dlen++] = 0x80 | refnum;
	data[dlen++] = 0xff; /* don't use pin fail counter for now */
	for (i = 0; i < pin_len; i++)
		data[dlen++] = pin[i];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xdc, refnum, 4);
	apdu.lc = dlen;
	apdu.datalen = dlen;
	apdu.data = data;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");	
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	
	sc_file_free(pinfile); /* XXX leaked on error returns above */

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

static int
acos5_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		 sc_pkcs15_object_t *obj)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	struct sc_file	*keyfile = NULL;
	size_t		bytes, mod_len, exp_len, prv_len, pub_len;
	int		r, algo;
	struct sc_file *found = NULL;
	u8 sec_attr[100], *p;
	int sec_attr_len;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	/* The caller is supposed to have chosen a key file path for us */
	if (key_info->path.len == 0 || key_info->modulus_length == 0) {
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL,
			       SC_ERROR_INVALID_ARGUMENTS);
	}

	/* Get the file we're supposed to create */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &keyfile);
	if (r < 0) {
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, r);
	}

	/* 
	 * private key files have a 5 byte header, then 
	 * 5 CRT parts, each 1/2 of the modulus size
	 */
	keyfile->size = 5 + 5 * (key_info->modulus_length / 8 / 2);

	if ((r = sc_pkcs15init_fixup_file(profile, p15card, keyfile)) < 0)
		goto done;

	r = sc_select_file(card, &keyfile->path, &found);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		/*
		 * TODO: remove this block because sefile
		 * is now created in acos5_create_dir
		 */
		p = sec_attr;
		*p++ = 0x8d;
		*p++ = 2;
		*p++ = (ACOS5_MAIN_SE_FILE >> 8) & 0xff;
		*p++ = ACOS5_MAIN_SE_FILE & 0xff;
		sec_attr_len = p - sec_attr;
		sc_file_set_sec_attr(keyfile, sec_attr,  sec_attr_len);

		r = sc_pkcs15init_create_file(profile, p15card, keyfile);
		if (r >= 0)
			r = sc_select_file(card, &keyfile->path, &found);
	}

	if (r >= 0)
		r = sc_pkcs15init_authenticate(profile, p15card, keyfile,
					       SC_AC_OP_UPDATE);

done:
	if (found)
		sc_file_free(found);

	if (keyfile)
		sc_file_free(keyfile);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, r);
}

/* set the Digital Signature Template, sect 4.2.6 */
static int
acos5_set_dst(sc_card_t *card, int file_id, int qual_byte)
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
	data[dlen++] = 2;
	data[dlen++] = (file_id >> 8) & 0xff;
	data[dlen++] = file_id & 0xff;

	data[dlen++] = 0x95;
	data[dlen++] = 0x01;
	data[dlen++] = qual_byte;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x01, 0xb6);
	apdu.lc = dlen;
	apdu.datalen = dlen;
	apdu.data = data;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");	
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	return 0;
}

static int
acos5_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		   struct sc_pkcs15_object *object, 
		   struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info
		= (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *prkey_file = NULL, *pukey_file = NULL;
	int r;
	int dlen;
	u8 data[50];
	sc_apdu_t apdu;
	sc_path_t *prkey_path, *pukey_path;
	int len;
	u8 sec_attr[100], *p;
	int sec_attr_len;
	int pukey_raw_size;
	u8 pukey_raw[5 + 8 + 2048 / 8];
	u8 *exponent_raw, exponent[8];
	u8 modulus[256]; /* up to 2048 bit keys */

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	/* Check that the card supports the requested modulus length */
	if (sc_card_find_rsa_alg(card, key_info->modulus_length) == NULL) {
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL,
			    SC_ERROR_INVALID_ARGUMENTS, "Unsupported key size");
	}

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "store key with ID:%s and path:%s", 
		 sc_pkcs15_print_id(&key_info->id),
		 sc_print_path(&key_info->path));

	/* extract the file_id from the given private key file */
	prkey_path = &key_info->path;
	len = prkey_path->len;

	/* make public key path, copying low byte of file id from private key */
	r = sc_select_file(card, &key_info->path, &prkey_file);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r,
		    "Cannot store key: select key file failed");
	
	if (sc_profile_get_file(profile,
				"template-hw-public-key", &pukey_file) < 0) {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
			 "template-hw-public-key missing from profile");
		SC_FUNC_RETURN (ctx, SC_LOG_DEBUG_VERBOSE, 
				SC_ERROR_NOT_SUPPORTED);
	}

	pukey_path = &pukey_file->path;
	len = pukey_path->len;
	pukey_path->value[len - 1] = prkey_file->id & 0xff;
	pukey_file->id = (pukey_path->value[len - 2] << 8)
		| pukey_path->value[len - 1];
	
	/* make the public key file */
	pukey_raw_size = 5 + 8 + key_info->modulus_length / 8;
	pukey_file->size = pukey_raw_size;

	p = sec_attr;
	*p++ = 0x8d;
	*p++ = 2;
	*p++ = (ACOS5_MAIN_SE_FILE >> 8) & 0xff;
	*p++ = ACOS5_MAIN_SE_FILE & 0xff;
	sec_attr_len = p - sec_attr;
	sc_file_set_sec_attr(pukey_file, sec_attr,  sec_attr_len);

	r = sc_create_file(card, pukey_file);
	if (r < 0 && r != SC_ERROR_FILE_ALREADY_EXISTS) 
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "can't make pubkey file");

	/* now set up for telling the card to generate the new key pair */
	r = sc_pkcs15init_authenticate(profile, p15card, prkey_file,
				       SC_AC_OP_GENERATE);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r,
		    "No authorisation to generate private key");

	/* dst means Digital Signature Template */
	r = acos5_set_dst(card, prkey_file->id, 0x40);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "can't set_dst for priv key");

	r = acos5_set_dst(card, pukey_file->id, 0x80);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "can't set_dst for pub key");

	dlen = 0;
	data[dlen++] = key_info->modulus_length / 8 / 16;

	/* this will make a type 0x7 key (private w/CRT, capable of decipher) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x46, 0x80, 0x00);
	apdu.lc = dlen;
	apdu.datalen = dlen;
	apdu.data = data;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "transmit error");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "generate key failed");

	/* now read out and return the new public key */
	r = sc_select_file(card, pukey_path, NULL);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r,
		    "error selecting new public key");

	if (pukey_raw_size > sizeof pukey_raw)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);

	len = sc_read_binary(card, 0, pukey_raw, pukey_raw_size, 0);
	if (len != pukey_raw_size) {
		sc_debug (ctx, SC_LOG_DEBUG_NORMAL,
			  "error reading raw public key");
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	
	pubkey->algorithm = SC_ALGORITHM_RSA;

	/*
	 * data is 5 bytes header, 8 bytes exponent (little endian), modulus
	 * first 8 bytes of pubkey_raw are little endian exponent
	 */

	/* first, find the most significant non-zero byte */
	exponent_raw = pukey_raw + 5;
	for (len = 8; len >= 1; len--) {
		if (exponent_raw[len - 1])
			break;
	}
	if ((p = malloc (len)) == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy (p, exponent_raw, len);
	sc_mem_reverse (p, len);
	pubkey->u.rsa.exponent.len = len;
	pubkey->u.rsa.exponent.data = p;

	len = key_info->modulus_length / 8;
	if ((p = malloc (len)) == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy (p, pukey_raw + 5 + 8, len);
	sc_mem_reverse (p, len);
	pubkey->u.rsa.modulus.len = len;
	pubkey->u.rsa.modulus.data = p;

	/*
	 * the memory allocated for the exponent and modulus will be
	 * freed in sc_pkcs15_erase_pubkey()
	 */

	sc_file_free(prkey_file);
	sc_file_free(pukey_file);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, 0);
}


static int
acos5_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;
	int       r;
	sc_cardctl_acos5_store_key_t	skdata;
	struct sc_pkcs15_prkey_rsa *rsakey;
	sc_path_t *pukey_path;
	int len;
	struct sc_path *prkey_path;
	struct sc_file *prkey_file, *pukey_file;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "only RSA is supported");
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, 
			       SC_ERROR_NOT_SUPPORTED);
	}
	rsakey = &key->u.rsa;

	/* select the rsa private key */
	prkey_path = &kinfo->path;
	r = sc_select_file(card, prkey_path, &prkey_file);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r,
		    "unable to select rsa key file");

	/* make public key path, copying low byte of file id from private key */
	r = sc_profile_get_file(profile, "template-hw-public-key",
				&pukey_file);
	if (r < 0) {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
			 "template-hw-public-key missing from profile");
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE,
			       SC_ERROR_NOT_SUPPORTED);
	}
	pukey_path = &pukey_file->path;
	len = pukey_path->len;
	pukey_path->value[len - 1] = prkey_file->id & 0xff;
	pukey_file->id = (pukey_path->value[len - 2] << 8)
		| pukey_path->value[len - 1];

	memset(&skdata, 0, sizeof skdata);
	skdata.prkey_file_id = prkey_file->id;
	skdata.prkey_path = prkey_path;
	skdata.pukey_file = pukey_file;
	skdata.se_file_id = ACOS5_MAIN_SE_FILE;
	skdata.modulus = rsakey->modulus.data;
	skdata.modulus_len = rsakey->modulus.len;
	skdata.exponent = rsakey->exponent.data;
	skdata.exponent_len = rsakey->exponent.len;
	skdata.d = rsakey->d.data;
	skdata.d_len = rsakey->d.len;
	skdata.p = rsakey->p.data;
	skdata.p_len = rsakey->p.len;
	skdata.q = rsakey->q.data;
	skdata.q_len = rsakey->q.len;
	skdata.iqmp = rsakey->iqmp.data;
	skdata.iqmp_len = rsakey->iqmp.len;
	skdata.dmp1 = rsakey->dmp1.data;
	skdata.dmp1_len = rsakey->dmp1.len;
	skdata.dmq1 = rsakey->dmq1.data;
	skdata.dmq1_len = rsakey->dmq1.len;

	r = sc_card_ctl(card, SC_CARDCTL_ACOS5_STORE_KEY, &skdata);
	SC_TEST_RET (ctx, SC_LOG_DEBUG_NORMAL, r, "unable to store key data");
	
	sc_file_free(prkey_file);
	sc_file_free(pukey_file);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

static int 
acos5_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	int		r;
	sc_apdu_t apdu;
	
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xca, 0xff, 0);
	apdu.cla |= 0x80;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		printf("clear card failed\n");
		exit(1);
	}

	/*
	 * should do acos5_finish_clear(card) here, but 
	 * it appears the card needs to be reset first.  so,
	 * I put it in acos5_init_card, so it will be
	 * run when the user next runs pkcs15-init -C
	 *
	 * TODO: is there a way to reset the card here?
	 */

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}


static struct sc_pkcs15init_operations sc_pkcs15init_acos5_operations = {
	acos5_erase_card, /* erase_card */
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
