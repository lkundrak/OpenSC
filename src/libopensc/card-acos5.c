/*
 * card-acos5.c: Support for ACS ACOS5 cards.
 *
 * Copyright (C) 2007  Ian A. Young<ian@iay.org.uk>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "internal.h"
#include "cardctl.h"

static struct sc_atr_table acos5_atrs[] = {
	{"3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00", NULL, NULL,
	SC_CARD_TYPE_ACOS5_GENERIC, 0, NULL},
	{"3b:be:18:00:00:41:05:10:00:00:00:00:00:00:00:00:00:90:00", NULL, NULL,
	 SC_CARD_TYPE_ACOS5_GENERIC, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations acos5_ops;
static struct sc_card_driver acos5_drv = {
	"ACS ACOS5 card",
	"acos5",
	&acos5_ops,
	NULL, 0, NULL
};

static int acos5_match_card(sc_card_t * card)
{
	int i;

	i = _sc_match_atr(card, acos5_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int acos5_init(sc_card_t * card)
{
	unsigned long	flags;

	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN;
	flags |= SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_HASH_SHA1;

	_sc_card_add_rsa_alg(card, 512, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);

	card->caps |= SC_CARD_CAP_USE_FCI_AC;
	card->max_recv_size = 128;
	card->max_send_size = 128;
	return SC_SUCCESS;
}

static int acos5_select_file_by_path(sc_card_t * card,
				     const sc_path_t * in_path,
				     sc_file_t ** file_out)
{
	int in_len = in_path->len;
	const u8 *in_pos = in_path->value;
	sc_path_t path;

	memset(&path, 0, sizeof(sc_path_t));
	path.len = 2;		/* one component at a time */
	path.type = SC_PATH_TYPE_FILE_ID;

	/*
	 * Check parameters.
	 */
	if (in_len % 2 != 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	/*
	 * File ID by file ID...
	 */
	while (in_len) {
		int result;
		memcpy(path.value, in_pos, 2);
		result = iso_ops->select_file(card, &path, file_out);
		if (result != SC_SUCCESS)
			return result;
		in_len -= 2;
		in_pos += 2;
	}
	return SC_SUCCESS;
}

static int acos5_select_file(sc_card_t * card,
			     const sc_path_t * in_path, sc_file_t ** file_out)
{
	switch (in_path->type) {

	case SC_PATH_TYPE_PATH:
		return acos5_select_file_by_path(card, in_path, file_out);

	default:
		return iso_ops->select_file(card, in_path, file_out);
	}
}

static int acos5_get_serialnr(sc_card_t * card, sc_serial_number_t * serial)
{
	int r;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

	/*
	 * Check arguments.
	 */
	if (!serial)
		return SC_ERROR_INVALID_ARGUMENTS;

	/*
	 * Return a cached serial number, if we have one.
	 */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		return SC_SUCCESS;
	}

	/*
	 * Fetch serial number using GET CARD INFO.
	 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x14, 0, 0);
	apdu.cla |= 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 6;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;

	/*
	 * Cache serial number.
	 */
	memcpy(card->serialnr.value, apdu.resp, MIN(apdu.resplen, SC_MAX_SERIALNR));
	card->serialnr.len = MIN(apdu.resplen, SC_MAX_SERIALNR);

	/*
	 * Copy and return serial number.
	 */
	memcpy(serial, &card->serialnr, sizeof(*serial));
	return SC_SUCCESS;
}

int
acos_store_key (sc_card_t *card, sc_cardctl_acos5_store_key_info_t *stkey)
{
	struct sc_pkcs15_prkey_rsa *prkey;

	prkey = stkey->prkey_rsa;

	dlen = 0;
	data[dlen++] = stkey->key_type;
	data[dlen++] = prkey->modulus.len / 16;
	data[dlen++] = (stkey->other_key_file_id >> 8) & 0xff;
	data[dlen++] = stkey->other_key_file_id & 0xff;
}

static int acos5_card_ctl(sc_card_t * card, unsigned long cmd, void *ptr)
{
	switch (cmd) {

	case SC_CARDCTL_GET_SERIALNR:
		return acos5_get_serialnr(card, (sc_serial_number_t *) ptr);

	case SC_CARDCTL_LIFECYCLE_SET:
		return (0);

	case SC_CARDCTL_ACOS5_STORE_KEY:
		return acos5_store_key (card, (sc_cardctl_acos5_store_key_info_t *)ptr);

	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}

static int acos5_list_files(sc_card_t * card, u8 * buf, size_t buflen)
{
	sc_apdu_t apdu;
	int r;
	size_t count;
	u8 *bufp = buf;		/* pointer into buf */
	int fno = 0;		/* current file index */

	/*
	 * Check parameters.
	 */
	if (!buf || (buflen & 1))
		return SC_ERROR_INVALID_ARGUMENTS;

	/*
	 * Use CARD GET INFO to fetch the number of files under the
	 * curently selected DF.
	 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x14, 0x01, 0x00);
	apdu.cla |= 0x80;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90)
		return SC_ERROR_INTERNAL;
	count = apdu.sw2;

	while (count--) {
		u8 info[8];

		/*
		 * Truncate the scan if no more room left in output buffer.
		 */
		if (buflen == 0)
			break;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x14, 0x02,
			       fno++);
		apdu.cla |= 0x80;
		apdu.resp = info;
		apdu.resplen = sizeof(info);
		apdu.le = sizeof(info);
		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			return SC_ERROR_INTERNAL;

		*bufp++ = info[2];
		*bufp++ = info[3];
		buflen -= 2;
	}

	return (bufp - buf);
}


static int acos5_construct_fci(sc_card_t *card, const sc_file_t *file,
	u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];

	if (*outlen < 2)
		return SC_ERROR_BUFFER_TOO_SMALL;
	*p++ = 0x62;
	p++;
	
	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x80, buf, 2, p, *outlen - (p - out), &p);

	if (file->type_attr_len) {
		if ((p - out) + file->type_attr_len > *outlen)
			return (SC_ERROR_BUFFER_TOO_SMALL);
		memcpy (p, file->type_attr, file->type_attr_len);
		p += file->type_attr_len;
	} else {
		/* file->shareable ? */
		buf[0] = 0;
		switch (file->type) {
		case SC_FILE_TYPE_INTERNAL_EF:
			buf[0] |= 0x08;
			/* fall in */
		case SC_FILE_TYPE_WORKING_EF:
			buf[0] |= file->ef_structure & 7;
			break;
		case SC_FILE_TYPE_DF:
			buf[0] |= 0x38;
			break;
		default:
			return SC_ERROR_NOT_SUPPORTED;
		}
		sc_asn1_put_tag(0x82, buf, 1, p, *outlen - (p - out), &p);
	}
	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, *outlen - (p - out), &p);

	if (file->prop_attr_len) {
		if ((p - out) + file->prop_attr_len > *outlen)
			return (SC_ERROR_BUFFER_TOO_SMALL);
		memcpy (p, file->prop_attr, file->prop_attr_len);
		p += file->prop_attr_len;
	}
	if (file->sec_attr_len) {
		if ((p - out) + file->sec_attr_len > *outlen)
			return (SC_ERROR_BUFFER_TOO_SMALL);
		memcpy (p, file->sec_attr, file->sec_attr_len);
		p += file->sec_attr_len;
	}

	out[1] = p - out - 2;

	*outlen = p - out;
	return 0;
}

static int acos5_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int r;
	sc_apdu_t apdu;
	sc_file_t	*file;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (path->type != SC_PATH_TYPE_FILE_ID || (path->len != 0 && path->len != 2)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File type has to be SC_PATH_TYPE_FILE_ID");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
	}

	r = sc_select_file(card, path, &file);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "can't select file to delete");
	sc_file_free(file);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int (*iso7816_pin_cmd_orig)(sc_card_t *card,
				    struct sc_pin_cmd_data *data,
				    int *tries_left);

static int acos5_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
			   int *tries_left)
{
	sc_apdu_t apdu;
	struct sc_path path;
	struct sc_pin_cmd_pin *pin;
	int r;
	
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		pin = &data->pin1;
		
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
			       0x20, 0x00, data->pin_reference | 0x80);
		apdu.lc = pin->len;
		apdu.datalen = pin->len;
		apdu.data = pin->data;

		data->apdu = &apdu;
		r = (*iso7816_pin_cmd_orig)(card, data, tries_left);
		break;
	default:
		sc_debug (card->ctx, SC_LOG_DEBUG_NORMAL, "acos5_pin_cmd: can't handle cmd");
		r = SC_ERROR_INTERNAL;
		break;
	}
	return (r);
}


static struct sc_card_driver *sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	/* these default values have names like iso7816_create_file */
	iso_ops = iso_drv->ops;
	acos5_ops = *iso_ops;


	acos5_ops.match_card = acos5_match_card;
	acos5_ops.init = acos5_init;
	// finish
	// read_binary
	// write_binary
	// update_binary
	// erase_binary
	// read_record
	// write_record
	// append_record
	// update_record
	acos5_ops.select_file = acos5_select_file;
	// get_response
	// get_challenge
	// verify
	// logout
	// restore_security_env
	// set_security_env
	// decipher
	// compute_signature
	// change_reference_data
	// reset_retry_counter
	// create_file
	acos5_ops.delete_file = acos5_delete_file;
	acos5_ops.list_files = acos5_list_files;
	// check_sw
	acos5_ops.card_ctl = acos5_card_ctl;
	// process_fci
	acos5_ops.construct_fci = acos5_construct_fci;

	iso7816_pin_cmd_orig = acos5_ops.pin_cmd;
	acos5_ops.pin_cmd = acos5_pin_cmd;
	// get_data
	// put_data
	// delete_record
	return &acos5_drv;
}

struct sc_card_driver *sc_get_acos5_driver(void)
{
	return sc_get_driver();
}
