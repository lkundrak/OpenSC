include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = Makefile.mak 

lib_LTLIBRARIES = libopensc.la
noinst_HEADERS = cards.h ctbcs.h internal.h esteid.h muscle.h muscle-filesystem.h \
	internal-winscard.h p15card-helper.h \
	opensc.h pkcs15.h \
	cardctl.h asn1.h log.h \
	errors.h types.h compression.h itacns.h iso7816.h \
	authentic.h iasecc.h iasecc-sdo.h

AM_CPPFLAGS = -DOPENSC_CONF_PATH=\"$(sysconfdir)/opensc.conf\"
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_OPENCT_CFLAGS) \
	$(OPTIONAL_PCSC_CFLAGS) $(OPTIONAL_ZLIB_CFLAGS) \
	$(LTLIB_CFLAGS)
INCLUDES = -I$(top_srcdir)/src

libopensc_la_SOURCES = \
	sc.c ctx.c log.c errors.c \
	asn1.c base64.c sec.c card.c iso7816.c dir.c ef-atr.c padding.c apdu.c \
	\
	pkcs15.c pkcs15-cert.c pkcs15-data.c pkcs15-pin.c \
	pkcs15-prkey.c pkcs15-pubkey.c pkcs15-sec.c \
	pkcs15-algo.c pkcs15-cache.c pkcs15-syn.c \
	\
	muscle.c muscle-filesystem.c \
	\
	ctbcs.c reader-ctapi.c reader-pcsc.c reader-openct.c \
	\
	card-setcos.c card-miocos.c card-flex.c card-gpk.c \
	card-cardos.c card-tcos.c card-default.c \
	card-mcrd.c card-starcos.c card-openpgp.c card-jcop.c \
	card-oberthur.c card-belpic.c card-atrust-acos.c card-entersafe.c \
	card-incrypto34.c card-piv.c card-muscle.c card-acos5.c \
	card-asepcos.c card-akis.c card-gemsafeV1.c card-rutoken.c \
	card-rtecp.c card-westcos.c card-myeid.c card-ias.c \
	card-javacard.c card-itacns.c card-authentic.c \
	card-iasecc.c iasecc-sdo.c \
	\
	pkcs15-openpgp.c pkcs15-infocamere.c pkcs15-starcert.c \
	pkcs15-tcos.c pkcs15-esteid.c pkcs15-postecert.c pkcs15-gemsafeGPK.c \
	pkcs15-actalis.c pkcs15-atrust-acos.c pkcs15-tccardos.c pkcs15-piv.c \
	pkcs15-esinit.c pkcs15-westcos.c pkcs15-pteid.c pkcs15-oberthur.c \
	pkcs15-itacns.c pkcs15-gemsafeV1.c \
	compression.c p15card-helper.c \
	libopensc.exports
if WIN32
libopensc_la_SOURCES += $(top_builddir)/win32/versioninfo.rc
endif
libopensc_la_LIBADD = $(OPTIONAL_OPENSSL_LIBS) $(OPTIONAL_OPENCT_LIBS) \
	$(OPTIONAL_ZLIB_LIBS) $(LTLIB_LIBS) \
	$(top_builddir)/src/pkcs15init/libpkcs15init.la \
	$(top_builddir)/src/scconf/libscconf.la \
	$(top_builddir)/src/common/libcompat.la
if WIN32
libopensc_la_LIBADD += -lws2_32
endif
libopensc_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@ \
	-export-symbols "$(srcdir)/libopensc.exports" \
	-no-undefined

if WIN32
# def file required for MS users to build library
mylibdir=$(libdir)
mylib_DATA=.libs/@WIN_LIBPREFIX@opensc-@OPENSC_LT_OLDEST@.dll.def
.libs/@WIN_LIBPREFIX@opensc-@OPENSC_LT_OLDEST@.dll.def:	libopensc.la
endif
