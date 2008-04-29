#ifndef __INTERNAL_WINSCARD_H
#define __INTERNAL_WINSCARD_H

/* Mostly copied from pcsc-lite, this is the minimum required */

#ifndef _WIN32
#ifndef BYTE
typedef unsigned char BYTE;
#endif
typedef const void *LPCVOID;
typedef void *LPVOID;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef BYTE *LPBYTE;
typedef DWORD *LPDWORD;
typedef char *LPSTR;
#endif
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(_MSC_VER)
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int8 uint8_t;
#else
#warning no uint32_t type available, please contact opensc-devel@opensc-project.org
#endif

#ifndef _MSC_VER
#define MAX_ATR_SIZE			33	/**< Maximum ATR size */

#define SCARD_PROTOCOL_T0		0x0001	/**< T=0 active protocol. */
#define SCARD_PROTOCOL_T1		0x0002	/**< T=1 active protocol. */
#define SCARD_PROTOCOL_RAW		0x0004	/**< Raw active protocol. */

#define SCARD_STATE_UNAWARE		0x0000	/**< App wants status */
#define SCARD_STATE_IGNORE		0x0001	/**< Ignore this reader */
#define SCARD_STATE_CHANGED		0x0002	/**< State has changed */
#define SCARD_STATE_EMPTY		0x0010	/**< Card removed */
#define SCARD_STATE_PRESENT		0x0020	/**< Card inserted */

#define SCARD_SHARE_EXCLUSIVE		0x0001	/**< Exclusive mode only */
#define SCARD_SHARE_SHARED		0x0002	/**< Shared mode only */

#define SCARD_LEAVE_CARD		0x0000	/**< Do nothing on close */
#define SCARD_RESET_CARD		0x0001	/**< Reset on close */
#define SCARD_UNPOWER_CARD		0x0002	/**< Power down on close */

#define SCARD_SCOPE_USER		0x0000	/**< Scope in user space */

#define SCARD_S_SUCCESS			0x00000000 /**< No error was encountered. */
#define SCARD_E_INVALID_HANDLE		0x80100003 /**< The supplied handle was invalid. */
#define SCARD_E_TIMEOUT			0x8010000A /**< The user-specified timeout value has expired. */
#define SCARD_E_SHARING_VIOLATION	0x8010000B /**< The smart card cannot be accessed because of other connections outstanding. */
#define SCARD_E_NOT_TRANSACTED		0x80100016 /**< An attempt was made to end a non-existent transaction. */
#define SCARD_E_READER_UNAVAILABLE	0x80100017 /**< The specified reader is not currently available for use. */
#define SCARD_E_NO_READERS_AVAILABLE    0x8010002E /**< Cannot find a smart card reader. */
#define SCARD_W_UNRESPONSIVE_CARD	0x80100066 /**< The smart card is not responding to a reset. */
#define SCARD_W_UNPOWERED_CARD		0x80100067 /**< Power has been removed from the smart card, so that further communication is not possible. */
#define SCARD_W_RESET_CARD		0x80100068 /**< The smart card has been reset, so any shared state information is invalid. */
#define SCARD_W_REMOVED_CARD		0x80100069 /**< The smart card has been removed, so further communication is not possible. */

#define SCARD_CTL_CODE(code) (0x42000000 + (code))

typedef const BYTE *LPCBYTE;
typedef long SCARDCONTEXT; /**< \p hContext returned by SCardEstablishContext() */
typedef SCARDCONTEXT *PSCARDCONTEXT;
typedef SCARDCONTEXT *LPSCARDCONTEXT;
typedef long SCARDHANDLE; /**< \p hCard returned by SCardConnect() */
typedef SCARDHANDLE *PSCARDHANDLE;
typedef SCARDHANDLE *LPSCARDHANDLE;

typedef struct
{
	const char *szReader;
	void *pvUserData;
	unsigned long dwCurrentState;
	unsigned long dwEventState;
	unsigned long cbAtr;
	unsigned char rgbAtr[MAX_ATR_SIZE];
}
SCARD_READERSTATE_A;

typedef struct _SCARD_IO_REQUEST
{
	unsigned long dwProtocol;	/* Protocol identifier */
	unsigned long cbPciLength;	/* Protocol Control Inf Length */
}
SCARD_IO_REQUEST, *PSCARD_IO_REQUEST, *LPSCARD_IO_REQUEST;

#endif	/* MSC_VER */

#if defined(_WIN32)
#define PCSC_API WINAPI
#elif defined(USE_CYGWIN)
#define PCSC_API __stdcall
#else
#define PCSC_API
#endif

typedef const SCARD_IO_REQUEST *LPCSCARD_IO_REQUEST;
typedef SCARD_READERSTATE_A SCARD_READERSTATE, *PSCARD_READERSTATE_A,
	*LPSCARD_READERSTATE_A;

typedef LONG (PCSC_API *SCardEstablishContext_t)(DWORD dwScope, LPCVOID pvReserved1,
	LPCVOID pvReserved2, LPSCARDCONTEXT phContext);
typedef LONG (PCSC_API *SCardReleaseContext_t)(SCARDCONTEXT hContext);
typedef LONG (PCSC_API *SCardConnect_t)(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
	DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);
typedef LONG (PCSC_API *SCardReconnect_t)(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols,
	DWORD dwInitialization, LPDWORD pdwActiveProtocol);
typedef LONG (PCSC_API *SCardDisconnect_t)(SCARDHANDLE hCard, DWORD dwDisposition);
typedef LONG (PCSC_API *SCardBeginTransaction_t)(SCARDHANDLE hCard);
typedef LONG (PCSC_API *SCardEndTransaction_t)(SCARDHANDLE hCard, DWORD dwDisposition);
typedef LONG (PCSC_API *SCardStatus_t)(SCARDHANDLE hCard, LPSTR mszReaderNames, LPDWORD pcchReaderLen,
	LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen);
typedef LONG (PCSC_API *SCardGetStatusChange_t)(SCARDCONTEXT hContext, DWORD dwTimeout,
	LPSCARD_READERSTATE_A rgReaderStates, DWORD cReaders);
typedef LONG (PCSC_API *SCardControlOLD_t)(SCARDHANDLE hCard, LPCVOID pbSendBuffer, DWORD cbSendLength,
	LPVOID pbRecvBuffer, LPDWORD lpBytesReturned);
typedef LONG (PCSC_API *SCardControl_t)(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer,
	DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength,
	LPDWORD lpBytesReturned);
typedef LONG (PCSC_API *SCardTransmit_t)(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,
	LPCBYTE pbSendBuffer, DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci,
	LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);
typedef LONG (PCSC_API *SCardListReaders_t)(SCARDCONTEXT hContext, LPCSTR mszGroups,
	LPSTR mszReaders, LPDWORD pcchReaders);

/* Copied from pcsc-lite reader.h */

/**
 * TeleTrust Class 2 reader tags
 */
#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)

#define FEATURE_VERIFY_PIN_START  0x01 /**< OMNIKEY Proposal */
#define FEATURE_VERIFY_PIN_FINISH 0x02 /**< OMNIKEY Proposal */
#define FEATURE_MODIFY_PIN_START  0x03 /**< OMNIKEY Proposal */
#define FEATURE_MODIFY_PIN_FINISH 0x04 /**< OMNIKEY Proposal */
#define FEATURE_GET_KEY_PRESSED   0x05 /**< OMNIKEY Proposal */
#define FEATURE_VERIFY_PIN_DIRECT 0x06 /**< USB CCID PIN Verify */
#define FEATURE_MODIFY_PIN_DIRECT 0x07 /**< USB CCID PIN Modify */
#define FEATURE_MCT_READERDIRECT  0x08 /**< KOBIL Proposal */
#define FEATURE_MCT_UNIVERSAL     0x09 /**< KOBIL Proposal */
#define FEATURE_IFD_PIN_PROP      0x0A /**< Gemplus Proposal */
#define FEATURE_ABORT             0x0B /**< SCM Proposal */

/* structures used (but not defined) in PCSC Part 10 revision 2.01.02:
 * "IFDs with Secure Pin Entry Capabilities" */

/* Set structure elements aligment on bytes
 * http://gcc.gnu.org/onlinedocs/gcc/Structure_002dPacking-Pragmas.html */
#ifdef __APPLE__
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/** the structure must be 6-bytes long */
typedef struct
{
	uint8_t tag;
	uint8_t length;
	uint32_t value;	/**< This value is always in BIG ENDIAN format as documented in PCSC v2 part 10 ch 2.2 page 2. You can use ntohl() for example */
} PCSC_TLV_STRUCTURE;

/** the wLangId and wPINMaxExtraDigit are 16-bits long so are subject to byte
 * ordering */
#define HOST_TO_CCID_16(x) (x)
#define HOST_TO_CCID_32(x) (x)

/** structure used with \ref FEATURE_VERIFY_PIN_DIRECT */
typedef struct
{
	uint8_t bTimerOut;	/**< timeout is seconds (00 means use default timeout) */
	uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
	uint8_t bmFormatString; /**< formatting options */
	uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
	                        * bits 3-0 PIN block size in bytes after
	                        * justification and formatting */
	uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
	                         * bit 4 set if system units are bytes, clear if
	                         * system units are bits,
	                         * bits 3-0 PIN length position in system units */
	uint16_t wPINMaxExtraDigit; /**< 0xXXYY where XX is minimum PIN size in digits,
	                            and YY is maximum PIN size in digits */
	uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
	                                 * be considered complete */
	uint8_t bNumberMessage; /**< Number of messages to display for PIN verification */
	uint16_t wLangId; /**< Language for messages */
	uint8_t bMsgIndex; /**< Message index (should be 00) */
	uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
	uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
	uint8_t abData[1]; /**< Data to send to the ICC */
} PIN_VERIFY_STRUCTURE;

/** structure used with \ref FEATURE_MODIFY_PIN_DIRECT */
typedef struct
{
	uint8_t bTimerOut;	/**< timeout is seconds (00 means use default timeout) */
	uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
	uint8_t bmFormatString; /**< formatting options */
	uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
	                        * bits 3-0 PIN block size in bytes after
	                        * justification and formatting */
	uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
	                         * bit 4 set if system units are bytes, clear if
	                         * system units are bits,
	                         * bits 3-0 PIN length position in system units */
	uint8_t bInsertionOffsetOld; /**< Insertion position offset in bytes for
	                             the current PIN */
	uint8_t bInsertionOffsetNew; /**< Insertion position offset in bytes for
	                             the new PIN */
	uint16_t wPINMaxExtraDigit;
	                         /**< 0xXXYY where XX is minimum PIN size in digits,
	                            and YY is maximum PIN size in digits */
	uint8_t bConfirmPIN; /**< Flags governing need for confirmation of new PIN */
	uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
	                                 * be considered complete */
	uint8_t bNumberMessage; /**< Number of messages to display for PIN verification*/
	uint16_t wLangId; /**< Language for messages */
	uint8_t bMsgIndex1; /**< index of 1st prompting message */
	uint8_t bMsgIndex2; /**< index of 2d prompting message */
	uint8_t bMsgIndex3; /**< index of 3d prompting message */
	uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
	uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
	uint8_t abData[1]; /**< Data to send to the ICC */
} PIN_MODIFY_STRUCTURE;

/* restore default structure elements alignment */
#ifdef __APPLE__
#pragma pack()
#else
#pragma pack(pop)
#endif

#endif
