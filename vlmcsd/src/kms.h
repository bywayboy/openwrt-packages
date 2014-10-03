#ifndef __kms_h
#define __kms_h

#include "sys/time.h"
#include "vlmcsd.h"
#include "types.h"
//
// REQUEST... types are actually fixed size
// RESPONSE... size may vary, defined here is max possible size
//

#define MAX_RESPONSE_SIZE 384
#define PID_BUFFER_SIZE 64
#define MAX_REQUEST_SIZE sizeof(REQUEST_V6)
#define WORKSTATION_NAME_BUFFER 64 // Align to 8 bytes

// Constants for V6 time stamp interval
#define TIME_C1 0x00000022816889BDULL
#define TIME_C2 0x000000208CBAB5EDULL
#define TIME_C3 0x3156CD5AC628477AULL

#define VERSION_INFO union \
{ \
	DWORD Version;\
	struct { \
		WORD MinorVer; \
		WORD MajorVer; \
	} /*__packed*/; \
} /*__packed*/;

typedef struct {
	VERSION_INFO
	DWORD IsClientVM;
	DWORD LicenseStatus;
	DWORD GraceTime;
	GUID AppId;
	GUID SkuId;
	GUID KmsId;
	GUID ClientMachineId;
	DWORD MinimumClients;
	FILETIME TimeStamp;
	BYTE Reserved1[16];
	WCHAR WorkstationName[WORKSTATION_NAME_BUFFER];
} /*__packed*/ REQUEST;

typedef struct {
	VERSION_INFO
	DWORD KmsPIDLen;
	WCHAR KmsPID[PID_BUFFER_SIZE];
	GUID ClientMachineId;
	FILETIME TimeStamp;
	DWORD ActivatedMachines;
	DWORD ActivationInterval;
	DWORD RenewalInterval;
} /*__packed*/ RESPONSE;

#ifdef _DEBUG
typedef struct {
	VERSION_INFO
	DWORD KmsPIDLen;
	WCHAR KmsPID[49]; 		// Set this to the ePID length you want to debug
	GUID ClientMachineId;
	FILETIME TimeStamp;
	DWORD ActivatedMachines;
	DWORD ActivationInterval;
	DWORD RenewalInterval;
} __packed RESPONSE_DEBUG;
#endif


typedef struct {
	REQUEST RequestBase;
	BYTE Hash[16];
} /*__packed*/ REQUEST_V4;

typedef struct {
	RESPONSE ResponseBase;
	BYTE Hash[16];
} /*__packed*/ RESPONSE_V4;


typedef struct {
	VERSION_INFO
	BYTE Salt[16];
	REQUEST RequestBase;
	BYTE Pad[4];
} /*__packed*/ REQUEST_V5;

typedef REQUEST_V5 REQUEST_V6;

typedef struct {
	VERSION_INFO
	BYTE Salt[16];
	RESPONSE ResponseBase;
	BYTE Rand[16];
	BYTE Hash[32];
	BYTE HwId[8];
	BYTE XorSalts[16];
	BYTE Hmac[16];
	//BYTE Pad[10];
} /*__packed*/ RESPONSE_V6;

typedef struct {
	VERSION_INFO
	BYTE Salt[16];
	RESPONSE ResponseBase;
	BYTE Rand[16];
	BYTE Hash[32];
} /*__packed*/ RESPONSE_V5;

#ifdef _DEBUG
typedef struct {
	VERSION_INFO
	BYTE Salt[16];
	RESPONSE_DEBUG ResponseBase;
	BYTE Rand[16];
	BYTE Hash[32];
	BYTE Unknown[8];
	BYTE XorSalts[16];
	BYTE Hmac[16];
	BYTE Pad[16];
} __packed RESPONSE_V6_DEBUG;
#endif

#define RESPONSE_RESULT_OK ((1 << 9) - 1) //(9 bits)
typedef union
{
	DWORD mask;
	struct
	{
		BOOL HashOK : 1;
		BOOL TimeStampOK : 1;
		BOOL ClientMachineIDOK : 1;
		BOOL VersionOK : 1;
		BOOL IVsOK : 1;
		BOOL DecryptSuccess : 1;
		BOOL HmacSha256OK : 1;
		BOOL PidLengthOK : 1;
		BOOL RpcOK : 1;
		BOOL reserved2 : 1;
		BOOL reserved3 : 1;
		BOOL reserved4 : 1;
		BOOL reserved5 : 1;
		BOOL reserved6 : 1;
		uint32_t effectiveResponseSize : 9;
		uint32_t correctResponseSize : 9;
	};
} RESPONSE_RESULT;

typedef BYTE HWID[8];

typedef struct
{
	GUID guid;
	const char* name;
	const char* pid;
	uint8_t AppIndex;
	uint8_t KmsIndex;
} KmsIdList;

#define KMS_PARAM_MAJOR AppIndex
#define KMS_PARAM_REQUIREDCOUNT KmsIndex

#define APP_ID_WINDOWS 0
#define APP_ID_OFFICE2010 1
#define APP_ID_OFFICE2013 2

#define KMS_ID_VISTA 0
#define KMS_ID_WIN7 1
#define KMS_ID_WIN8_VL 2
#define KMS_ID_WIN_BETA 3
#define KMS_ID_WIN8_RETAIL 4
#define KMS_ID_WIN81_VL 5
#define KMS_ID_WIN81_RETAIL 6
#define KMS_ID_WIN2008A 7
#define KMS_ID_WIN2008B 8
#define KMS_ID_WIN2008C 9
#define KMS_ID_WIN2008R2A 10
#define KMS_ID_WIN2008R2B 11
#define KMS_ID_WIN2008R2C 12
#define KMS_ID_WIN2012 13
#define KMS_ID_WIN2012R2 14
#define KMS_ID_OFFICE2010 15
#define KMS_ID_OFFICE2013 16
#define KMS_ID_WIN_SRV_BETA 17

#define PWINGUID &AppList[APP_ID_WINDOWS].guid
#define POFFICE2010GUID &AppList[APP_ID_OFFICE2010].guid
#define POFFICE2013GUID &AppList[APP_ID_OFFICE2013].guid

size_t CreateResponseV4(REQUEST_V4 *const Request, BYTE *const response_data);
size_t CreateResponseV6(REQUEST_V6 *restrict Request, BYTE *const response_data);
BYTE *CreateRequestV4(size_t *size, const REQUEST* requestBase);
BYTE *CreateRequestV6(size_t *size, const REQUEST* requestBase);
void RandomPidInit();
void Get16RandomBytes(void* ptr);
void Hex2bin(BYTE *const bin, const char *hex, const size_t maxbin);
RESPONSE_RESULT DecryptResponseV6(RESPONSE_V6* Response_v6, int responseSize, uint8_t* const response, const uint8_t* const request, BYTE* hwid);
RESPONSE_RESULT DecryptResponseV4(RESPONSE_V4* Response_v4, const int responseSize, uint8_t* const response, const uint8_t* const request);
void GetUnixTimeAsFileTime(FILETIME *const ts);
__pure int64_t FileTimeToUnixTime(const FILETIME *const ts);
const char* GetProductNameHE(const GUID *const guid, const KmsIdList *const List, ProdListIndex_t *const i);
const char* GetProductNameLE(const GUID *const guid, const KmsIdList *const List, ProdListIndex_t *const i);
__pure ProdListIndex_t GetExtendedProductListSize();
__pure ProdListIndex_t GetAppListSize(void);

extern const KmsIdList ProductList[];
extern const KmsIdList AppList[];
extern const KmsIdList ExtendedProductList[];

#ifdef _PEDANTIC
uint16_t IsValidLcid(const uint16_t Lcid);
#endif // _PEDANTIC

#endif // __kms_h
