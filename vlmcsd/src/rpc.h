#ifndef __rpc_h
#define __rpc_h

#ifndef CONFIG
#define CONFIG "config.h"
#endif // CONFIG
#include CONFIG

#include "types.h"

typedef struct {
	BYTE   VersionMajor;
	BYTE   VersionMinor;
	BYTE   PacketType;
	BYTE   PacketFlags;
	DWORD  DataRepresentation;
	WORD   FragLength;
	WORD   AuthLength;
	DWORD  CallId;
} /*__packed*/ RPC_HEADER;


typedef struct {
	// RPC_HEADER  hdr;
	WORD   MaxXmitFrag;
	WORD   MaxRecvFrag;
	DWORD  AssocGroup;
	DWORD  NumCtxItems;
	struct {
		WORD   ContextId;
		WORD   NumTransItems;
		GUID   InterfaceUUID;
		WORD   InterfaceVerMajor;
		WORD   InterfaceVerMinor;
		GUID   TransferSyntax;
		DWORD  SyntaxVersion;
	} CtxItems[1];
} /*__packed*/ RPC_BIND_REQUEST;

typedef struct {
	// RPC_HEADER  hdr;
	WORD   MaxXmitFrag;
	WORD   MaxRecvFrag;
	DWORD  AssocGroup;
	WORD   SecondaryAddressLength;
	BYTE   SecondaryAddress[6];
	DWORD  NumResults;
	struct {
		WORD   AckResult;
		WORD   AckReason;
		GUID   TransferSyntax;
		DWORD  SyntaxVersion;
	} Results[0];
} /*__packed*/ RPC_BIND_RESPONSE;


typedef struct {
	// RPC_HEADER  hdr;
	DWORD  AllocHint;
	WORD   ContextId;
	WORD   Opnum;
	struct {
		DWORD  DataLength;
		DWORD  DataSizeIs;
	} Ndr;
	BYTE   Data[0];
} /*__packed*/ RPC_REQUEST;

typedef struct {
	// RPC_HEADER  hdr;
	DWORD  AllocHint;
	WORD   ContextId;
	BYTE   CancelCount;
	BYTE   Pad1;
	struct {
		DWORD  DataLength;
		DWORD  DataSizeIs1;
		DWORD  DataSizeIs2;
	} Ndr;
	BYTE   Data[0];
} /*__packed*/ RPC_RESPONSE;

#define RPC_PT_REQUEST   0
#define RPC_PT_RESPONSE  2
#define RPC_PT_BIND_REQ  11
#define RPC_PT_BIND_ACK  12

#define RPC_PF_FIRST			1
#define RPC_PF_LAST				2
#define RPC_PF_CANCEL_PENDING	4
#define RPC_PF_RESERVED			8
#define RPC_PF_MULTIPLEX		16
#define RPC_PF_NOT_EXEC			32
#define RPC_PF_MAYBE			64
#define RPC_PF_OBJECT			128

void rpcServer(const SOCKET sock, const DWORD RpcAssocGroup);
int rpcBindClient(const SOCKET sock);
int rpcSendRequest(const SOCKET sock, const BYTE *const KmsRequest, const size_t requestSize, BYTE **KmsResponse, size_t *const responseSize);

#endif // __rpc_h
