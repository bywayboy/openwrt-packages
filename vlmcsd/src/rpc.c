#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#endif
#include "rpc.h"
#include "output.h"
#include "crypto.h"
#include "endian.h"

static int CheckRpcHeader(const RPC_HEADER *const Header, const BYTE desiredPacketType, const PRINTFUNC p);

////TODO: Use GUID instead of BYTE[16]
static const BYTE TransferSyntaxNDR32[] = {
	0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60
};

////TODO: Use GUID instead of BYTE[16]
static const BYTE InterfaceUuid[] = {
	0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06
};


//
// Dispatch RPC payload to kms.c
//
#define CREATERESPONSE_T(v)  int (*v)(const void *const, void *const)

static const struct {
	unsigned int  RequestSize;
	CREATERESPONSE_T( CreateResponse );
} _Versions[] = {
	{ sizeof(REQUEST_V4), (CREATERESPONSE_T()) CreateResponseV4 },
	{ sizeof(REQUEST_V6), (CREATERESPONSE_T()) CreateResponseV6 },
	{ sizeof(REQUEST_V6), (CREATERESPONSE_T()) CreateResponseV6 }
};


//
// RPC request (server)
//
#if defined(_PEDANTIC) && !defined(NO_LOG)
static void CheckRpcRequest(const RPC_REQUEST *const Request, const unsigned int len, const uint_fast8_t _v)
{
	if (len >_Versions[_v].RequestSize + sizeof(RPC_REQUEST))
		logger("Warning: %u excess bytes in RPC request.\n",
				len - _Versions[_v].RequestSize + sizeof(RPC_REQUEST)
		);

	if (Request->ContextId)
		logger("Warning: Context id should be 0 but is %u.\n",
				(unsigned int)LE16(Request->ContextId)
		);

	if (Request->Opnum)
		logger("Warning: OpNum should be 0 but is %u.\n",
				(unsigned int)LE16(Request->Opnum)
		);

	if (LE32(Request->AllocHint) != len - sizeof(RPC_REQUEST) + sizeof(Request->Ndr))
		logger("Warning: Allocation hint should be %u but is %u.\n",
				len + sizeof(Request->Ndr),
				LE32(Request->AllocHint)
		);

	if (LE32(Request->Ndr.DataLength) != len - sizeof(RPC_REQUEST))
		logger("Warning: NDR32 data length field should be %u but is %u.\n",
				len - sizeof(RPC_REQUEST),
				LE32(Request->Ndr.DataLength)
		);

	if (LE32(Request->Ndr.DataSizeIs) != len - sizeof(RPC_REQUEST))
		logger("Warning: NDR32 data size field should be %u but is %u.\n",
				len - sizeof(RPC_REQUEST),
				LE32(Request->Ndr.DataSizeIs)
		);
}
#endif // defined(_PEDANTIC) && !defined(NO_LOG)


static unsigned int RpcRequestSize(const RPC_REQUEST *const Request, const unsigned int RequestSize)
{
	uint_fast8_t  _v;
	_v = (uint_fast8_t)LE16(((WORD*)Request->Data)[1]) - 4;

	if ( _v < _countof(_Versions)
			&& RequestSize >= _Versions[_v].RequestSize + sizeof(RPC_REQUEST) )
	{
		#if defined(_PEDANTIC) && !defined(NO_LOG)
		CheckRpcRequest(Request, RequestSize, _v);
		#endif // defined(_PEDANTIC) && !defined(NO_LOG)
		return MAX_RESPONSE_SIZE + sizeof(RPC_RESPONSE);
	}

	return 0;
}


static int RpcRequest(const RPC_REQUEST *const Request, RPC_RESPONSE *const Response, const DWORD RpcAssocGroup, const SOCKET sock, const unsigned int len)
{
	uint_fast16_t  _v;
	_v = LE16(((WORD*)Request->Data)[1]) - 4;

	int ResponseSize = _Versions[_v].CreateResponse(Request->Data, Response->Data);

	if ( ResponseSize )
	{
		Response->Ndr.DataSizeIs1 = LE32(0x00020000);
		Response->Ndr.DataLength  =
		Response->Ndr.DataSizeIs2 = LE32(ResponseSize);

		int len = ResponseSize + sizeof(Response->Ndr);

		BYTE* pRpcReturnCode = ((BYTE*)&Response->Ndr) + len;
		UA32(pRpcReturnCode) = 0; //LE16 not needed for 0
		len += sizeof(DWORD);

		// Pad zeros to 32-bit align (seems not neccassary but Windows RPC does it this way)
		int pad = ((~len & 3) + 1) & 3;
		memset(pRpcReturnCode + sizeof(DWORD), 0, pad);
		len += pad;

		Response->AllocHint = LE32(len);

		Response->AllocHint +=
				Response->ContextId = Request->ContextId;

		*((WORD*)&Response->CancelCount) = 0; // CancelCount + Pad1
	}

	return ResponseSize;
}


#if defined(_PEDANTIC) && !defined(NO_LOG)
static void CheckRpcBindRequest(const RPC_BIND_REQUEST *const Request, const unsigned int len)
{
	uint_fast8_t i, HasTransferSyntaxNDR32 = FALSE;
	char guidBuffer1[GUID_STRING_LENGTH + 1], guidBuffer2[GUID_STRING_LENGTH + 1];

	uint32_t CapCtxItems =	(len - sizeof(*Request) + sizeof(Request->CtxItems)) / sizeof(Request->CtxItems);
	DWORD NumCtxItems = LE32(Request->NumCtxItems);

	if (NumCtxItems > CapCtxItems) // Can't be too small because already handled by RpcBindSize
		logger("Warning: Excess bytes in RPC bind request.\n");

	for (i = 0; i < NumCtxItems; i++)
	{
		if ( IsEqualGUID((GUID*)TransferSyntaxNDR32, &Request->CtxItems[i].TransferSyntax) )
		{
			HasTransferSyntaxNDR32 = TRUE;

			if (Request->CtxItems[i].ContextId != 0)
				logger("Warning: NDR32 context id is not 0.\n");

			if (Request->CtxItems[i].NumTransItems != LE16(1))
				logger("Fatal: %u NDR32 transfer items detected, but only one is supported.\n",
						(unsigned int)LE16(Request->CtxItems[i].NumTransItems)
				);

			if (!IsEqualGUID(&Request->CtxItems[i].InterfaceUUID, InterfaceUuid))
			{
				Uuid2String((GUID*)&Request->CtxItems[i].InterfaceUUID, guidBuffer1);
				Uuid2String((GUID*)InterfaceUuid, guidBuffer2);
				logger("Warning: NDR32 Interface UUID is %s but should be %s.\n", guidBuffer1, guidBuffer2);
			}

			if (Request->CtxItems[i].InterfaceVerMajor != LE16(1) || Request->CtxItems[i].InterfaceVerMinor != 0)
				logger("Warning: NDR32 Interface version is %u.%u but should be 1.0.\n",
						(unsigned int)LE16(Request->CtxItems[i].InterfaceVerMajor),
						(unsigned int)LE16(Request->CtxItems[i].InterfaceVerMinor)
				);

			if (Request->CtxItems[0].SyntaxVersion != LE32(2))
				logger("NDR32 transfer syntax version is %u but should be 2.\n", LE32(Request->CtxItems[0].SyntaxVersion));
		}
	}

	if (!HasTransferSyntaxNDR32)
		logger("Warning: RPC bind request has no NDR32 CtxItem.\n");
}
#endif // defined(_PEDANTIC) && !defined(NO_LOG)

//
// RPC binding handling (server)
//
static unsigned int RpcBindSize(const RPC_BIND_REQUEST *const Request, const unsigned int RequestSize)
{
	if ( RequestSize >= sizeof(RPC_BIND_REQUEST) )
	{
		unsigned int _NumCtxItems = LE32(Request->NumCtxItems);

		if ( RequestSize >= sizeof(RPC_BIND_REQUEST) - sizeof(Request->CtxItems[0]) + _NumCtxItems * sizeof(Request->CtxItems[0]) )
		{
			#if defined(_PEDANTIC) && !defined(NO_LOG)
			CheckRpcBindRequest(Request, RequestSize);
			#endif // defined(_PEDANTIC) && !defined(NO_LOG)
			return sizeof(RPC_BIND_RESPONSE) + _NumCtxItems * sizeof(((RPC_BIND_RESPONSE *)0)->Results[0]);
		}
	}

	return 0;
}


static int RpcBind(const RPC_BIND_REQUEST *const Request, RPC_BIND_RESPONSE *const Response, const DWORD RpcAssocGroup, const SOCKET sock, const unsigned int len)
{
	unsigned int  i, _st = 0;

	for (i = 0; i < LE32(Request->NumCtxItems); i++)
	{
		if ( IsEqualGUID((GUID*)TransferSyntaxNDR32, &Request->CtxItems[i].TransferSyntax) )
		{
			Response->Results[i].SyntaxVersion = LE32(2);
			Response->Results[i].AckResult =
			Response->Results[i].AckReason = 0;
			memcpy(&Response->Results[i].TransferSyntax, TransferSyntaxNDR32, sizeof(GUID));
			_st = !0;
		}
		else
		{
			Response->Results[i].SyntaxVersion = 0;
			Response->Results[i].AckResult =
			Response->Results[i].AckReason = LE16(2); // Unsupported
			memset(&Response->Results[i].TransferSyntax, 0, sizeof(GUID));
		}
	}

	if ( _st )
	{
		Response->MaxXmitFrag = Request->MaxXmitFrag;
		Response->MaxRecvFrag = Request->MaxRecvFrag;
		Response->AssocGroup  = LE32(RpcAssocGroup);

		socklen_t len;
		struct sockaddr_storage addr;

		// M$ RPC does not do this. Excess bytes contain apparently random data
		memset(Response->SecondaryAddress, 0, sizeof(Response->SecondaryAddress));

		len = sizeof addr;

		if (getsockname(sock, (struct sockaddr*)&addr, &len) ||
				getnameinfo((struct sockaddr*)&addr, len, NULL, 0, (char*)Response->SecondaryAddress, sizeof(Response->SecondaryAddress), NI_NUMERICSERV))
		{
			// In case of failure (should never happen) use default port (doesn't seem to break activation)
			strcpy((char*)Response->SecondaryAddress, "1688");
		}

		uint_fast8_t temp = strlen((char*)Response->SecondaryAddress) + 1;
		////FIXME: Temporary workaround for TCP ports < 10. sizeof(Response->SecondaryAddress) must be padded to 2, 6, 10, ...
		if (temp < 3) temp = 3;

		Response->SecondaryAddressLength = LE16(temp);
		Response->NumResults = Request->NumCtxItems;
	}

	return _st;
}

//
// Main RPC handling routine
//
#define GETRESPONSESIZE_T(v)  unsigned int (*v)(const void *const , const unsigned int)
#define GETRESPONSE_T(v)      int (*v)(const void *const , void *, const DWORD, const SOCKET, const unsigned int)

static const struct {
	BYTE  ResponsePacketType;
	GETRESPONSESIZE_T( GetResponseSize );
	GETRESPONSE_T( GetResponse );
} _Actions[] = {
	{ RPC_PT_BIND_ACK, (GETRESPONSESIZE_T()) RpcBindSize,    (GETRESPONSE_T()) RpcBind    },
	{ RPC_PT_RESPONSE, (GETRESPONSESIZE_T()) RpcRequestSize, (GETRESPONSE_T()) RpcRequest }
};


void RpcServer(const SOCKET sock, const DWORD RpcAssocGroup)
{
	RPC_HEADER  _Header;

	srand ((unsigned int)time(NULL));

	while (_recv(sock, &_Header, sizeof(_Header)))
	{
		unsigned int  _st, request_len, response_len, _a;
		BYTE  *_Request /* =  NULL */; //uncomment to avoid false warnings when compiling with -Og

		#if defined(_PEDANTIC) && !defined(NO_LOG)
		CheckRpcHeader(&_Header, _Header.PacketType, &logger);
		#endif // defined(_PEDANTIC) && !defined(NO_LOG)

		switch (_Header.PacketType)
		{
			case RPC_PT_BIND_REQ: _a = 0; break;
			case RPC_PT_REQUEST:  _a = 1; break;
			default: return;
		}

		if ( (_st = ( (signed)( request_len = LE16(_Header.FragLength) - sizeof(_Header) )) > 0
					&& (_Request = (BYTE*)malloc(request_len) )))
		{
			BYTE *_Response /* = NULL */; //uncomment to avoid warnings when compiling with -Og

			if ((_st = (_recv(sock, _Request, request_len))
						&& ( response_len = _Actions[_a].GetResponseSize(_Request, request_len) )
						&& (_Response = (BYTE*)malloc( response_len += sizeof(_Header) ))))
			{
				if ( (_st = _Actions[_a].GetResponse(_Request, _Response + sizeof(_Header), RpcAssocGroup, sock, request_len)) )
				{
					RPC_HEADER *rh = (RPC_HEADER *)_Response;

					if (_Actions[_a].ResponsePacketType == RPC_PT_RESPONSE)
						response_len = LE32(((RPC_RESPONSE*)(_Response + sizeof(_Header)))->AllocHint) + 24;

					/* *((WORD*)rh)           = *((WORD*)&_Header);
					rh->PacketFlags        = RPC_PF_FIRST | RPC_PF_LAST;
					rh->DataRepresentation = _Header.DataRepresentation;
					rh->AuthLength         = _Header.AuthLength;
					rh->CallId             = _Header.CallId;*/
					memcpy(rh, &_Header, sizeof(RPC_HEADER));
					rh->PacketType = _Actions[_a].ResponsePacketType;
					rh->FragLength = LE16(response_len);

					_st = _send(sock, _Response, response_len);

					if (DisconnectImmediately && rh->PacketType == RPC_PT_RESPONSE)
						shutdown(sock, VLMCSD_SHUT_RDWR);
				}
				free(_Response);
			}
			free(_Request);
		}
		if (!_st) return;
	}
}


static DWORD CallId = 2; // M$ starts with CallId 2. So we do the same.


// Check RPC Header (check to be performed with any received header: request and response)
static int CheckRpcHeader(const RPC_HEADER *const Header, const BYTE desiredPacketType, const PRINTFUNC p)
{
	int status = 0;

	if (Header->PacketType != desiredPacketType)
	{
		p("Fatal: Received wrong RPC packet type. Expected %u but got %u\n",
				(uint32_t)desiredPacketType,
				Header->PacketType
		);
		status = !0;
	}

	if (Header->DataRepresentation != BE32(0x10000000))
	{
		p("Fatal: RPC response does not conform to Microsoft's limited support of DCE RPC\n");
		status = !0;
	}

	if (Header->AuthLength != 0)
	{
		p("Fatal: RPC response requests authentication\n");
		status = !0;
	}

	// vlmcsd does not support fragmented packets (not yet neccassary)
	if ( (Header->PacketFlags & (RPC_PF_FIRST | RPC_PF_LAST)) != (RPC_PF_FIRST | RPC_PF_LAST) )
	{
		p("Fatal: RPC packet flags RPC_PF_FIRST and RPC_PF_LAST are not both set.\n");
		status = !0;
	}

	if (Header->PacketFlags & RPC_PF_CANCEL_PENDING)	p("Warning: %s should not be set\n", "RPC_PF_CANCEL_PENDING");
	if (Header->PacketFlags & RPC_PF_RESERVED)			p("Warning: %s should not be set\n", "RPC_PF_RESERVED");
	if (Header->PacketFlags & RPC_PF_NOT_EXEC)			p("Warning: %s should not be set\n", "RPC_PF_NOT_EXEC");
	if (Header->PacketFlags & RPC_PF_MAYBE)				p("Warning: %s should not be set\n", "RPC_PF_MAYBE");
	if (Header->PacketFlags & RPC_PF_OBJECT)			p("Warning: %s should not be set\n", "RPC_PF_OBJECT");

	if (Header->VersionMajor != 5 || Header->VersionMinor != 0)
	{
		p("Fatal: Expected RPC version 5.0 and got %u.%u\n", Header->VersionMajor, Header->VersionMinor);
		status = !0;
	}

	return status;
}


// Check Header of RPC Response
static int CheckRpcHeaders(const RPC_HEADER *const ResponseHeader, const RPC_HEADER *const RequestHeader, const BYTE desiredPacketType, const PRINTFUNC p)
{
	int status = CheckRpcHeader(ResponseHeader, desiredPacketType, p);

	if (desiredPacketType == RPC_PT_BIND_ACK)
	{
		if ((ResponseHeader->PacketFlags & RPC_PF_MULTIPLEX) != (RequestHeader->PacketFlags & RPC_PF_MULTIPLEX))
		{
			p("Warning: RPC_PF_MULTIPLEX of RPC request and response should match\n");
		}
	}
	else
	{
		if (ResponseHeader->PacketFlags & RPC_PF_MULTIPLEX)
		{
			p("Warning: %s should not be set\n", "RPC_PF_MULTIPLEX");
		}
	}

	if (ResponseHeader->CallId != RequestHeader->CallId)
	{
		p("Fatal: Sent Call Id %u but received answer for Call Id %u\n",
				(uint32_t)LE32(RequestHeader->CallId),
				(uint32_t)LE32(ResponseHeader->CallId)
		);

		status = !0;
	}

	return status;
}


static void CreateRpcRequestHeader(RPC_HEADER* RequestHeader, BYTE packetType, WORD size)
{
	RequestHeader->PacketType 			= packetType;
	RequestHeader->PacketFlags 			= RPC_PF_FIRST | RPC_PF_LAST;
	RequestHeader->VersionMajor 		= 5;
	RequestHeader->VersionMinor			= 0;
	RequestHeader->AuthLength			= 0;
	RequestHeader->DataRepresentation	= BE32(0x10000000); // Little endian, ASCII charset, IEEE floating point
	RequestHeader->CallId				= LE32(CallId);
	RequestHeader->FragLength			= LE16(size);
}


int RpcSendRequest(const SOCKET sock, const BYTE *const KmsRequest, const size_t requestSize, BYTE **KmsResponse, size_t *const responseSize)
{
	#define MAX_EXCESS_BYTES 16
	RPC_HEADER *RequestHeader, ResponseHeader;
	RPC_REQUEST *RpcRequest;
	RPC_RESPONSE _Response;
	int status = 0;
	size_t size = sizeof(RPC_HEADER) + sizeof(RPC_REQUEST) + requestSize;

	*KmsResponse = NULL;

	BYTE *_Request = (BYTE*)malloc(size);
	if (!_Request) return !0;

	RequestHeader = (RPC_HEADER*)_Request;
	RpcRequest = (RPC_REQUEST*)(_Request + sizeof(RPC_HEADER));

	CreateRpcRequestHeader(RequestHeader, RPC_PT_REQUEST, size);

	// Increment CallId for next Request
	CallId++;

	RpcRequest->ContextId = 0;
	RpcRequest->Opnum = 0;
	RpcRequest->AllocHint = requestSize + sizeof(RpcRequest->Ndr);
	RpcRequest->Ndr.DataLength = LE32(requestSize);
	RpcRequest->Ndr.DataSizeIs = LE32(requestSize);

	memcpy(RpcRequest->Data, KmsRequest, requestSize);

	for(;;)
	{
		int bytesread;

		if (!_send(sock, _Request, size))
		{
			errorout("\nFatal: Could not send RPC request\n");
			status = !0;
			break;
		}

		if (!_recv(sock, &ResponseHeader, sizeof(RPC_HEADER)))
		{
			errorout("\nFatal: No RPC response received from server\n");
			status = !0;
			break;
		}

		if ((status = CheckRpcHeaders(&ResponseHeader, RequestHeader, RPC_PT_RESPONSE, &errorout))) break;

		if (!_recv(sock, &_Response, sizeof(_Response)))
		{
			errorout("\nFatal: RPC response is incomplete\n");
			status = !0;
			break;
		}

		if (_Response.CancelCount != 0)
		{
			errorout("\nFatal: RPC response cancel count is not 0\n");
			status = !0;
		}

		if (_Response.ContextId != 0)
		{
			errorout("\nFatal: RPC response context id is not 0\n");
			status = !0;
		}

		*responseSize = LE32(_Response.Ndr.DataLength);

		if (!*responseSize || !_Response.Ndr.DataSizeIs1)
		{
			status = LE32(_Response.Ndr.DataSizeIs2);
			break;
		}

		if (_Response.Ndr.DataLength != _Response.Ndr.DataSizeIs2)
		{
			errorout("\nFatal: NDR data length (%u) does not match NDR data size (%u)\n",
					(uint32_t)*responseSize,
					(uint32_t)LE32(_Response.Ndr.DataSizeIs2)
			);

			status = !0;
		}

		*KmsResponse = (BYTE*)malloc(*responseSize + MAX_EXCESS_BYTES);

		if (!*KmsResponse)
		{
			errorout("\nFatal: Could not allocate memory for KMS response\n");
			status = !0;
			break;
		}

		// If RPC stub is too short, assume missing bytes are zero (same ill behavior as MS RPC)
		memset(*KmsResponse, 0, *responseSize + MAX_EXCESS_BYTES);

		// Read up to 16 bytes more than bytes expected to detect faulty KMS emulators
		if ((bytesread = recv(sock, (char*)*KmsResponse, *responseSize + MAX_EXCESS_BYTES, 0)) < (int)*responseSize)
		{
			errorout("\nFatal: No or incomplete KMS response received. Required %u bytes but only got %i\n",
					(uint32_t)*responseSize,
					(int32_t)(bytesread < 0 ? 0 : bytesread)
			);

			status = !0;
			break;
		}

		DWORD *pReturnCode;

		size_t len = *responseSize + sizeof(_Response.Ndr) + sizeof(*pReturnCode);
		size_t pad = ((~len & 3) + 1) & 3;

		if (len + pad != LE32(_Response.AllocHint))
		{
			errorout("\nWarning: RPC stub size is %u, should be %u (probably incorrect padding)\n", (uint32_t)LE32(_Response.AllocHint), (uint32_t)(len + pad));
		}
		else
		{
			size_t i;
			for (i = 0; i < pad; i++)
			{
				if (*(*KmsResponse + *responseSize + sizeof(*pReturnCode) + i))
				{
					errorout("\nWarning: RPC stub data not padded to zeros according to Microsoft standard\n");
					break;
				}
			}
		}

		pReturnCode = (DWORD*)(*KmsResponse + *responseSize);
		status = LE32(UA32(pReturnCode));

		if (status) errorout("\nWarning: RPC stub data reported Error %u\n", (uint32_t)status);

		break;
	}

	free(_Request);
	return status;
	#undef MAX_EXCESS_BYTES
}


int RpcBindClient(const SOCKET sock)
{
	RPC_HEADER *RequestHeader, ResponseHeader;
	RPC_BIND_REQUEST *bindRequest;
	RPC_BIND_RESPONSE *bindResponse;
	int status;
	#define NUM_CTX_ITEMS 1
	#define SIZE (sizeof(RPC_HEADER) + sizeof(RPC_BIND_REQUEST) + (NUM_CTX_ITEMS - 1) * sizeof(bindRequest->CtxItems[0]))

	BYTE _Request[SIZE];
	RequestHeader = (RPC_HEADER*)_Request;
	bindRequest = (RPC_BIND_REQUEST* )(_Request + sizeof(RPC_HEADER));

	CreateRpcRequestHeader(RequestHeader, RPC_PT_BIND_REQ, SIZE);
	RequestHeader->PacketFlags |=  UseMultiplexedRpc ? RPC_PF_MULTIPLEX : 0;

	bindRequest->AssocGroup		= 0;
	bindRequest->MaxRecvFrag	= bindRequest->MaxXmitFrag = LE16(5840);
	bindRequest->NumCtxItems	= LE32(NUM_CTX_ITEMS);

	bindRequest->CtxItems[0].ContextId			= 0;
	bindRequest->CtxItems[0].InterfaceVerMajor	= LE16(1);
	bindRequest->CtxItems[0].InterfaceVerMinor	= 0;
	bindRequest->CtxItems[0].NumTransItems		= LE16(1);
	bindRequest->CtxItems[0].SyntaxVersion		= LE32(2);

	memcpy(&bindRequest->CtxItems[0].TransferSyntax, TransferSyntaxNDR32, sizeof(GUID));
	memcpy(&bindRequest->CtxItems[0].InterfaceUUID, InterfaceUuid, sizeof(GUID));

	if (!_send(sock, _Request, SIZE))
	{
		errorout("\nFatal: Sending RPC bind request failed\n");
		return !0;
	}

	if (!_recv(sock, &ResponseHeader, sizeof(RPC_HEADER)))
	{
		errorout("\nFatal: Did not receive a response from server\n");
		return !0;
	}

	if ((status = CheckRpcHeaders(&ResponseHeader, RequestHeader, RPC_PT_BIND_ACK, &errorout))) return status;

	if (!(bindResponse = (RPC_BIND_RESPONSE*)malloc(LE16(ResponseHeader.FragLength) - sizeof(RPC_HEADER))))
	{
		errorout("\nFatal: Could not allocate memory for RPC bind response\n");
		return !0;
	}

	if (!_recv(sock, bindResponse, LE16(ResponseHeader.FragLength) - sizeof(RPC_HEADER)))
	{
		errorout("\nFatal: Incomplete RPC bind acknowledgement received\n");
		status = !0;
	}
	else
	{
		for (status = 0;;)
		{
			if (bindResponse->NumResults != bindRequest->NumCtxItems)
			{
				errorout("\nFatal: Expected %u CTX items but got %u\n",
						(uint32_t)LE32(bindRequest->NumCtxItems),
						(uint32_t)LE32(bindResponse->NumResults)
				);

				status = !0;
			}

			if (bindResponse->Results[0].AckResult != 0)
			{
				status = (int)(uint16_t)LE16(bindResponse->Results[0].AckResult);
				errorout("\nFatal: Server declined RPC bind request. AckResult is %i\n", status);
				break;
			}

			if (bindResponse->Results[0].SyntaxVersion != bindRequest->CtxItems[0].SyntaxVersion)
			{
				errorout("\nFatal: Expected syntax version %u but got %u\n",
						(uint32_t)LE32(bindRequest->CtxItems[0].SyntaxVersion),
						(uint32_t)LE32(bindResponse->Results[0].SyntaxVersion)
				);

				status = !0;
			}

			if (!IsEqualGUID(&bindResponse->Results[0].TransferSyntax, &bindRequest->CtxItems[0].TransferSyntax))
			{
				errorout("\nFatal: Transfer syntax of RPC bind request and response does not match\n");
				status = !0;
			}

			break;
		}
	}

	free(bindResponse);
	return status;
	#undef SIZE
}
