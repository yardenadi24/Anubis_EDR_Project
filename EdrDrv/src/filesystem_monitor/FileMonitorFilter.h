#pragma once
#include <fltKernel.h>
#include <bcrypt.h>  // This is the primary header for CNG in kernel mode
#include "../Commons/commons.h"


#define FILE_SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define MAX_DEVICE_NAME_LENGTH 260
#define HASH_STRING_LENGTH 65  // 64 hex chars + null terminator
#define MAX_HASH_BYTES 32      // SHA-256 produces 32 bytes
#define SEQUENTIAL_THRESHOLD_BYTES (1024 * 1024)  // 1MB threshold
#define SEQUENTIAL_TIMEOUT_SECONDS 5

// Communication port constants
#define FILTER_PORT_NAME L"\\AnubisFileMonitorPort"
#define MAX_CONNECTIONS 1  // Only allow one user-mode connection

static LIST_ENTRY g_FileEventQueue;
static KSPIN_LOCK g_FileQueueLock;
static KIRQL g_FileQueueOldIrql;
static LONG g_QueuedEventCount = 0;
static BOOLEAN g_FileMonitorInitialized = FALSE;

#define MAX_FILE_EVENTS 10000  // Maximum queued events

static constexpr USHORT c_MinSectorSize = 0x200;
static constexpr UINT64 c_nUnknownFileSize = (UINT64)-1;
constexpr UINT32 c_nSendMsgTimeout = 2 /*sec*/ * 1000 /*ms*/;

// Connection tracking
typedef struct _CONNECTION_CONTEXT {
	ULONG ProcessId;
	BOOLEAN IsConnected;
} CONNECTION_CONTEXT, * PCONNECTION_CONTEXT;

enum class FILE_CREATION_STATUS
{
	NONE,
	CREATED,
	OPENED,
	TRUNCATED,
	LAST
};

enum class VOLUME_DRIVER_TYPE
{
	NONE,
	FIXED,
	NETWORK,
	REMOVABLE,
	LAST
};

enum class SEQUENCE_TYPE
{
	NONE,
	READ,
	WRITE,
	LAST
};


typedef struct _INSTANCE_CONTEXT
{

	PFLT_INSTANCE pInstance; // Pointer to the instance

	BOOLEAN fSetupIsFinished; 

	CHAR sDeviceName[MAX_DEVICE_NAME_LENGTH]; // Device name for logging

	VOLUME_DRIVER_TYPE DriverType; 

	USHORT SectorSize;

	// Flags
	BOOLEAN fIsNetworkFS; // is network FS (MUP, virtual machine shares)
	BOOLEAN fIsMup; // is standard windows network share access (network FS)
	BOOLEAN fIsUsb; // is USB device
	BOOLEAN fIsFixed; // fixed drive
	BOOLEAN fIsCdrom; // cdrom drive


	UNICODE_STRING usVolumeGuid; // Volume GUID. if not filled, .length = 0
	WCHAR pVolumeGuidBuffer[MAX_PATH];

	UNICODE_STRING usDiskPdoName; // Disk PDO name (Disk Physical Device Object), .length = 0
	WCHAR pDiskPdoBuffer[MAX_PATH]; // Buffer for disk PDO name

	UNICODE_STRING usDeviceName; // Volume device name. if not filled, .length = 0
	WCHAR pDeviceNameBuffer[MAX_PATH]; // Disk PDO buffer. 

	UNICODE_STRING usContainerId; // Disk ContainerId. if not filled, .length = 0
	WCHAR pContainerIdBuffer[MAX_PATH]; // Disk ContainerId buffer.

	VOID Init()
	{
		RtlZeroMemory(this, sizeof(_INSTANCE_CONTEXT));

		fSetupIsFinished = FALSE;

		usVolumeGuid.Buffer = pVolumeGuidBuffer;
		usVolumeGuid.Length = 0;
		usVolumeGuid.MaximumLength = sizeof(pVolumeGuidBuffer);

		usDiskPdoName.Buffer = pDiskPdoBuffer;
		usDiskPdoName.Length = 0;
		usDiskPdoName.MaximumLength = sizeof(pDiskPdoBuffer);

		usDeviceName.Buffer = pDeviceNameBuffer;
		usDeviceName.Length = 0;
		usDeviceName.MaximumLength = sizeof(pDeviceNameBuffer);

		usContainerId.Buffer = pContainerIdBuffer;
		usContainerId.Length = 0;
		usContainerId.MaximumLength = sizeof(pContainerIdBuffer);

		SectorSize = c_MinSectorSize;
	}

} INSTANCE_CONTEXT, * PINSTANCE_CONTEXT;

typedef struct _SEQUENCE_ACTION
{
	BOOLEAN fEnabled = FALSE; //TODO:: CHANGED TO ATOMIC
	UINT64 nNextPos = 0;
	UINT64 nTotalBytesProcessed;

	BCRYPT_HASH_HANDLE hHash;
	BCRYPT_ALG_HANDLE  hAlgorithm;
	BOOLEAN fHashInitialized;

	UCHAR FinalHash[32];
	UCHAR FinalHexHash[65];
	BOOLEAN fHashFinalized;

	ULONG SequentialChunks;
	LARGE_INTEGER LastUpdateTime;

	_SEQUENCE_ACTION()
	{
		RtlZeroMemory(FinalHash, 32);
		fEnabled = FALSE;
		nNextPos = 0;
		nTotalBytesProcessed = 0;
		fHashFinalized = FALSE;
		fHashInitialized = FALSE;
	}
	
	~_SEQUENCE_ACTION()
	{
		CleanupHash();
	}

	NTSTATUS
	InitializeHash()
	{
		if (fHashInitialized)
			return STATUS_SUCCESS;

		// Ensure we're at PASSIVE_LEVEL
		if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
			return STATUS_UNSUCCESSFUL;
		}

		NTSTATUS Status = STATUS_SUCCESS;

		Status = BCryptOpenAlgorithmProvider(
			&hAlgorithm,
			BCRYPT_SHA256_ALGORITHM,
			NULL,
			0);

		if (!NT_SUCCESS(Status)) {
			return Status;
		}

		Status = BCryptCreateHash(
			hAlgorithm,
			&hHash,
			NULL,
			0,
			NULL,
			0,
			0);

		if (!NT_SUCCESS(Status)) {
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			hAlgorithm = NULL;
			return Status;
		}

		fHashInitialized = TRUE;
		KeQuerySystemTime(&LastUpdateTime);

		return STATUS_SUCCESS;
	}

	NTSTATUS
	UpdateHash(
		_In_reads_bytes_(cbData) CONST PVOID pData,
		_In_ SIZE_T cbData)
	{
		if (pData == NULL || cbData == 0)
			return STATUS_INVALID_PARAMETER;

		NTSTATUS Status = STATUS_SUCCESS;

		__try {
			if (!fHashInitialized)
				Status = InitializeHash();

			if (!NT_SUCCESS(Status))
				__leave;

			// If finalized, don't update
			if (fHashFinalized) {
				Status = STATUS_INVALID_STATE_TRANSITION;
				__leave;
			}

			if (cbData > SEQUENTIAL_THRESHOLD_BYTES)
			{
				PUCHAR pByteData = (PUCHAR)pData;
				SIZE_T BytesRemaining = cbData;

				while (BytesRemaining > 0)
				{
					SIZE_T ChunkSize = min(BytesRemaining, SEQUENTIAL_THRESHOLD_BYTES);

					Status = BCryptHashData(
						hHash,
						pByteData,
						(ULONG)ChunkSize,
						0);

					if (!NT_SUCCESS(Status))
					{
						__leave;
					}

					pByteData += ChunkSize;
					BytesRemaining -= ChunkSize;
				}
			}
			else {

				// Normal single update
				Status = BCryptHashData(
					hHash,
					(PUCHAR)pData,
					(ULONG)cbData,
					0);

				if (!NT_SUCCESS(Status)) {
					DbgError("BCryptHashData failed: 0x%X", Status);
					__leave;
				}
			}

			// Update tracking
			nTotalBytesProcessed += cbData;
			nNextPos += cbData;
			SequentialChunks++;
			KeQuerySystemTime(&LastUpdateTime);

			DbgInfo("Hash updated: %Iu bytes, total: %llu", cbData, nTotalBytesProcessed);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = GetExceptionCode();
			DbgError("Exception in UpdateHash: 0x%X", Status);
			
			// Reset hash
			CleanupHash();
			fHashInitialized = FALSE;
		}
	}

	// Finalize the hash and get the result
	NTSTATUS
	FinalizeHash()
	{
		if (!fHashInitialized)
			STATUS_INVALID_STATE_TRANSITION;

		if (fHashFinalized)
			return STATUS_SUCCESS;

		NTSTATUS Status = BCryptFinishHash(
			hHash,
			FinalHash,
			sizeof(FinalHash),
			0);

		if (NT_SUCCESS(Status))
		{
			FillHashHexString();
			fHashFinalized = TRUE;
			DbgInfo("Hash finalized after %llu bytes", nTotalBytesProcessed);
		}
		else {
			DbgError("BCryptFinishHash failed: 0x%X", Status);
		}

		return Status;
	}

	VOID
	FillHashHexString()
	{
		if (!fHashFinalized)
		{
			// No hash yet
			RtlZeroMemory(FinalHexHash, 65);
			return;
		}

		for (int i = 0; i < 32; i++)
		{
			sprintf_s((PCHAR)(&FinalHexHash[i * 2]), 3, "%02x", FinalHash[i]);
		}
		FinalHexHash[64] = '\0';
	}

	VOID
	CleanupHash()
	{
		if (hHash != NULL)
		{
			BCryptDestroyHash(hHash);
			hHash = NULL;
		}

		if (hAlgorithm != NULL)
		{
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			hAlgorithm = NULL;
		}

		fHashInitialized = FALSE;
	}

	VOID
	Reset()
	{
		CleanupHash();
		nNextPos = 0;
		nTotalBytesProcessed = 0;
		SequentialChunks = 0;
		fHashFinalized = FALSE;

		RtlZeroMemory(FinalHash, sizeof(FinalHash));
		RtlZeroMemory(FinalHexHash, sizeof(FinalHexHash));
	}

	NTSTATUS UpdateHashIoOperation(_In_ PFLT_CALLBACK_DATA pData, SEQUENCE_TYPE Type)
	{
		NTSTATUS Status = STATUS_SUCCESS;
		SIZE_T DataSize = pData != NULL ? pData->IoStatus.Information : 0;

		if (pData == NULL || DataSize == 0 || Type == SEQUENCE_TYPE::NONE || Type == SEQUENCE_TYPE::LAST)
			return STATUS_INVALID_PARAMETER;

		// Ensure we're at the right IRQL
		if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
			DbgError("Cannot hash at IRQL %d\n", KeGetCurrentIrql());
			return STATUS_INVALID_DEVICE_STATE;
		}

		BOOLEAN IsWrite = Type == SEQUENCE_TYPE::WRITE;

		DbgInfo("Updating hash for %s operation: %Iu bytes",
			IsWrite ? "WRITE" : "READ", DataSize);

		// Extract the MDL and Buffer pointers based on operation type
		PMDL pMdl = NULL;
		PVOID pBuffer = NULL;

		if (IsWrite)
		{
			pMdl = pData->Iopb->Parameters.Write.MdlAddress;
			pBuffer = pData->Iopb->Parameters.Write.WriteBuffer;
		}
		else {
			pMdl = pData->Iopb->Parameters.Read.MdlAddress;
			pBuffer = pData->Iopb->Parameters.Read.ReadBuffer;
		}

		// Now handle based on I/O type
		if (pMdl != NULL) {
			// Direct I/O path - need to walk the MDL chain
			Status = ProcessDirectIOForHash(pMdl, DataSize);
		}
		else if (pBuffer != NULL) {
			// Buffered I/O path - simple case
			Status = ProcessBufferedIOForHash(pBuffer, DataSize);
		}
		else {
			// Neither MDL nor Buffer - this shouldn't happen
			DbgError("No data source available for hashing");
			Status = STATUS_INVALID_PARAMETER;
		}

		if (NT_SUCCESS(Status)) {
			DbgInfo("Hash update successful: %llu total bytes hashed",
				nTotalBytesProcessed);
		}
		else {
			DbgError("Hash update failed: 0x%X", Status);
		}

		return Status;
	}

	// Helper for buffered I/O (much simpler)
	NTSTATUS ProcessBufferedIOForHash(
		_In_ PVOID pBuffer,
		_In_ SIZE_T DataSize)
	{
		NTSTATUS Status = STATUS_SUCCESS;

		__try {
			// For buffered I/O, we might need to probe the buffer if it's from user mode
			if (pBuffer >= MmUserProbeAddress) {
				ProbeForRead(pBuffer, DataSize, 1);
			}

			// Single call to update hash
			Status =UpdateHash(pBuffer, DataSize);

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Status = GetExceptionCode();
			DbgError("Exception in buffered I/O hash update: 0x%X", Status);
		}

		return Status;
	}

	// Helper for direct I/O (handles MDL complexity)
	NTSTATUS ProcessDirectIOForHash(
		_In_ PMDL pMdlChain,
		_In_ SIZE_T TotalDataSize)
	{
		NTSTATUS Status = STATUS_SUCCESS;
		SIZE_T BytesProcessed = 0;

		// Walk the MDL chain
		for (PMDL pCurrentMdl = pMdlChain;
			pCurrentMdl != NULL && BytesProcessed < TotalDataSize;
			pCurrentMdl = pCurrentMdl->Next)
		{
			PVOID pMdlBuffer = MmGetSystemAddressForMdlSafe(
				pCurrentMdl,
				NormalPagePriority | MdlMappingNoExecute);

			if (pMdlBuffer == NULL) {
				Status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			SIZE_T MdlSize = MmGetMdlByteCount(pCurrentMdl);
			SIZE_T BytesToProcess = min(MdlSize, TotalDataSize - BytesProcessed);

			__try {
				Status = UpdateHash(pMdlBuffer, BytesToProcess);
				if (!NT_SUCCESS(Status)) {
					break;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				Status = GetExceptionCode();
				break;
			}

			BytesProcessed += BytesToProcess;
		}

		return Status;
	}

}SEQUENCE_ACTION, *PSEQUENCE_ACTION;

typedef struct _STREAM_HANDLE_CONTEXT
{


	ULONG_PTR  nOpeningProcessId = 0;
	PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
	PINSTANCE_CONTEXT pInstCtx = NULL;
	
	UINT64 nSizeAtCreation = c_nUnknownFileSize;	
	FILE_CREATION_STATUS eCreationStatus = FILE_CREATION_STATUS::NONE;
		
	BOOLEAN fIsDirectory = FALSE;
	BOOLEAN fIsExecute = FALSE;
	BOOLEAN fDeleteOnClose = FALSE;
	BOOLEAN fDispositionDelete = FALSE;
	BOOLEAN fDirty = FALSE; // Changed
	BOOLEAN fSkipItem = FALSE;

	SEQUENCE_ACTION SequenceReadInfo;
	SEQUENCE_ACTION SequenceWriteInfo;


	_STREAM_HANDLE_CONTEXT() = default;
	~_STREAM_HANDLE_CONTEXT()
	{
		if (pNameInfo != NULL)
		{
			FltReleaseFileNameInformation(pNameInfo);
			pNameInfo = NULL;
		}

		if (pInstCtx != NULL)
		{
			FltReleaseContext(pInstCtx);
			pInstCtx = NULL;
		}
		
		SequenceReadInfo.CleanupHash();
		SequenceWriteInfo.CleanupHash();
	}

	// Replacement new
	// Constructs an object at a specific, pre-allocated memory location
	// Being called like this: TypeA ptr = new (ExistingMemory) TypeA(Args...) 
	PVOID __cdecl operator new (size_t, PVOID p)
	{
		return p;
	}

	// Replacement delete
	VOID __cdecl operator delete(PVOID)
	{}



	static 
	NTSTATUS
	Initialize(
	PSTREAM_HANDLE_CONTEXT* ppThisStreamCtx,
	PCFLT_RELATED_OBJECTS pFltObjects)
	{
		PFLT_CONTEXT pFltCtx = NULL;
		NTSTATUS Status = STATUS_SUCCESS;

		Status = FltAllocateContext(
			pFltObjects->Filter,
			FLT_STREAMHANDLE_CONTEXT,
			sizeof(STREAM_HANDLE_CONTEXT),
			NonPagedPool,
			&pFltCtx
		);

		if (!NT_SUCCESS(Status))
		{
			if (pFltCtx != NULL)
			{
				FltReleaseContext(pFltCtx);
			}

			return Status;
		}

		// Add the context
		Status = FltSetStreamHandleContext(
			pFltObjects->Instance,
			pFltObjects->FileObject,
			FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
			pFltCtx,
			NULL);

		if (!NT_SUCCESS(Status))
		{
			if (pFltCtx != NULL)
				FltReleaseContext(pFltCtx);

			return Status;
		}

		// Call constructor
		*ppThisStreamCtx = new(pFltCtx) _STREAM_HANDLE_CONTEXT;

		RtlZeroMemory(pFltCtx, sizeof(STREAM_HANDLE_CONTEXT));

		return STATUS_SUCCESS;
	}

	static
	VOID
		CleanUp(
			PFLT_CONTEXT Ctx,
			FLT_CONTEXT_TYPE /*Ctx type*/
		)
	{
		PSTREAM_HANDLE_CONTEXT DelCtx = (PSTREAM_HANDLE_CONTEXT)Ctx;
		delete DelCtx;
	}

}STREAM_HANDLE_CONTEXT, *PSTREAM_HANDLE_CONTEXT;

NTSTATUS
Initialize(PDRIVER_OBJECT pDriverObj);

VOID
Finalize();

CONST
PWCHAR
ConvertDriverTypeToString(VOLUME_DRIVER_TYPE eType)
{
	switch (eType)
	{
	case VOLUME_DRIVER_TYPE::FIXED:
		return L"FIXED";
	case VOLUME_DRIVER_TYPE::NETWORK:
		return L"NETWORK";
	case VOLUME_DRIVER_TYPE::REMOVABLE:
		return L"REMOVABLE";
	default:
		return L"";
	}
}

VOID
CleanUpInstanceContext(
	PFLT_CONTEXT pCtx,
	FLT_CONTEXT_TYPE
)
{
	if (pCtx == NULL)
		return;

	PINSTANCE_CONTEXT pInstCtx = (PINSTANCE_CONTEXT)pCtx;
	if (pInstCtx->pDiskPdoBuffer != NULL)
		ExFreePoolWithTag(pInstCtx->pDiskPdoBuffer, EDR_MEMORY_TAG);
	if (pInstCtx->pDeviceNameBuffer != NULL)
		ExFreePoolWithTag(pInstCtx->pDeviceNameBuffer, EDR_MEMORY_TAG);
	if (pInstCtx->pContainerIdBuffer != NULL)
		ExFreePoolWithTag(pInstCtx->pContainerIdBuffer, EDR_MEMORY_TAG);
}

NTSTATUS
CollectUsbInfo(
	PCFLT_RELATED_OBJECTS pFltObjects,
	PINSTANCE_CONTEXT pInCtx);

NTSTATUS
QueryInstanceTeardown(
	PCFLT_RELATED_OBJECTS /*pFltObjects*/,
	FLT_INSTANCE_QUERY_TEARDOWN_FLAGS /*eFlags*/);

NTSTATUS
UnloadFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);


NTSTATUS
SetupInstance
(_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS /*eFlags*/,
	_In_ DEVICE_TYPE eVolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE eVolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreCleanup(
_Inout_ PFLT_CALLBACK_DATA /*pData*/,
_In_ PCFLT_RELATED_OBJECTS pFltObjects,
_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/);

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostCleanup(
__inout PFLT_CALLBACK_DATA pData,
__in PCFLT_RELATED_OBJECTS pFltObjects,
__in_opt PVOID /*pCompletionContext*/,
__in FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreSetFileInfo(
_Inout_ PFLT_CALLBACK_DATA pData,
_In_ PCFLT_RELATED_OBJECTS pFltObjects,
_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/);

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostSetFileInfo(
__inout PFLT_CALLBACK_DATA pData,
__in PCFLT_RELATED_OBJECTS pFltObjects,
__in_opt PVOID /*pCompletionContext*/,
__in FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreWrite(
_Inout_ PFLT_CALLBACK_DATA pData,
_In_ PCFLT_RELATED_OBJECTS pFltObjects,
_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/);

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostWrite(
__inout PFLT_CALLBACK_DATA pData,
__in PCFLT_RELATED_OBJECTS pFltObjects,
__in_opt PVOID /*pCompletionContext*/,
__in FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreRead(_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/);

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostRead(
	__inout PFLT_CALLBACK_DATA pData,
	__in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/,
	__in FLT_POST_OPERATION_FLAGS Flags);

NTSTATUS
SendFileEventNoResponse(
	kEventType EventType,
	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx);

//////////////////////////////////////////////////////////////////////////
// Meta data for the file event
//////////////////////////////////////////////////////////////////////////

LARGE_INTEGER
GetCurrentTimeStamp();


NTSTATUS GetNormalizedFilePath(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PUNICODE_STRING NormalizedPath
);

NTSTATUS
QueryFileSize(
	PFLT_INSTANCE pInstance,
	PFILE_OBJECT pFileObject,
	PULONGLONG pFileSize
);

ULONG
GetRequestorProcessId(
	PFLT_CALLBACK_DATA pData
);

NTSTATUS
GetRenameTargetPath(
	PFLT_CALLBACK_DATA pData,
	PUNICODE_STRING pTargetName
);

VOID
ExtractCreateParameters(
	PFLT_CALLBACK_DATA pData,
	ACCESS_MASK* pDesiredAccess,
	ULONG* CreateDisposition,
	ULONG* CreateOptions,
	ULONG* FileAttributes,
	ULONG* ShareAccess
);

VOID
DebugPrintAccessMask(ACCESS_MASK Access);

// Communication port callbacks
NTSTATUS FLTAPI
FilterConnectNotify(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionPortCookie
);

VOID FLTAPI
FilterDisconnectNotify(
	_In_opt_ PVOID ConnectionCookie
);

NTSTATUS FLTAPI
FilterMessageNotify(
	_In_opt_ PVOID PortCookie,
	_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength,
	_Out_ PULONG ReturnOutputBufferLength
);

// Port management
NTSTATUS
InitializeCommunicationPort();

VOID 
CleanupCommunicationPort();
