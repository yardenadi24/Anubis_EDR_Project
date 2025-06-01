#pragma once
#include <fltKernel.h>
#include "../Commons/commons.h"


#define FILE_SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define MAX_DEVICE_NAME_LENGTH 260

static constexpr USHORT c_MinSectorSize = 0x200;
static constexpr UINT64 c_nUnknownFileSize = (UINT64)-1;
constexpr UINT32 c_nSendMsgTimeout = 2 /*sec*/ * 1000 /*ms*/;

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

typedef struct _INSTANCE_CONTEXT
{

	PFLT_INSTANCE pInstance; // Pointer to the instance

	BOOLEAN fSetupIsFinished; 

	CHAR sDeviceName[MAX_DEVICE_NAME_LENGTH]; // Device name for logging

	VOLUME_DRIVER_TYPE DriverType; 

	USHORT SectorSize;

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
	UCHAR HashedData[32]; // 32 for SHA256

	_SEQUENCE_ACTION()
	{
		RtlZeroMemory(HashedData, 32);
	}

	NTSTATUS UpdateHash(
		CONST PVOID pData,
		SIZE_T cbData)
	{
		NTSTATUS Status = STATUS_SUCCESS;
		__try
		{
			Status = ComputeHash(
						(PUCHAR)pData,
						cbData,
						HashedData);
			if (NT_SUCCESS(Status))
			{
				// Computed new hash
				nNextPos += cbData;
				__leave;
			}

			// Failed
			Status = STATUS_UNSUCCESSFUL;

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			Status = GetExceptionCode();
		}

		return Status;
	}


}SEQUENCE_ACTION, *PSEQUENCE_ACTION;

typedef struct _STREAM_HANDLE_CONTEXT
{


	PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
		
	UINT64 nSizeAtCreation = c_nUnknownFileSize;
		
	ULONG_PTR  nOpeningProcessId = 0;
		
	FILE_CREATION_STATUS eCreationStatus = FILE_CREATION_STATUS::NONE;
	BOOLEAN fIsDirectory = FALSE;
	BOOLEAN fIsExecute = FALSE;
	BOOLEAN fDeleteOnClose = FALSE;
	BOOLEAN fDispositionDelete = FALSE;
	BOOLEAN fDirty = FALSE; // Changed
	BOOLEAN fSkipItem = FALSE;

	SEQUENCE_ACTION SequenceReadInfo;
	SEQUENCE_ACTION SequenceWriteInfo;

	PINSTANCE_CONTEXT pInstCtx = NULL;

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

NTSTATUS Initialize(PDRIVER_OBJECT pDriverObj);

VOID Finalize();


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
UpdateHash(
	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx,
	PFLT_CALLBACK_DATA pData);

NTSTATUS
OpenFile(
PFLT_INSTANCE pInstance,
UNICODE_STRING& rFilePath,
PVOID FileHandle,
PFILE_OBJECT pFileObj,
ACCESS_MASK DesiredAccess = FILE_GENERIC_READ,
ULONG ShareAccess = FILE_SHARE_ALL);

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