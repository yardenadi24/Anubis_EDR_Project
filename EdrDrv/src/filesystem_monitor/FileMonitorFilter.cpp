#include "FileMonitorFilter.h"
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <Ntddstor.h>
#include "..\utils\kStringUtils.h"
#include "..\utils\kOsUtils.h"
#include "..\utils\kDiskUtils.h"


PFLT_FILTER g_pFilter = NULL;
BOOLEAN g_Monitor = FALSE;
BOOLEAN g_PortInitialized = FALSE;
PFLT_PORT g_pServerPort; // Filter server port 
PFLT_PORT g_pClientPort; // Filter client port 

//////////////////////////
// Operation callbacks
/////////////////////////

CONST
FLT_OPERATION_REGISTRATION
c_Callbacks[] =
{
	{ IRP_MJ_CREATE, 0, PreCreate, PostCreate },
	{ IRP_MJ_CLEANUP, 0, PreCleanup, PostCleanup },
	{ IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreSetFileInfo, PostSetFileInfo },
	{ IRP_MJ_WRITE, 0, PreWrite, PostWrite },
	{ IRP_MJ_READ, 0, PreRead, PostRead },

	{ IRP_MJ_OPERATION_END }
};

//////////////////////////
// Contexts
//////////////////////////

CONST
FLT_CONTEXT_REGISTRATION
c_ContextRegistration[] =
{
	{FLT_INSTANCE_CONTEXT, 0, CleanUpInstanceContext, sizeof(INSTANCE_CONTEXT), EDR_MEMORY_TAG},
	{FLT_STREAMHANDLE_CONTEXT, 0, STREAM_HANDLE_CONTEXT::CleanUp, sizeof(STREAM_HANDLE_CONTEXT), EDR_MEMORY_TAG}
};

//////////////////////////
// Registration struct
//////////////////////////

CONST
FLT_REGISTRATION
c_FilterRegistration
{
	sizeof(FLT_REGISTRATION) /*Size*/,
	FLT_REGISTRATION_VERSION /*Version*/,
	0 /*Flags*/,
	c_ContextRegistration /*Contexts*/,
	c_Callbacks /*Callbacks*/,
	UnloadFilter /*Unload func*/,
	SetupInstance /*Instance setup routine*/,
	QueryInstanceTeardown,
	StartInstanceTeardown,
	CompleteInstanceTeardown,

	NULL /*Generate file name*/,
	NULL /*Generate destination file name*/,
	NULL /*Normalize name component*/
};

NTSTATUS
Initialize(PDRIVER_OBJECT pDriverObj)
{
	BOOLEAN fSuccess = FALSE;

	__try {

		NTSTATUS Status = FltRegisterFilter(pDriverObj, &c_FilterRegistration, &g_pFilter);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		Status = FltStartFiltering(g_pFilter);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}


		fSuccess = TRUE;
	}
	__finally {

		if (!fSuccess)
		{
			Finalize();
			return STATUS_UNSUCCESSFUL;
		}

	}
	return STATUS_SUCCESS;
}


VOID
Finalize()
{
	if (g_pFilter == NULL)
		return;

	FltUnregisterFilter(g_pFilter);
	g_pFilter = NULL;
}

// This routine is called whenever
// a new instance is created on a volume. This
// gives us a chance to decide
// if we need to attach to this volume or not.
NTSTATUS SetupInstance(_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS /*eFlags*/,
	_In_ DEVICE_TYPE eVolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE eVolumeFilesystemType)
{
	PINSTANCE_CONTEXT pInstCtx = NULL;
	PFLT_VOLUME_PROPERTIES pVolumeProperties = NULL;

	__try
	{
		// Allocate memory for the instance context
		PFLT_CONTEXT pFltCtx = NULL;
		FltAllocateContext(
			pFltObjects->Filter,
			FLT_INSTANCE_CONTEXT,
			sizeof(_INSTANCE_CONTEXT),
			NonPagedPool,
			&pFltCtx);

		pInstCtx = (PINSTANCE_CONTEXT)pFltCtx;

		if (pInstCtx == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		pInstCtx->Init();

		do
		{
			// Get Volume properties
			ULONG nBufferSize = 0;
			NTSTATUS status = FltGetVolumeProperties(
				pFltObjects->Volume,
				NULL, // NULL to get the size first
				0,
				&nBufferSize);

			if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL)
			{
				// TODO::LOG
				break; // Failed to get volume properties
			}

			// Allocate demanded size
			pVolumeProperties = (PFLT_VOLUME_PROPERTIES)ExAllocatePoolWithTag(
				NonPagedPool,
				nBufferSize,
				EDR_MEMORY_TAG
			);
			if (pVolumeProperties == NULL)
				return STATUS_INSUFFICIENT_RESOURCES;


			status = FltGetVolumeProperties(
				pFltObjects->Volume,
				pVolumeProperties,
				nBufferSize,
				&nBufferSize);

			if (!NT_SUCCESS(status))
			{
				ExFreePoolWithTag(pVolumeProperties, EDR_MEMORY_TAG);
				pVolumeProperties = NULL;
				break; // Failed to get volume properties
			}

		} while (false);
		
		// Get device name if possiable
		PUNICODE_STRING pDeviceName = pVolumeProperties == NULL ? &cUnkownUnicodeString : &pVolumeProperties->RealDeviceName;

		
		ANSI_STRING AnsiDeviceName;
		AnsiDeviceName.Buffer = pInstCtx->sDeviceName;
		AnsiDeviceName.Length = 0;
		AnsiDeviceName.MaximumLength = sizeof(pInstCtx->sDeviceName) - 1;

		NTSTATUS status = RtlUnicodeStringToAnsiString(
			&AnsiDeviceName,
			pDeviceName,
			FALSE);

		if (!NT_SUCCESS(status))
		{
			AnsiDeviceName.Length = 0;
		}

		pInstCtx->sDeviceName[AnsiDeviceName.Length] = 0; // Null-terminate the string

		// Copy Device name to the instance context
		if (pVolumeProperties != NULL)
		{
			CloneUnicodeString(
				&pVolumeProperties->RealDeviceName,
				&pInstCtx->usDeviceName,
				(PVOID*)&pInstCtx->pDeviceNameBuffer);
		}

		// Get the sector size
		if (pVolumeProperties != NULL)
		{
			pInstCtx->SectorSize = (pVolumeProperties->SectorSize < c_MinSectorSize) ? c_MinSectorSize : pVolumeProperties->SectorSize;
		}

		// Check if its a network FS attempt
		if (eVolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
		{
			pInstCtx->fIsNetworkFS = TRUE;

			// The string L"\\Device\\Mup" 
			// refers to the Multiple UNC Provider (MUP) device in Windows.
			// MUP is a file system driver that allows access to network resources
			// using UNC (Universal Naming Convention) paths (Example: \\server\share)
			STATIC_UNICODE_STRING(usDeviceMup, L"\\device\\mup");
			if (pVolumeProperties != NULL
				&& RtlEqualUnicodeString(
					&pVolumeProperties->RealDeviceName,
					&usDeviceMup, TRUE))
			{
				pInstCtx->fIsMup = TRUE;
			}
		}

		if (eVolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM)
		{
			// Collect USB info
			status = CollectUsbInfo(pFltObjects, pInstCtx);
		}

		if (pVolumeProperties != NULL)
		{
			pInstCtx->fIsFixed = !BOOLEAN_FLAG_ON(
				pVolumeProperties->DeviceCharacteristics,
				FILE_REMOVABLE_MEDIA | FILE_FLOPPY_DISKETTE | FILE_REMOTE_DEVICE | FILE_PORTABLE_DEVICE);
		}
		else {
			pInstCtx->fIsFixed = (BOOLEAN)(eVolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM && !pInstCtx->fIsUsb);
		}


		// Get volume GUID
		ULONG nBufferSizeNeeded = 0;
		if (!NT_SUCCESS(FltGetVolumeGuidName(pFltObjects->Volume, &pInstCtx->usVolumeGuid, &nBufferSizeNeeded)))
		{
			// Cant get volume guid , should log
		}

		if (pInstCtx->fIsNetworkFS)
		{
			pInstCtx->DriverType = VOLUME_DRIVER_TYPE::NETWORK;
		}
		else if (pVolumeProperties != NULL)
		{
			if (BOOLEAN_FLAG_ON(pVolumeProperties->DeviceCharacteristics, FILE_REMOVABLE_MEDIA))
			{
				pInstCtx->DriverType = VOLUME_DRIVER_TYPE::REMOVABLE;
			}
			else {
				pInstCtx->DriverType = VOLUME_DRIVER_TYPE::FIXED;
			}
		}
		else {
			if (pInstCtx->fIsFixed)
			{
				pInstCtx->DriverType = VOLUME_DRIVER_TYPE::FIXED;
			}
			else {
				pInstCtx->DriverType = VOLUME_DRIVER_TYPE::REMOVABLE;
			}
		}

		ULONG nDeviceCharacteristics = pVolumeProperties != NULL ? pVolumeProperties->DeviceCharacteristics : 0;

		// LOG the device info

		pInstCtx->fSetupIsFinished = TRUE;

	}
	__finally
	{
		if (pInstCtx != NULL)
		{
			FltReleaseContext(pInstCtx);
		}
		if (pVolumeProperties != NULL)
		{
			ExFreePoolWithTag(pVolumeProperties, EDR_MEMORY_TAG);
		}
	}

	return STATUS_SUCCESS;
}



// This is called when an instance is being manually
// deleted by call to 'FltDetachVolume' of 'FilterDetach'
// giving us a chance to fail the detach request
NTSTATUS
QueryInstanceTeardown(
	PCFLT_RELATED_OBJECTS /*pFltObjects*/,
	FLT_INSTANCE_QUERY_TEARDOWN_FLAGS /*eFlags*/)
{
	return STATUS_SUCCESS;
}


// This routine is called at the start of instance teardown.
VOID StartInstanceTeardown(
	PCFLT_RELATED_OBJECTS /*pFltObjects*/,
	FLT_INSTANCE_TEARDOWN_FLAGS /*eFlags*/)
{
}

// This routine is called at the end of instance teardown.
VOID CompleteInstanceTeardown(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS /*eFlags*/)
{
	PINSTANCE_CONTEXT pInstCtx = NULL;
	__try
	{
		FltGetInstanceContext(
			pFltObjects->Instance,
			(PFLT_CONTEXT*)&pInstCtx);
	}
	__finally
	{
		if (pInstCtx != NULL)
		{
			FltReleaseContext(pInstCtx);
		}
	}
}

// Mainly check if need to monitor
FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreate(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	// Skip conditions
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) // Above Passive level
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (IoGetTopLevelIrp()) // Is nested IRP 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (FLT_IS_FASTIO_OPERATION(pData))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (!FLT_IS_IRP_OPERATION(pData))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Skip PIPE MAILSLOT
	if (FlagOn(pFltObjects->FileObject->Flags, FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Skip Paging file
	if (BOOLEAN_FLAG_ON(pData->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// ECP (Extra Create Parameter),
	// which is a mechanism in Windows for attaching extra metadata
	// to file create/open operations.
	// These are often used by system components
	// We want to see if its Prefetcher or Windows defender.
	PECP_LIST EcpList = NULL;
	if (NT_SUCCESS(FltGetEcpListFromCallbackData(g_pFilter, pData, &EcpList)) && EcpList != NULL)
	{
		// Skip Prefetcher
		// Skip Windows defender csvfs calls
		// TODO
	}

	// Get process handle
	//HANDLE nProcessId = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(pData);

	// TODO:: Create and fill process context
	// TODO:: Implement self defense

	if (!g_Monitor)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// TODO:: Is white listed?

	// TODO:: Specific monitor enablement for specific operation

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCreate(
	__inout PFLT_CALLBACK_DATA pData,
	__in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/,
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	if (g_Monitor)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (BOOLEAN_FLAG_ON(Flags, FLTFL_POST_OPERATION_DRAINING) /*No need to monitor draining*/)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (!NT_SUCCESS(pData->IoStatus.Status) || pData->IoStatus.Status == STATUS_REPARSE /* Special handling for symLinks, volume mount points, junction points etc */)
		return FLT_POSTOP_FINISHED_PROCESSING;

	PINSTANCE_CONTEXT pInstCtx = NULL;
	PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;

	__try
	{
		// Skip	PIPE MAILSLOT VOLUME_OPEN, which is set by FS driver
		if (FlagOn(pFltObjects->FileObject->Flags, FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
			return FLT_POSTOP_FINISHED_PROCESSING;

		ULONG_PTR nProcessId = (ULONG_PTR)FltGetRequestorProcessId(pData);

		FILE_STANDARD_INFORMATION FileStdInfo = {};
		UINT64 nSizeAtCreation = c_nUnknownFileSize;
		BOOLEAN fIsDirectory = FALSE;
		ULONG nRetLength = 0;

		NTSTATUS Status = FltQueryInformationFile(
			pFltObjects->Instance,
			pFltObjects->FileObject,
			&FileStdInfo,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation,
			&nRetLength);

		if (NT_SUCCESS(Status))
		{
			fIsDirectory = FileStdInfo.Directory;
			nSizeAtCreation = FileStdInfo.EndOfFile.QuadPart;
		}

		// Skip directory
		if (fIsDirectory)
			return FLT_POSTOP_FINISHED_PROCESSING;

		Status = FltGetInstanceContext(
			pFltObjects->Instance,
			(PFLT_CONTEXT*)&pInstCtx);

		if (!NT_SUCCESS(Status))
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		// Get Name Info
		(void)FltGetFileNameInformation(pData, (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT), &pNameInfo);
		if (pNameInfo != NULL)
		{
			Status = FltParseFileNameInformation(pNameInfo);
		}

		if (pNameInfo == NULL)
			return FLT_POSTOP_FINISHED_PROCESSING;

		// Allocate and fill stream handle context
		
		FltReferenceFileNameInformation(pNameInfo);
		
		STREAM_HANDLE_CONTEXT::Initialize(&pStreamHandleCtx, pFltObjects);
		
		pStreamHandleCtx->pNameInfo = pNameInfo;
		pStreamHandleCtx->nOpeningProcessId = nProcessId;
		pStreamHandleCtx->fIsDirectory = fIsDirectory;
		pStreamHandleCtx->nSizeAtCreation = nSizeAtCreation;

		FltReferenceContext(pInstCtx); // Add reference due to the stream ctx use
		pStreamHandleCtx->pInstCtx = pInstCtx;

		// Creation parameters
		ACCESS_MASK DesiredAccess = pData->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
		ULONG CreationOptions = pData->Iopb->Parameters.Create.Options & 0xFFFFFF;

		pStreamHandleCtx->fDeleteOnClose = BOOLEAN_FLAG_ON(CreationOptions, FILE_DELETE_ON_CLOSE);
		pStreamHandleCtx->fIsExecute =
			!FlagOn(CreationOptions, FILE_DIRECTORY_FILE) &&
			FlagOn(DesiredAccess, FILE_EXECUTE) &&
			!FlagOn(DesiredAccess, FILE_WRITE_DATA) &&
			!FlagOn(DesiredAccess, FILE_READ_EA);

		// Fill creation status
		switch (pData->IoStatus.Information)
		{
			case FILE_SUPERSEDED:
			case FILE_OVERWRITTEN:
				pStreamHandleCtx->eCreationStatus = FILE_CREATION_STATUS::TRUNCATED;
			case FILE_OPENED:
				pStreamHandleCtx->eCreationStatus = FILE_CREATION_STATUS::OPENED;
				break;
			case FILE_CREATED:
				pStreamHandleCtx->eCreationStatus = FILE_CREATION_STATUS::CREATED;
				break;
			default:
				pStreamHandleCtx->eCreationStatus = FILE_CREATION_STATUS::OPENED;
		}

		if (!pStreamHandleCtx->fSkipItem)
		{
			// Detect Write sequence
			if (pStreamHandleCtx->nSizeAtCreation == 0)
			{
				// Files size 0
				pStreamHandleCtx->SequenceWriteInfo.fEnabled = TRUE;
			}

			pStreamHandleCtx->SequenceReadInfo.fEnabled = TRUE;

			SendFileEventNoResponse(kEventType::FileCreate, pStreamHandleCtx);
			// TODO:: LOG
		}

	}
	__finally
	{
		if (pInstCtx != NULL)
			FltReleaseContext(pInstCtx);
		if (pStreamHandleCtx != NULL)
			FltReleaseContext(pStreamHandleCtx);
		if (pNameInfo != NULL)
			FltReleaseFileNameInformation(pNameInfo);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreCleanup(
	_Inout_ PFLT_CALLBACK_DATA /*pData*/,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_Monitor)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
	NTSTATUS Status = FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);
	if (!NT_SUCCESS(Status) || pStreamHandleCtx == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	BOOLEAN fSkipItem = pStreamHandleCtx->fSkipItem;
	FltReleaseContext(pStreamHandleCtx);

	FLT_PREOP_CALLBACK_STATUS Ret;
	if (fSkipItem)
		Ret = FLT_PREOP_SUCCESS_NO_CALLBACK;
	else
		Ret = FLT_PREOP_SYNCHRONIZE;

	return Ret;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCleanup(
	__inout PFLT_CALLBACK_DATA pData,
	__in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/,
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	if (!g_Monitor ||
		FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
		!NT_SUCCESS(pData->IoStatus.Status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	NTSTATUS Status = STATUS_SUCCESS;
	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;

	__try
	{
		Status = FltGetStreamHandleContext(
			pFltObjects->Instance,
			pFltObjects->FileObject,
			(PFLT_CONTEXT*)&pStreamHandleCtx);

		if (pStreamHandleCtx == NULL)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		BOOLEAN fFileWasDeleted = FALSE;
		if (pStreamHandleCtx->fDeleteOnClose ||
			pStreamHandleCtx->fDispositionDelete)
		{
			fFileWasDeleted = TRUE;
		}

		if (pStreamHandleCtx->SequenceWriteInfo.fEnabled)
		{
			// TODO:: Improve logic
			SendFileEventNoResponse(kEventType::FileDataWrite, pStreamHandleCtx);
		}

		if (pStreamHandleCtx->SequenceReadInfo.fEnabled)
		{
			// TODO:: Improve logic
			SendFileEventNoResponse(kEventType::FileDataRead, pStreamHandleCtx);
		}

		if (pStreamHandleCtx->fDirty && !fFileWasDeleted)
		{
			SendFileEventNoResponse(kEventType::FileDataChange, pStreamHandleCtx);
		}

		if (pStreamHandleCtx->eCreationStatus != FILE_CREATION_STATUS::CREATED && fFileWasDeleted)
		{
			SendFileEventNoResponse(kEventType::FileDelete, pStreamHandleCtx);
		}


		SendFileEventNoResponse(kEventType::FileClose, pStreamHandleCtx);
		// TODO:: LOG

	}
	__finally
	{
		if (pStreamHandleCtx != NULL)
			FltReleaseContext(pStreamHandleCtx);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}



// Mainly monitor delete attempts
FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreSetFileInfo(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_Monitor)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// If not delete, skip
	FILE_INFORMATION_CLASS InfoClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;
	if (InfoClass != FileDispositionInformation &&
		InfoClass != FileDispositionInformationEx)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// If no context skip post op
	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
	NTSTATUS Status = FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);
	if (!NT_SUCCESS(Status))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	BOOLEAN SkipItem = pStreamHandleCtx->fSkipItem;
	FltReleaseContext((PFLT_CONTEXT)pStreamHandleCtx);

	if (SkipItem)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostSetFileInfo(
	__inout PFLT_CALLBACK_DATA pData,
	__in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/,
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	if (!g_Monitor ||
		FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
		!NT_SUCCESS(pData->IoStatus.Status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;

	__try
	{

		// Get stream ctx handle
		NTSTATUS Status = FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);
		if (pStreamHandleCtx == NULL)
			return FLT_POSTOP_FINISHED_PROCESSING;

		// Set delete information
		FILE_INFORMATION_CLASS InfoClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;
		if (InfoClass == FileDispositionInformation)
		{
			pStreamHandleCtx->fDispositionDelete =
				((PFILE_DISPOSITION_INFORMATION)(pData->Iopb->Parameters.SetFileInformation.InfoBuffer))->DeleteFile;
		}
		else if (InfoClass == FileDispositionInformationEx)
		{
			ULONG TempFlags = ((PFILE_DISPOSITION_INFORMATION_EX)(pData->Iopb->Parameters.SetFileInformation.InfoBuffer))->Flags;

			if (FlagOn(TempFlags, FILE_DISPOSITION_ON_CLOSE))
				pStreamHandleCtx->fDeleteOnClose = BOOLEAN_FLAG_ON(TempFlags, FILE_DISPOSITION_DELETE);
			else
				pStreamHandleCtx->fDispositionDelete = BOOLEAN_FLAG_ON(TempFlags, FILE_DISPOSITION_DELETE);
		}
	}
	__finally
	{
		if (pStreamHandleCtx != NULL)
			FltReleaseContext(pStreamHandleCtx);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
	FLTAPI
	PreWrite(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_Monitor)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// At IRQLs above APC_LEVEL (i.e., at DISPATCH_LEVEL or higher), 
	// you cannot safely access pageable memory, 
	// perform certain synchronization, or call many system routines
	if (KeGetCurrentIrql() > APC_LEVEL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
	NTSTATUS Status = FltGetStreamContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);
	if (!NT_SUCCESS(Status) || pStreamHandleCtx == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//TODO:: Check if should skip write item

	auto& WriteParams = pData->Iopb->Parameters.Write;

	BOOLEAN fShouldPost = FALSE;

	do
	{
		auto& Info = pStreamHandleCtx->SequenceWriteInfo;

		if (!Info.fEnabled)
			break;

		if (WriteParams.Length == 0)
			break;

		UINT64 WritePos =
			(WriteParams.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
				WriteParams.ByteOffset.HighPart == -1) ?
			pFltObjects->FileObject->CurrentByteOffset.QuadPart :
			WriteParams.ByteOffset.QuadPart;

		if (WritePos != Info.nNextPos)
		{
			Info.fEnabled = FALSE;
			break;
		}

		fShouldPost = TRUE;

	} while (FALSE);

	if (!pStreamHandleCtx->fDirty)
		fShouldPost = TRUE;

	FltReleaseContext(pStreamHandleCtx);

	if (!fShouldPost)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS
	FLTAPI
	PostWrite(
		__inout PFLT_CALLBACK_DATA pData,
		__in PCFLT_RELATED_OBJECTS pFltObjects,
		__in_opt PVOID /*pCompletionContext*/,
		__in FLT_POST_OPERATION_FLAGS Flags)
{
	if (!g_Monitor)
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
		return FLT_POSTOP_FINISHED_PROCESSING;

	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
	__try
	{
		NTSTATUS Status = FltGetStreamContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);
		if (!NT_SUCCESS(Status) || pStreamHandleCtx == NULL)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		//TODO:: LOG

		// If any bytes was written
		if (NT_SUCCESS(pData->IoStatus.Status))
		{
			pStreamHandleCtx->fDirty = TRUE;
			// Disable detect sequence read
			pStreamHandleCtx->SequenceReadInfo.fEnabled = FALSE;
		}

		// Sequence action detection
		do
		{
			auto& Info = pStreamHandleCtx->SequenceWriteInfo;

			if (!Info.fEnabled)
				break;

			// Operation failed
			if (!NT_SUCCESS(pData->IoStatus.Status))
			{
				Info.fEnabled = FALSE;
				break;
			}


			// TODO:: Write operation we should update the file hash


		} while (FALSE);

	}
	__finally
	{
		if (pStreamHandleCtx != NULL)
			FltReleaseContext(pStreamHandleCtx);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreRead(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_Monitor) 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (KeGetCurrentIrql() > APC_LEVEL) 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// if no context - skip post operation
	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
	NTSTATUS ns = FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);
	if (!NT_SUCCESS(ns) || pStreamHandleCtx == NULL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// TODO:: Skipping by rules

	if(pStreamHandleCtx->fSkipItem)
	{
		FltReleaseContext(pStreamHandleCtx);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	auto& ReadParams = pData->Iopb->Parameters.Read;

	// postRead is necessary (checking of operation success) 
	BOOLEAN fPostIsNecessary = false;

	do
	{
		SEQUENCE_ACTION& info = pStreamHandleCtx->SequenceReadInfo;
		if (!info.fEnabled)
			break;

		// not interesting action
		if (ReadParams.Length == 0)
			break;

		// getting reading pos from parameters or current file pos
		UINT64 nReadPos =
			(ReadParams.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION
		     && ReadParams.ByteOffset.HighPart == -1) ?
			pFltObjects->FileObject->CurrentByteOffset.QuadPart :
			ReadParams.ByteOffset.QuadPart;

		// check read position
		if (nReadPos != info.nNextPos)
		{
			info.fEnabled = FALSE;
			break;
		}

		fPostIsNecessary = TRUE;

	} while (false);

	FltReleaseContext(pStreamHandleCtx);
	return fPostIsNecessary ? FLT_PREOP_SYNCHRONIZE : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostRead(
	__inout PFLT_CALLBACK_DATA pData,
	__in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/,
	__in FLT_POST_OPERATION_FLAGS Flags)
{

	if (!g_Monitor)
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
		return FLT_POSTOP_FINISHED_PROCESSING;

	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
	__try
	{
		NTSTATUS Status = FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);
		if (!NT_SUCCESS(Status) || pStreamHandleCtx == NULL)
			return FLT_POSTOP_FINISHED_PROCESSING;

		// TODO::LOG

		do {

			SEQUENCE_ACTION& Info = pStreamHandleCtx->SequenceReadInfo;

			if (!Info.fEnabled)
				break;

			if (!NT_SUCCESS(Status))
			{
				Info.fEnabled = FALSE;
			}

			// TODO::Update Hash

		} while (FALSE);

	}
	__finally
	{
		if (pStreamHandleCtx != NULL)
			FltReleaseContext(pStreamHandleCtx);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS
SendFileEventNoResponse(
	kEventType EventType,
	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx)
{
	FILE_EVENT kFileEvent;
	RtlZeroMemory(&kFileEvent, sizeof(FILE_EVENT));

	PINSTANCE_CONTEXT pInstCtx = pStreamHandleCtx->pInstCtx;

	kFileEvent.Header.EventType = EventType;
	kFileEvent.Header.TickTime = getTickCount64();
	kFileEvent.Header.ProcessId = pStreamHandleCtx->nOpeningProcessId;

	RtlCopyMemory(kFileEvent.FilePath, pStreamHandleCtx->pNameInfo->Name.Buffer, pStreamHandleCtx->pNameInfo->Name.Length);
	RtlCopyMemory(kFileEvent.FileVolumeGuid, pInstCtx->usVolumeGuid.Buffer, pInstCtx->usVolumeGuid.Length);
	RtlCopyMemory(kFileEvent.FileVolumeType, ConvertDriverTypeToString(pInstCtx->DriverType), EVENT_TYPE_WCHAR_LENGTH);

	if (pInstCtx->usDeviceName.Length != 0)
		RtlCopyMemory(kFileEvent.FileVolumeDevice, pInstCtx->usDeviceName.Buffer, pInstCtx->usDeviceName.Length);

	if (EventType == kEventType::FileDataRead && pStreamHandleCtx->SequenceReadInfo.fEnabled)
		BytesToHexString(pStreamHandleCtx->SequenceReadInfo.HashedData, 32, kFileEvent.FileRawHash);

	if (EventType == kEventType::FileDataWrite && pStreamHandleCtx->SequenceWriteInfo.fEnabled)
		BytesToHexString(pStreamHandleCtx->SequenceWriteInfo.HashedData, 32, kFileEvent.FileRawHash);

	// TODO:: Change to use queue and workers
	LARGE_INTEGER Timeout = {};
	Timeout.QuadPart =
		(LONGLONG)c_nSendMsgTimeout *
		(LONGLONG)1000 /*micro*/ *
		(LONGLONG)10 /*nano*/ *
		(LONGLONG)-1;

	NTSTATUS Status = STATUS_SUCCESS;
	Status = FltSendMessage(g_pFilter, &g_pClientPort, (PVOID)&kFileEvent, sizeof(FILE_EVENT), NULL, NULL, &Timeout);

	return Status;
}

NTSTATUS
UpdateHash(
	PSTREAM_HANDLE_CONTEXT pStreamHandleCtx,
	PFLT_CALLBACK_DATA pData,
	kEventType EventType /*Operation Read or Write*/
)
{
	auto& ReadParams = pData->Iopb->Parameters.Read;
	auto& WriteParams = pData->Iopb->Parameters.Write;

	SEQUENCE_ACTION& ActionInfo = EventType == kEventType::FileDataRead ? pStreamHandleCtx->SequenceReadInfo : pStreamHandleCtx->SequenceWriteInfo;

	SIZE_T DataSize = pData->IoStatus.Information;

	PMDL pHeadMdl = (EventType == kEventType::FileDataRead) ? ReadParams.MdlAddress : WriteParams.MdlAddress;


	// Direct IO
	if (pHeadMdl != NULL)
	{
		SIZE_T RestDataSize = DataSize;
		for (PMDL pCurrMdl = pHeadMdl; pCurrMdl != NULL && RestDataSize != 0; pCurrMdl = pCurrMdl->Next)
		{
			PVOID pDataBuffer = MmGetSystemAddressForMdlSafe(pCurrMdl, NormalPagePriority | MdlMappingNoExecute);
			if (pDataBuffer == NULL)
			{
				return STATUS_INVALID_PARAMETER_3;
			}

			SIZE_T nCurrMdlDataSize = min(MmGetMdlByteCount(pCurrMdl), RestDataSize);

		}
	}
}

NTSTATUS GetDiskPdoName(PDEVICE_OBJECT pVolumeDeviceObject, UNICODE_STRING* pDst,
	PVOID* ppBuffer)
{
	PDEVICE_OBJECT pStoragePdo = nullptr;
	__try
	{
		GetVolumeObject(pVolumeDeviceObject, &pStoragePdo);

		UNICODE_STRING usPdoName;
		UINT8 Buffer[0x400] = {};
		usPdoName.Buffer = (PWCH)Buffer;
		usPdoName.MaximumLength = sizeof(Buffer);
		usPdoName.Length = 0;
		GetDeviceName(pStoragePdo, &usPdoName);
		CloneUnicodeString(&usPdoName, pDst, ppBuffer);
	}
	__finally
	{
		if (pStoragePdo != nullptr)
			ObDereferenceObject(pStoragePdo);
	}

	return STATUS_SUCCESS;
}

NTSTATUS
CollectUsbInfo(
		PCFLT_RELATED_OBJECTS pFltObjects,
		PINSTANCE_CONTEXT pInCtx)
{
	PDEVICE_OBJECT pDiskDeviceObj = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	__try
	{
		// Get the device object
		Status = FltGetDiskDeviceObject(pFltObjects->Volume, &pDiskDeviceObj);
		if (!NT_SUCCESS(Status) || !pDiskDeviceObj)
		{
			return STATUS_UNSUCCESSFUL; // Failed to get disk device object
		}

		CHAR Buffer[512];
		PSTORAGE_DEVICE_DESCRIPTOR pDeviceDescriptor = (PSTORAGE_DEVICE_DESCRIPTOR)&Buffer[0];

		STORAGE_PROPERTY_QUERY PropertyQuery;
		PropertyQuery.PropertyId = StorageDeviceProperty;
		PropertyQuery.QueryType = PropertyStandardQuery;
		Status = KDeviceIoControl(
			pDiskDeviceObj, /*Send IOCTL to the Device handling this volume*/
			IOCTL_STORAGE_QUERY_PROPERTY,
			&PropertyQuery,
			sizeof(PropertyQuery),
			pDeviceDescriptor,
			sizeof(pDeviceDescriptor));
		if (!NT_SUCCESS(Status))
		{
			// Cant get the device descriptor for this volume
			return STATUS_SUCCESS;
		}

		// Check if the device is USB
		if (pDeviceDescriptor->BusType != BusTypeUsb)
		{
			return STATUS_SUCCESS; // Not USB device
		}

		// USB device detected
		pInCtx->fIsUsb = TRUE;

		Status = GetDiskPdoName(
			pDiskDeviceObj,
			&pInCtx->usDiskPdoName,
			(PVOID*)&pInCtx->pDiskPdoBuffer);
		if (!NT_SUCCESS(Status))
		{
			return Status; // Failed to get disk PDO name
		}


		// Get the container ID
		Status =  GetContainerId(
			pDiskDeviceObj,
			&pInCtx->usContainerId,
			(PVOID*) & pInCtx->pDeviceNameBuffer);

		if (!NT_SUCCESS(Status))
		{
			return Status; // Failed to get container ID
		}

	}
	__finally
	{
		if (pDiskDeviceObj)
		{
			ObDereferenceObject(pDiskDeviceObj); // Dereference the disk device object
		}
	}

	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Meta data for the file event
//////////////////////////////////////////////////////////////////////////

LARGE_INTEGER
GetCurrentTimeStamp()
{
	LARGE_INTEGER ts;
	KeQuerySystemTimePrecise(&ts);
	return ts;
}


NTSTATUS GetNormalizedFilePath(
	PFLT_CALLBACK_DATA pData,
	PCFLT_RELATED_OBJECTS pFltObjects,
	PUNICODE_STRING pNormalizedPath
)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION pNameInfo;

	status = FltGetFileNameInformation(
		pData,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		&pNameInfo
	);

	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(pNameInfo);
		if (NT_SUCCESS(status)) {
			*pNormalizedPath = pNameInfo->Name;
		}
		FltReleaseFileNameInformation(pNameInfo);
	}
	return status;
}


NTSTATUS
QueryFileSize(
	PFLT_INSTANCE pInstance,
	PFILE_OBJECT pFileObject,
	PULONGLONG pFileSize
)
{
	NTSTATUS Status;
	FILE_STANDARD_INFORMATION FileInfo = { 0 };

	Status = FltQueryInformationFile(
		pInstance,
		pFileObject,
		&FileInfo,
		sizeof(FileInfo),
		FileStandardInformation,
		NULL
	);

	if (NT_SUCCESS(Status)) {
		*pFileSize = FileInfo.EndOfFile.QuadPart;
	}

	return Status;
}

ULONG
GetRequestorProcessId(
	PFLT_CALLBACK_DATA pData
)
{
	return FltGetRequestorProcessId(pData);
}

NTSTATUS
GetRenameTargetPath(
	PFLT_CALLBACK_DATA pData,
	PUNICODE_STRING pTargetName
)
{
	if (!pData || !pTargetName)
		return STATUS_INVALID_PARAMETER;
	
	if (pData->Iopb->Parameters.SetFileInformation.FileInformationClass != FileRenameInformation &&
		pData->Iopb->Parameters.SetFileInformation.FileInformationClass != FileRenameInformationEx)
	{
		return STATUS_INVALID_PARAMETER;
	}

	PFILE_RENAME_INFORMATION RenameInfo = (PFILE_RENAME_INFORMATION)pData->Iopb->Parameters.SetFileInformation.InfoBuffer;

	if (!RenameInfo || RenameInfo->FileNameLength == 0)
		return STATUS_INVALID_PARAMETER;

	pTargetName->Length = (USHORT)RenameInfo->FileNameLength;
	pTargetName->MaximumLength = pTargetName->Length;
	pTargetName->Buffer = RenameInfo->FileName;

	return STATUS_SUCCESS;
}
VOID
ExtractCreateParameters(
	PFLT_CALLBACK_DATA Data,
	ACCESS_MASK* DesiredAccess,
	ULONG* CreateDisposition,
	ULONG* CreateOptions,
	ULONG* FileAttributes,
	ULONG* ShareAccess
)
{
	*DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	*CreateOptions = Data->Iopb->Parameters.Create.Options & 0xFFFFFFF0;
	*CreateDisposition = Data->Iopb->Parameters.Create.Options & 0x0000000F;
	*FileAttributes = Data->Iopb->Parameters.Create.FileAttributes;
	*ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
}

VOID
DebugPrintAccessMask(ACCESS_MASK access)
{
	if (access & GENERIC_READ) DbgPrint("  GENERIC_READ\n");
	if (access & GENERIC_WRITE) DbgPrint("  GENERIC_WRITE\n");
	if (access & GENERIC_EXECUTE) DbgPrint("  GENERIC_EXECUTE\n");
	if (access & DELETE) DbgPrint("  DELETE\n");
	if (access & FILE_READ_DATA) DbgPrint("  FILE_READ_DATA\n");
	if (access & FILE_WRITE_DATA) DbgPrint("  FILE_WRITE_DATA\n");
	if (access & FILE_EXECUTE) DbgPrint("  FILE_EXECUTE\n");
}