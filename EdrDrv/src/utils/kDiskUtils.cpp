#include "kDiskUtils.h"
#include "kOsUtils.h"
#include "kStringUtils.h"
#include <ntstrsafe.h>

NTSTATUS
GetVolumeObject(
	PDEVICE_OBJECT pVolumeDeviceObject,
	PDEVICE_OBJECT* ppDiskPhysicalDeviceObject
)
{
	 UINT8 Buffer[1024];
	 NTSTATUS Status = KDeviceIoControl(
		 pVolumeDeviceObject,
		 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
		 NULL,
		 0,
		 Buffer,
		 sizeof(Buffer));
	 if (!NT_SUCCESS(Status))
	 {
		 return Status; // Failed to get disk extents
	 }

	 PVOLUME_DISK_EXTENTS pVolumeDeviceExtent = (PVOLUME_DISK_EXTENTS)Buffer;
	 if (pVolumeDeviceExtent->NumberOfDiskExtents == 0)
	 {
		 return STATUS_UNSUCCESSFUL; // No disk extents found
	 }

	 const ULONG DiskNumber = pVolumeDeviceExtent->Extents[0].DiskNumber;
	 Status = RtlStringCbPrintfW((NTSTRSAFE_PWSTR)Buffer, sizeof(Buffer), L"\\GLOBAL??\\PhysicalDrive%d", DiskNumber);
	 if (!NT_SUCCESS(Status))
	 {
		 return Status;
	 }

	 UNICODE_STRING StrDeviceName;
	 RtlInitUnicodeString(&StrDeviceName, (NTSTRSAFE_PWSTR)Buffer);

	 PFILE_OBJECT pFileObject = NULL;
	 PDEVICE_OBJECT pDeviceObject = NULL;
	 Status = IoGetDeviceObjectPointer(
		 &StrDeviceName,
		 FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		 &pFileObject,
		 &pDeviceObject);
	 if (!NT_SUCCESS(Status))
	 {
		 return Status;
	 }

	 PDEVICE_OBJECT pLowerDevice = IoGetDeviceAttachmentBaseRef(pDeviceObject);
	 ObDereferenceObject(pFileObject);

	 *ppDiskPhysicalDeviceObject = pLowerDevice;
	 return STATUS_SUCCESS;
}

NTSTATUS
GetContainerId(
	PDEVICE_OBJECT pVolumeDeviceObject,
	UNICODE_STRING* pDst,
	PVOID* ppBuffer)
{

	UINT8 Buffer[1024];
	ULONG nResultLength = 0;

	NTSTATUS Status = IoGetDeviceProperty(
		pVolumeDeviceObject,
		DevicePropertyContainerID,
		sizeof(Buffer),
		&Buffer,
		&nResultLength);

	UNICODE_STRING usContainerId;
	RtlInitUnicodeString(&usContainerId, (WCHAR*)Buffer);

	Status = CloneUnicodeString(
		&usContainerId,
		pDst,
		ppBuffer);

	if (!NT_SUCCESS(Status))
	{
		return Status; // Failed to clone the container ID string
	}
	
	return STATUS_SUCCESS;
}



//	Compute Hash
NTSTATUS
ComputeHash(
	PUCHAR Data,
	ULONG DataSize,
	PUCHAR HashOutput)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	NTSTATUS status;

	// Open algorithm provider
	status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_SHA256_ALGORITHM,  // or SHA1, MD5, SHA384, SHA512
		NULL,
		0
	);

	// Create hash object
	if (NT_SUCCESS(status)) {
		status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
	}

	// Hash the data
	if (NT_SUCCESS(status)) {
		status = BCryptHashData(hHash, Data, DataSize, 0);
	}

	// Get the hash result
	if (NT_SUCCESS(status)) {
		status = BCryptFinishHash(hHash, HashOutput, 32, 0); // 32 for SHA256
	}

	// Cleanup
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

	return status;
}

NTSTATUS GetDeviceName(PDEVICE_OBJECT pDeviceObject, PUNICODE_STRING pusResultPdoName)
{
	UINT8 Buffer[0x400];

	//
	// Way 1: IoGetDeviceProperty
	//
	ULONG nResultLength = 0;
	*(WCHAR*)Buffer = 0;
	NTSTATUS ns = IoGetDeviceProperty(pDeviceObject,
		DevicePropertyPhysicalDeviceObjectName, ARRAYSIZE(Buffer), &Buffer, &nResultLength);
	if (NT_SUCCESS(ns))
	{
		UNICODE_STRING usPdoName;
		RtlInitUnicodeString(&usPdoName, (const WCHAR*)Buffer);
		RtlUnicodeStringCopy(pusResultPdoName, &usPdoName);
		return STATUS_SUCCESS;
	}

	//
	// Way 2: ObQueryNameString
	//
	auto pObjectNameInfo = (POBJECT_NAME_INFORMATION)&Buffer[0];
	pObjectNameInfo->Name.MaximumLength = 0;
	pObjectNameInfo->Name.Length = 0;

	ULONG nSize = 0;
	ns = ObQueryNameString(pDeviceObject, pObjectNameInfo, sizeof(Buffer), &nSize);
	if (NT_SUCCESS(ns))
	{
		RtlUnicodeStringCopy(pusResultPdoName, &pObjectNameInfo->Name);
		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}