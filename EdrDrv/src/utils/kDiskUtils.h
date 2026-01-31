#pragma once
//#include <Ntddstor.h>
#include <fltKernel.h>
#include <ntddk.h>
#include <bcrypt.h>

typedef unsigned char BYTE;

typedef struct _DISK_EXTENT
{
	//
	// Specifies the storage device number of
	// the disk on which this extent resides.
	//
	ULONG DiskNumber;

	//
	// Specifies the offset and length of this
	// extent relative to the beginning of the
	// disk.
	//
	LARGE_INTEGER StartingOffset;
	LARGE_INTEGER ExtentLength;

} DISK_EXTENT, * PDISK_EXTENT;

//
//
//
typedef struct _VOLUME_DISK_EXTENTS {

	//
	// Specifies one or more contiguous range
	// of sectors that make up this volume.
	//
	ULONG NumberOfDiskExtents;
	DISK_EXTENT Extents[ANYSIZE_ARRAY];

} VOLUME_DISK_EXTENTS, * PVOLUME_DISK_EXTENTS;

#define IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS CTL_CODE(0x00000056, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS
GetVolumeObject(
	PDEVICE_OBJECT pVolumeDeviceObject,
	PDEVICE_OBJECT* ppDiskPhysicalDeviceObject
);

NTSTATUS
GetContainerId(
	PDEVICE_OBJECT pVolumeDeviceObject,
	UNICODE_STRING* pDst,
	PVOID* ppBuffer);

//	Compute Hash
NTSTATUS
ComputeHash(
	PUCHAR Data,
	ULONG DataSize,
	PUCHAR HashOutput);

NTSTATUS GetDeviceName(PDEVICE_OBJECT pDeviceObject, PUNICODE_STRING pusResultPdoName);