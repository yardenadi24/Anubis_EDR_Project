#pragma once
#include <fltKernel.h>

inline
NTSTATUS
CloneUnicodeString(
	PCUNICODE_STRING pSrc, 
	UNICODE_STRING* pDst, 
	PVOID* ppBuffer)
{
	const USHORT StrBufferSize = pSrc->Length + sizeof(WCHAR);
	PVOID pStrBuffer = ExAllocatePoolWithTag(NonPagedPool, StrBufferSize, 'rtsc');
	if (pStrBuffer == nullptr)
	{
		return STATUS_NO_MEMORY; 
	}

	memcpy(pStrBuffer, pSrc->Buffer, pSrc->Length);
	// Add zero end
	((UINT8*)pStrBuffer)[pSrc->Length] = 0;
	((UINT8*)pStrBuffer)[pSrc->Length + 1] = 0;

	pDst->Buffer = (PWCH)pStrBuffer;
	pDst->Length = pSrc->Length;
	pDst->MaximumLength = StrBufferSize;

	*ppBuffer = pStrBuffer;
	return STATUS_SUCCESS;
}

VOID BytesToHexString(
	_In_reads_bytes_(Length) PUCHAR Bytes,
	_In_ ULONG Length,
	_Out_writes_(Length * 2 + 1) PCHAR HexString
)
{
	ULONG i;
	static const CHAR HexChars[] = "0123456789abcdef";

	for (i = 0; i < Length; i++) {
		// For example Byte = 0xA7
		HexString[i * 2] = HexChars[Bytes[i] >> 4]; // Takes 0xA
		HexString[i * 2 + 1] = HexChars[Bytes[i] & 0xF]; // Takes 0x7
	}
	HexString[Length * 2] = '\0';
}