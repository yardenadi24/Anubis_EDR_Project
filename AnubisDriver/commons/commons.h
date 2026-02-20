#pragma once
#include <ntifs.h>
#include "shared_commons.h"

#define DRIVER_PREFIX "Anubis_Driver: "
#define EDR_MEMORY_TAG 'sbnA'

#define DbgPrintln(s,...) DbgPrint(DRIVER_PREFIX "[%s] " s "\n",__FUNCTION__ ,__VA_ARGS__)
#define DbgError(s,...) DbgPrintln("<Error> " s , __VA_ARGS__)
#define DbgWarning(s,...) DbgPrintln("<Warning> " s , __VA_ARGS__)
#define DbgInfo(s,...) DbgPrintln("<Info> " s , __VA_ARGS__)

#define BOOLEAN_ALL_FLAG_ON(Mask, Flags) (((Mask) & (Flags)) == (Flags))
#define BOOLEAN_FLAG_ON(Mask, Flags) (((Mask) & (Flags)) != 0)

#define STATIC_UNICODE_STRING(name, str) \
	static UNICODE_STRING name = RTL_CONSTANT_STRING(str);

STATIC_UNICODE_STRING(cUnkownUnicodeString, L"UNKNOWN");
