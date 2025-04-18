#pragma once
#include <ntifs.h>
#include "SharedCommons.h"

#define DRIVER_PREFIX "Anubis_Driver: "

#define EDR_MEMORY_TAG 'sbnA'

#define DbgPrintln(s,...) DbgPrint(DRIVER_PREFIX "[%s] " s "\n",__FUNCTION__ ,__VA_ARGS__)

#define DbgError(s,...) DbgPrintln("<Error> " s , __VA_ARGS__)
#define DbgInfo(s,...) DbgPrintln("<Info> " s , __VA_ARGS__)
