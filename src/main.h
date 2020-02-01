// Copyright 2020 Bill Ticehurst. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file

#pragma once

#include <string>

// File type
const char* PE_X86     = "PE-X86";
const char* PE_AMD64   = "PE-AMD64";
const char* PE_ARM64   = "PE-ARM64";
const char* COFF_X86   = "COFF-X86";
const char* COFF_AMD64 = "COFF-AMD64";
const char* COFF_ARM64 = "COFF-ARM64";
const char* LIB  = "LIB";

std::string GetFileType(uintptr_t file_addr, size_t size);
