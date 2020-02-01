// Copyright 2020 Bill Ticehurst. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file

#pragma once

#include <cstdint>

#if !defined(__cplusplus)
#error Must be compiled for C++
#endif

#if !defined(_MSC_VER) && !defined(__clang__)
#error Must be compiled with MSVC or Clang
#endif

// Clang will set __POINTER_WIDTH__, MSVC defines _WIN64 for 64-bit targets.
#if (__POINTER_WIDTH__ == 64) || defined(_WIN64)
static_assert(sizeof(uintptr_t) == 8);
#else
static_assert(sizeof(uintptr_t) == 4);
#endif
