//
// minmax_trap.h
//
// Force-included (g++ -include) by the IP lists workflow. windows.h, which the
// MFC build includes without NOMINMAX, defines function-like min and max macros
// that break any std::min( or std::max( call in a header. libstdc++ #undefs both
// in c++config.h, so a -D on the command line is silently lost; instead this
// file includes the standard headers first and then defines the macros, the way
// they stand when StdAfx.h has included windows.h.
//

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

#define min(a, b) MIN_MACRO_COLLISION
#define max(a, b) MAX_MACRO_COLLISION
