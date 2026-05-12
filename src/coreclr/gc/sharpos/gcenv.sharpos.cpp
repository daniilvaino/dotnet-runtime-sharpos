// gc/sharpos/gcenv.sharpos.cpp
//
// SharpOS GCToOSInterface implementation. Phase 6.1: route на Win32 API
// (HOST_WINDOWS). Phase 6.2: replace with SharpOS kernel mm subsystem calls.
//
// References:
//   - gc/windows/gcenv.windows.cpp — Win32 implementation pattern
//   - gc/env/gcenv.os.h — interface declaration
//   - work/PAL/CORECLR_PORT_WINAPI_DEBT.md — debt tracking

// Include order matches gc/windows/gcenv.windows.cpp — windows.h первым,
// потом gcenv headers (otherwise typedef redefinition uint32_t/int32_t).
#include <cstdint>
#include <cstddef>
#include <cassert>
#include "windows.h"
#include "gcenv.structs.h"
#include "gcenv.base.h"
#include "gcenv.os.h"

// VirtualReserve flags bit values mirror gc/windows/gcenv.windows.cpp.
namespace
{
    constexpr uint32_t kWriteWatchFlag = 0x1;
}

void* GCToOSInterface::VirtualReserve(size_t size, size_t alignment, uint32_t flags, uint16_t /*node*/)
{
    DWORD memFlags = (flags & kWriteWatchFlag) ? (MEM_RESERVE | MEM_WRITE_WATCH) : MEM_RESERVE;
    if (alignment == 0)
    {
        return ::VirtualAlloc(nullptr, size, memFlags, PAGE_READWRITE);
    }
    // Aligned reserve: over-allocate and round.
    SIZE_T reserveSize = size + alignment;
    void* base = ::VirtualAlloc(nullptr, reserveSize, memFlags, PAGE_READWRITE);
    if (base == nullptr) return nullptr;
    uintptr_t aligned = ((uintptr_t)base + alignment - 1) & ~(uintptr_t)(alignment - 1);
    return (void*)aligned;
}

bool GCToOSInterface::VirtualRelease(void* address, size_t /*size*/)
{
    return ::VirtualFree(address, 0, MEM_RELEASE) != FALSE;
}

bool GCToOSInterface::VirtualCommit(void* address, size_t size, uint16_t /*node*/)
{
    return ::VirtualAlloc(address, size, MEM_COMMIT, PAGE_READWRITE) != nullptr;
}

bool GCToOSInterface::VirtualDecommit(void* address, size_t size)
{
    return ::VirtualFree(address, size, MEM_DECOMMIT) != FALSE;
}

uint32_t GCToOSInterface::GetTotalProcessorCount()
{
    SYSTEM_INFO si;
    ::GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}

bool GCToOSInterface::CanEnableGCCPUGroups()
{
    return false;
}

bool GCToOSInterface::ParseGCHeapAffinitizeRangesEntry(const char**, size_t*, size_t*)
{
    return false;
}

int64_t GCToOSInterface::QueryPerformanceFrequency()
{
    LARGE_INTEGER freq;
    ::QueryPerformanceFrequency(&freq);
    return freq.QuadPart;
}

int64_t GCToOSInterface::QueryPerformanceCounter()
{
    LARGE_INTEGER count;
    ::QueryPerformanceCounter(&count);
    return count.QuadPart;
}

bool GCToOSInterface::SupportsWriteWatch()
{
    void* mem = VirtualReserve(0x1000, 0, kWriteWatchFlag, 0);
    if (mem)
    {
        VirtualRelease(mem, 0x1000);
        return true;
    }
    return false;
}
