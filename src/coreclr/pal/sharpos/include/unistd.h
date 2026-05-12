// pal/sharpos/include/unistd.h
//
// POSIX <unistd.h> shim for TARGET_SHARPOS build на Windows host (MSVC).
// pal/inc/pal.h includes <unistd.h> когда TARGET_UNIX defined. MSVC не has
// этот header.
//
// MINIMAL VERSION: только types + constants. NO global macro remappings
// like `#define close _close` — те ломают MSVC's own C++ STL headers
// (<exception>, <fstream>, etc.) которые имеют methods с тем же именем.
//
// POSIX function remappings будут explicit в pal/sharpos/ implementation
// files via inline wrappers или сами вызовом _read/_write/etc.

#ifndef _SHARPOS_UNISTD_H
#define _SHARPOS_UNISTD_H

#include <sys/types.h>   // size_t

#ifdef _MSC_VER

// POSIX types
typedef int ssize_t;
typedef int pid_t;

// File descriptor constants
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

// NOTE: no function macro remappings (read, write, close, etc.) here —
// those broke MSVC's <exception> and similar. pal/sharpos/ implementation
// files that need POSIX semantics should use _read/_write/_close
// (MSVC underscore prefix variants) directly or via narrow inline wrappers.

#endif // _MSC_VER

#endif // _SHARPOS_UNISTD_H
