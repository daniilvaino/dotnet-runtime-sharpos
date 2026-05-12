// pal/sharpos/include/strings.h
//
// POSIX <strings.h> shim для TARGET_SHARPOS build на Windows host (MSVC).
// MSVC не имеет strings.h. pal/inc/pal.h includes <strings.h> when
// TARGET_UNIX defined.
//
// MINIMAL VERSION: empty (just `#include <string.h>` for size_t).
// Function remappings (strcasecmp → _stricmp etc.) done explicitly где
// они used в pal/sharpos/ implementation files. Global macros ломают
// MSVC's C++ STL headers.

#ifndef _SHARPOS_STRINGS_H
#define _SHARPOS_STRINGS_H

#include <string.h>

#endif // _SHARPOS_STRINGS_H
