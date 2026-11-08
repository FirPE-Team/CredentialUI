#ifndef CREDENTIAL_BUNDLE_H
#define CREDENTIAL_BUNDLE_H
#include <windows.h>
#define CREDENTIAL_BRIDGE_RESOURCE 201
/* NULL image/source selects this executable. Explicit arguments allow tests to
 * inspect a shipped EXE loaded as a data resource, without executing it. */
DWORD credential_bundle_prepare(HMODULE image, const WCHAR *source,
                                WCHAR dll[MAX_PATH]);
#endif
