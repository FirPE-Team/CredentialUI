#ifndef CREDENTIAL_ENVIRONMENT_H
#define CREDENTIAL_ENVIRONMENT_H
#include <windows.h>
BOOL credential_is_winpe(void);
int credential_require_winpe(void);
#endif
