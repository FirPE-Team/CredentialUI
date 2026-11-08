#ifndef CREDENTIAL_RUNTIME_H
#define CREDENTIAL_RUNTIME_H
#include <windows.h>
/* Empty mode starts the manager; --status and --stop control it. */
int credential_host_main(const WCHAR *mode, const WCHAR *log_path);
int credential_inject_main(const WCHAR *pid_text, BOOL install,
                           const WCHAR *log_path);
#endif
