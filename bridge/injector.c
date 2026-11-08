#define WIN32_LEAN_AND_MEAN
#include "credential_control.h"
#include "credential_runtime.h"
#include "credential_bundle.h"
#include "credential_environment.h"
#include "inject.h"
#include <stdlib.h>
int credential_inject_main(const WCHAR *pid_text, BOOL install,
                           const WCHAR *log_path) {
  if (!pid_text || !*pid_text)
    return ERROR_INVALID_PARAMETER;
  for (const WCHAR *digit = pid_text; *digit; ++digit)
    if (*digit < L'0' || *digit > L'9')
      return ERROR_INVALID_PARAMETER;
  WCHAR *end;
  unsigned long long parsed = _wcstoui64(pid_text, &end, 10);
  if (!parsed || *end || parsed > MAXDWORD)
    return ERROR_INVALID_PARAMETER;
  if (install) {
    int environment_error = credential_require_winpe();
    if (environment_error)
      return environment_error;
  }
  DWORD pid = (DWORD)parsed;
  DWORD log_error = credential_log_prepare(log_path);
  if (log_error)
    return (int)log_error;
  WCHAR dll[MAX_PATH];
  DWORD preparation = credential_bundle_prepare(NULL, NULL, dll);
  if (preparation)
    return (int)preparation;
  DWORD result = inject_bridge(pid, NULL, dll, install, log_path);
  credential_log(log_path, install ? L"attach" : L"detach", pid, result, 0);
  return (int)result;
}
