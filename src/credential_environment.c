#define WIN32_LEAN_AND_MEAN
#include "credential_environment.h"
#include <wchar.h>

BOOL credential_is_winpe(void) {
  WCHAR windows[MAX_PATH] = {0};
  UINT length = GetSystemWindowsDirectoryW(windows, MAX_PATH);
  if (length < 3 || length >= MAX_PATH ||
      (windows[0] != L'X' && windows[0] != L'x') ||
      windows[1] != L':' || windows[2] != L'\\')
    return FALSE;

  const WCHAR *key = L"SYSTEM\\CurrentControlSet\\Control";
  const WCHAR *value = L"SystemStartOptions";
  DWORD bytes = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ, NULL,
                   NULL, &bytes) != ERROR_SUCCESS ||
      bytes < sizeof(WCHAR) || bytes % sizeof(WCHAR))
    return FALSE;
  WCHAR *options = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, bytes);
  if (!options)
    return FALSE;
  DWORD read_bytes = bytes;
  LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ,
                               NULL, options, &read_bytes);
  BOOL winpe = FALSE;
  if (status == ERROR_SUCCESS && read_bytes >= sizeof(WCHAR) &&
      read_bytes <= bytes && !(read_bytes % sizeof(WCHAR)) &&
      options[read_bytes / sizeof(WCHAR) - 1] == L'\0') {
    for (const WCHAR *option = options; *option; ++option) {
      if (!_wcsnicmp(option, L"MININT", 6)) {
        winpe = TRUE;
        break;
      }
    }
  }
  HeapFree(GetProcessHeap(), 0, options);
  return winpe;
}

int credential_require_winpe(void) {
  if (credential_is_winpe())
    return ERROR_SUCCESS;
  MessageBoxW(NULL, L"此功能仅支持 WindowsPE 环境", L"CredentialUI",
              MB_OK | MB_ICONWARNING);
  return ERROR_NOT_SUPPORTED;
}
