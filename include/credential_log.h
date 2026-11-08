#ifndef CREDENTIAL_LOG_H
#define CREDENTIAL_LOG_H
#include <stdio.h>
#include <wchar.h>
#include <windows.h>

/* Passed to the bridge in remote memory, never through Explorer's environment. */
typedef struct CredentialBridgeOptions {
  DWORD size;
  WCHAR log_path[MAX_PATH];
} CredentialBridgeOptions;

static __inline DWORD credential_log_path(const WCHAR *input,
                                           WCHAR output[MAX_PATH]) {
  output[0] = 0;
  if (!input || !*input || wcslen(input) >= MAX_PATH)
    return ERROR_INVALID_PARAMETER;
  BOOL drive = ((input[0] >= L'A' && input[0] <= L'Z') ||
                (input[0] >= L'a' && input[0] <= L'z')) &&
               input[1] == L':' && (input[2] == L'\\' || input[2] == L'/');
  BOOL unc = input[0] == L'\\' && input[1] == L'\\' &&
             input[2] && input[2] != L'?' && input[2] != L'.';
  if (!drive && !unc)
    return ERROR_INVALID_PARAMETER;
  WCHAR *file = NULL;
  DWORD length = GetFullPathNameW(input, MAX_PATH, output, &file);
  if (!length || length >= MAX_PATH || !file || !*file) {
    output[0] = 0;
    return ERROR_INVALID_PARAMETER;
  }
  if (unc) {
    const WCHAR *share = wcschr(output + 2, L'\\');
    if (!share || share == output + 2 || !share[1] ||
        !wcschr(share + 1, L'\\') || share[1] == L'\\') {
      output[0] = 0;
      return ERROR_INVALID_PARAMETER;
    }
  }
  return ERROR_SUCCESS;
}

static __inline DWORD credential_log_prepare(const WCHAR *path) {
  if (!path || !*path)
    return ERROR_SUCCESS;
  HANDLE file = CreateFileW(path, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return GetLastError();
  CloseHandle(file);
  return ERROR_SUCCESS;
}

static __inline void credential_log(const WCHAR *path, const WCHAR *component,
                                    DWORD pid, DWORD code, DWORD detail) {
  if (!path || !*path)
    return;
  DWORD saved_error = GetLastError(), written;
  WCHAR line[256];
  int count = swprintf_s(line, 256, L"%llu %s pid=%lu code=%lu detail=%lu\r\n",
                         GetTickCount64(), component, pid, code, detail);
  char text[1024];
  int bytes = count > 0 ? WideCharToMultiByte(CP_UTF8, 0, line, count, text,
                                             sizeof text, NULL, NULL) : 0;
  if (bytes > 0) {
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
      WriteFile(file, text, (DWORD)bytes, &written, NULL);
      CloseHandle(file);
    }
  }
  SetLastError(saved_error);
}
#endif
