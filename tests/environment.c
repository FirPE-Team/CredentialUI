#define WIN32_LEAN_AND_MEAN
#include "credential_environment.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int failures, registry_calls, prompts;
static const WCHAR *system_directory = L"X:\\Windows";
static const WCHAR *start_options = L"FASTDETECT MININT";
static LSTATUS query_status, read_status;
static DWORD size_override;
static BOOL directory_failure, malformed_string;
#define CHECK(x) do { if (!(x)) { printf("FAIL line=%d %s\n", __LINE__, #x); failures++; } } while (0)

static UINT WINAPI test_system_directory(LPWSTR buffer, UINT capacity) {
  if (directory_failure)
    return 0;
  size_t length = wcslen(system_directory);
  if (length >= capacity)
    return (UINT)length + 1;
  wcscpy_s(buffer, capacity, system_directory);
  return (UINT)length;
}
static LSTATUS WINAPI test_registry(HKEY key, LPCWSTR subkey, LPCWSTR value,
    DWORD flags, LPDWORD type, PVOID data, LPDWORD size) {
  ++registry_calls;
  CHECK(key == HKEY_LOCAL_MACHINE);
  CHECK(!wcscmp(subkey, L"SYSTEM\\CurrentControlSet\\Control"));
  CHECK(!wcscmp(value, L"SystemStartOptions"));
  CHECK(flags == RRF_RT_REG_SZ);
  (void)type;
  DWORD bytes = (DWORD)((wcslen(start_options) + 1) * sizeof(WCHAR));
  if (!data) {
    *size = size_override ? size_override : bytes;
    return query_status;
  }
  if (read_status)
    return read_status;
  if (*size < bytes)
    return ERROR_MORE_DATA;
  memcpy(data, start_options, bytes);
  if (malformed_string)
    ((WCHAR *)data)[bytes / sizeof(WCHAR) - 1] = L'x';
  *size = bytes;
  return ERROR_SUCCESS;
}
static int WINAPI test_message(HWND owner, LPCWSTR text, LPCWSTR caption,
                               UINT flags) {
  ++prompts;
  CHECK(owner == NULL);
  CHECK(!wcscmp(text, L"此功能仅支持 WindowsPE 环境"));
  CHECK(!wcscmp(caption, L"CredentialUI"));
  CHECK(flags == (MB_OK | MB_ICONWARNING));
  return IDOK;
}
#define GetSystemWindowsDirectoryW test_system_directory
#define RegGetValueW test_registry
#define MessageBoxW test_message
#include "../src/credential_environment.c"

int wmain(void) {
  CHECK(credential_is_winpe());
  CHECK(credential_require_winpe() == ERROR_SUCCESS);
  CHECK(prompts == 0);
  system_directory = L"x:\\Windows";
  start_options = L"/fastdetect /minint /rdpath=boot.sdi";
  CHECK(credential_is_winpe());
  /* The requested rule is a substring match, rather than a boot-token parser. */
  start_options = L"PREFIXMININTSUFFIX";
  CHECK(credential_is_winpe());
  start_options = L"MININT";
  system_directory = L"C:\\Windows";
  registry_calls = 0;
  CHECK(!credential_is_winpe());
  CHECK(registry_calls == 0);
  CHECK(credential_require_winpe() == ERROR_NOT_SUPPORTED);
  CHECK(prompts == 1);
  system_directory = L"X:Windows";
  CHECK(!credential_is_winpe());
  system_directory = L"\\\\server\\X$\\Windows";
  CHECK(!credential_is_winpe());
  system_directory = L"";
  CHECK(!credential_is_winpe());
  system_directory = L"X:\\Windows";
  directory_failure = TRUE;
  CHECK(!credential_is_winpe());
  directory_failure = FALSE;
  WCHAR long_directory[MAX_PATH + 1];
  wmemset(long_directory, L'x', MAX_PATH);
  long_directory[MAX_PATH] = L'\0';
  system_directory = long_directory;
  CHECK(!credential_is_winpe());
  system_directory = L"X:\\Windows";
  start_options = L"FASTDETECT";
  CHECK(!credential_is_winpe());
  start_options = L"";
  CHECK(!credential_is_winpe());
  start_options = L"MININT";
  query_status = ERROR_FILE_NOT_FOUND;
  CHECK(!credential_is_winpe());
  query_status = ERROR_ACCESS_DENIED;
  CHECK(!credential_is_winpe());
  query_status = ERROR_UNSUPPORTED_TYPE;
  CHECK(!credential_is_winpe());
  query_status = ERROR_SUCCESS;
  read_status = ERROR_ACCESS_DENIED;
  CHECK(!credential_is_winpe());
  read_status = ERROR_MORE_DATA;
  CHECK(!credential_is_winpe());
  read_status = ERROR_SUCCESS;
  size_override = 1;
  CHECK(!credential_is_winpe());
  size_override = 0;
  malformed_string = TRUE;
  CHECK(!credential_is_winpe());
  malformed_string = FALSE;
  CHECK(credential_is_winpe());
  printf("environment failures=%d (system drive, MININT, read failures, prompt)\n", failures);
  return failures ? 1 : 0;
}
