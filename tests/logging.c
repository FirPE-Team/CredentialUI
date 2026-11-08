#define WIN32_LEAN_AND_MEAN
#include "../bridge/bridge.c"
#include "../bridge/inject.h"
#include <stdio.h>

static int failures;
#define CHECK(x) do { if (!(x)) { printf("FAIL line=%d %s error=%lu\n", __LINE__, #x, GetLastError()); failures++; } } while (0)

static DWORD command_result(const WCHAR *exe, const WCHAR *args) {
  WCHAR command[2048];
  swprintf_s(command, 2048, L"\"%s\" %s", exe, args);
  STARTUPINFOW start = {0};
  PROCESS_INFORMATION process = {0};
  start.cb = sizeof start;
  if (!CreateProcessW(exe, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, NULL, &start, &process)) {
    CHECK(FALSE);
    return GetLastError();
  }
  DWORD wait = WaitForSingleObject(process.hProcess, 5000), code = STILL_ACTIVE;
  CHECK(wait == WAIT_OBJECT_0);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, ERROR_TIMEOUT);
    WaitForSingleObject(process.hProcess, 5000);
  }
  GetExitCodeProcess(process.hProcess, &code);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return code;
}

static DWORD file_size(const WCHAR *path) {
  WIN32_FILE_ATTRIBUTE_DATA data = {0};
  CHECK(GetFileAttributesExW(path, GetFileExInfoStandard, &data));
  return data.nFileSizeLow;
}

int wmain(int argc, WCHAR **argv) {
  if (argc != 3)
    return 2;
  WCHAR base[MAX_PATH], sandbox[MAX_PATH], path[MAX_PATH], normalized[MAX_PATH];
  CHECK(GetTempPathW(MAX_PATH, base) < MAX_PATH);
  swprintf_s(sandbox, MAX_PATH, L"%sCredentialUI.LogTest.%lu.%llu", base,
             GetCurrentProcessId(), GetTickCount64());
  CHECK(CreateDirectoryW(sandbox, NULL));
  CHECK(SetCurrentDirectoryW(sandbox));
  swprintf_s(path, MAX_PATH, L"%s\\诊断 log.txt", sandbox);
  CHECK(credential_log_path(path, normalized) == ERROR_SUCCESS);
  CHECK(!wcscmp(path, normalized));
  const WCHAR *bad[] = {L"", L"credential.log", L".\\credential.log",
      L"C:credential.log", L"\\credential.log", L"C:\\", L"\\\\server\\share",
      L"\\\\.\\pipe\\credential", L"\\\\?\\C:\\credential.log"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i)
    CHECK(credential_log_path(bad[i], normalized) == ERROR_INVALID_PARAMETER);
  CHECK(credential_log_path(L"\\\\server\\share\\folder\\log.txt", normalized) == 0);

  credential_log(NULL, L"disabled", 1, 2, 3);
  credential_log(L"", L"disabled", 1, 2, 3);
  log_event(L"disabled-bridge", 2, 3);
  CHECK(GetFileAttributesW(L"credential.log") == INVALID_FILE_ATTRIBUTES);
  CHECK(credential_log_prepare(sandbox) != ERROR_SUCCESS);
  CHECK(credential_log_prepare(path) == ERROR_SUCCESS);
  SetLastError(1234);
  credential_log(path, L"manager-test", 1, 2, 3);
  CHECK(GetLastError() == 1234);
  DWORD first = file_size(path);
  CHECK(first > 0);
  CredentialBridgeOptions options = {0};
  options.size = sizeof options;
  wcscpy_s(options.log_path, MAX_PATH, path);
  CHECK(configure_log(&options) == ERROR_SUCCESS);
  log_event(L"bridge-test", 4, 5);
  CHECK(file_size(path) > first);
  DWORD second = file_size(path);
  CHECK(configure_log(NULL) == ERROR_SUCCESS);
  log_event(L"disabled-again", 4, 5);
  CHECK(file_size(path) == second);
  options.size = 0;
  CHECK(configure_log(&options) == ERROR_INVALID_PARAMETER);
  options.size = sizeof options;
  wmemset(options.log_path, L'x', MAX_PATH);
  CHECK(configure_log(&options) == ERROR_INVALID_PARAMETER);

  /* Exercise the actual remote configuration transport in this test process.
   * ProbeStop logs an event without installing hooks in Explorer. */
  WCHAR dll[MAX_PATH];
  swprintf_s(dll, MAX_PATH, L"%s\\CredentialUIBridge.dll", sandbox);
  CHECK(CopyFileW(argv[2], dll, TRUE));
  HMODULE bridge = LoadLibraryW(dll);
  CHECK(bridge != NULL);
  if (bridge) {
    CHECK(inject_bridge(GetCurrentProcessId(), NULL, dll, FALSE, path) == 0);
    CHECK(file_size(path) > second);
    second = file_size(path);
    CHECK(inject_bridge(GetCurrentProcessId(), NULL, dll, FALSE, NULL) == 0);
    CHECK(file_size(path) == second);
    FreeLibrary(bridge);
  }
  CHECK(GetFileAttributesW(L"credential.log") == INVALID_FILE_ATTRIBUTES);
  WCHAR args[1024];
  const WCHAR *bad_args[] = {L"--status --log", L"--status --log relative.log",
      L"--status --log C:relative.log", L"--status --log \\\\rooted.log",
      L"--status --log \"\"", L"--log --status"};
  for (size_t i = 0; i < sizeof bad_args / sizeof bad_args[0]; ++i)
    CHECK(command_result(argv[1], bad_args[i]) == ERROR_INVALID_PARAMETER);
  swprintf_s(args, 1024, L"--status --log \"%s\" --log \"%s\"", path, path);
  CHECK(command_result(argv[1], args) == ERROR_INVALID_PARAMETER);
  swprintf_s(args, 1024, L"--attach 0 --log \"%s\\invalid-action.log\"", sandbox);
  CHECK(command_result(argv[1], args) == ERROR_INVALID_PARAMETER);
  CHECK(GetFileAttributesW(L"invalid-action.log") == INVALID_FILE_ATTRIBUTES);
  swprintf_s(args, 1024, L"--status --log \"%s\\missing\\log.txt\"", sandbox);
  CHECK(command_result(argv[1], args) == ERROR_PATH_NOT_FOUND);
  swprintf_s(args, 1024, L"--status --log \"%s\"", sandbox);
  CHECK(command_result(argv[1], args) == ERROR_ACCESS_DENIED);
  /* --status is read-only; it is safe whether or not a real manager is active. */
  DWORD status = command_result(argv[1], L"--status");
  CHECK(status == 0 || status == ERROR_NOT_FOUND || status == ERROR_BUSY);
  CHECK(GetFileAttributesW(L"credential.log") == INVALID_FILE_ATTRIBUTES);
  swprintf_s(args, 1024, L"--log \"%s\" --status", path);
  CHECK(command_result(argv[1], args) == status);
  CHECK(DeleteFileW(dll));
  CHECK(DeleteFileW(path));
  CHECK(SetCurrentDirectoryW(base));
  CHECK(RemoveDirectoryW(sandbox));
  printf("logging failures=%d (opt-in, absolute path, CLI, bridge transport)\n", failures);
  return failures ? 1 : 0;
}
