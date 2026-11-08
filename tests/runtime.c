#define WIN32_LEAN_AND_MEAN
#include "credential_control.h"
#include "credential_environment.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
static DWORD test_owner;
static int failures;
static int environment_result;
#define CHECK(x) do { if (!(x)) { printf("FAIL line=%d %s\n", __LINE__, #x); failures++; } } while (0)
/* Exercise real host IPC/lifecycle under private test names without discovering
 * or injecting into the user's Explorer processes. */
static void test_object_name(WCHAR *out, size_t cap, const WCHAR *kind) {
  WCHAR actual[128];
  credential_object_name(actual, 128, kind);
  swprintf_s(out, cap, L"%s.Test.%lu", actual, test_owner);
}
static HANDLE test_empty_snapshot(DWORD flags, DWORD pid) {
  (void)flags;
  (void)pid;
  SetLastError(ERROR_NO_MORE_FILES);
  return INVALID_HANDLE_VALUE;
}
/* Hold the production singleton so real EXE dispatch checks cannot inject into
 * Explorer. The host lifecycle below uses separate test-only object names. */
static HANDLE block_executable_host(void) {
  WCHAR name[128];
  credential_object_name(name, 128, L"Instance");
  return CreateMutexW(NULL, FALSE, name);
}
static int test_require_winpe(void) {
  return environment_result;
}
#define credential_require_winpe test_require_winpe
#define credential_object_name test_object_name
#define CreateToolhelp32Snapshot test_empty_snapshot
#include "../bridge/host.c"
#include "../bridge/injector.c"
#undef credential_require_winpe
typedef struct PromptCheck {
  DWORD pid;
  BOOL expected, shown;
} PromptCheck;
static BOOL CALLBACK close_environment_prompt(HWND window, LPARAM parameter) {
  PromptCheck *prompt = (PromptCheck *)parameter;
  DWORD pid = 0;
  GetWindowThreadProcessId(window, &pid);
  if (pid != prompt->pid)
    return TRUE;
  WCHAR class_name[32];
  GetClassNameW(window, class_name, 32);
  if (wcscmp(class_name, L"#32770"))
    return TRUE;
  HWND button = FindWindowExW(window, NULL, L"Button", NULL);
  if (!IsWindowVisible(window) || !button ||
      !FindWindowExW(window, NULL, L"Static", L"此功能仅支持 WindowsPE 环境"))
    return TRUE;
  CHECK(prompt->expected);
  prompt->shown = TRUE;
  PostMessageW(button, BM_CLICK, 0, 0);
  return TRUE;
}
static DWORD command_result_with_prompt(const WCHAR *exe, const WCHAR *args,
                                        BOOL denied) {
  WCHAR command[2048];
  swprintf_s(command, 2048, L"\"%s\" %s", exe, args);
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  si.cb = sizeof si;
  if (!CreateProcessW(exe, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                      NULL, NULL, &si, &pi)) {
    CHECK(FALSE);
    return GetLastError();
  }
  PromptCheck prompt = {pi.dwProcessId, denied, FALSE};
  ULONGLONG deadline = GetTickCount64() + 5000;
  DWORD wait, code = STILL_ACTIVE;
  do {
    EnumWindows(close_environment_prompt, (LPARAM)&prompt);
    wait = WaitForSingleObject(pi.hProcess, 10);
  } while (wait == WAIT_TIMEOUT && GetTickCount64() < deadline);
  CHECK(wait == WAIT_OBJECT_0);
  CHECK(prompt.shown == denied);
  if (wait != WAIT_OBJECT_0)
    TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return code;
}
static DWORD command_result(const WCHAR *exe, const WCHAR *args) {
  return command_result_with_prompt(exe, args, FALSE);
}
int wmain(int argc, WCHAR **argv) {
  if ((argc == 3 || argc == 4) && !wcscmp(argv[1], L"--host")) {
    test_owner = wcstoul(argv[2], NULL, 10);
    return credential_host_main(L"", argc == 4 ? argv[3] : NULL);
  }
  test_owner = GetCurrentProcessId();
  CHECK(same_architecture(GetCurrentProcess()) == ERROR_SUCCESS);
  CHECK(credential_host_main(L"--invalid", NULL) == ERROR_INVALID_PARAMETER);
  CHECK(credential_host_main(L"--run", NULL) == ERROR_INVALID_PARAMETER);
  CHECK(credential_host_main(L"--status", NULL) == ERROR_NOT_FOUND);
  CHECK(credential_host_main(L"--stop", NULL) == ERROR_NOT_FOUND);
  environment_result = ERROR_NOT_SUPPORTED;
  CHECK(credential_host_main(L"", NULL) == ERROR_NOT_SUPPORTED);
  CHECK(credential_host_main(L"--status", NULL) == ERROR_NOT_FOUND);
  CHECK(credential_host_main(L"--stop", NULL) == ERROR_NOT_FOUND);
  CHECK(credential_inject_main(L"1", TRUE, NULL) == ERROR_NOT_SUPPORTED);
  environment_result = ERROR_SUCCESS;
  const WCHAR *invalid[] = {L"", L"0", L"-1", L"+1", L"1x", L" 1", L"4294967296", L"18446744073709551616"};
  for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i)
    CHECK(credential_inject_main(invalid[i], TRUE, NULL) == ERROR_INVALID_PARAMETER);
  WCHAR self[MAX_PATH], command[1024], log_path[MAX_PATH], temporary[MAX_PATH];
  GetModuleFileNameW(NULL, self, MAX_PATH);
  WCHAR default_log[MAX_PATH];
  wcscpy_s(default_log, MAX_PATH, self);
  WCHAR *default_name = wcsrchr(default_log, L'\\');
  if (!default_name)
    return 1;
  wcscpy_s(default_name + 1, MAX_PATH - (size_t)(default_name + 1 - default_log),
            L"credential.log");
  WIN32_FILE_ATTRIBUTE_DATA before = {0}, after = {0};
  BOOL existed = GetFileAttributesExW(default_log, GetFileExInfoStandard, &before);
  CHECK(GetTempPathW(MAX_PATH, temporary) < MAX_PATH);
  swprintf_s(log_path, MAX_PATH, L"%sCredentialUI.HostTest.%lu.%llu.log",
             temporary, test_owner, GetTickCount64());
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  BOOL made;
  si.cb = sizeof si;
  for (int logging = 0; logging < 2; ++logging) {
    if (logging)
      swprintf_s(command, 1024, L"\"%s\" --host %lu \"%s\"", self, test_owner, log_path);
    else
      swprintf_s(command, 1024, L"\"%s\" --host %lu", self, test_owner);
    made = CreateProcessW(self, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                          NULL, NULL, &si, &pi);
    CHECK(made);
    if (made) {
      ULONGLONG deadline = GetTickCount64() + 5000;
      int status;
      do {
        status = credential_host_main(L"--status", NULL);
        if (status == ERROR_SUCCESS)
          break;
        Sleep(20);
      } while (GetTickCount64() < deadline);
      CHECK(status == ERROR_SUCCESS);
      if (!status) {
        CHECK(credential_host_main(L"", NULL) == ERROR_ALREADY_EXISTS);
        CHECK(credential_host_main(L"--status", NULL) == ERROR_SUCCESS);
        CHECK(WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT);
        CHECK(credential_host_main(L"--stop", NULL) == ERROR_SUCCESS);
      }
      DWORD wait = WaitForSingleObject(pi.hProcess, 5000), code = STILL_ACTIVE;
      CHECK(wait == WAIT_OBJECT_0);
      if (wait != WAIT_OBJECT_0)
        TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
      GetExitCodeProcess(pi.hProcess, &code);
      CHECK(code == ERROR_SUCCESS);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      CHECK(credential_host_main(L"--status", NULL) == ERROR_NOT_FOUND);
    }
    if (logging) {
      HANDLE file = CreateFileW(log_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
      CHECK(file != INVALID_HANDLE_VALUE);
      if (file != INVALID_HANDLE_VALUE) {
        char events[2048] = {0};
        DWORD bytes = 0;
        CHECK(ReadFile(file, events, sizeof events - 1, &bytes, NULL));
        CHECK(strstr(events, "host-start") != NULL);
        CHECK(strstr(events, "host-stop") != NULL);
        CloseHandle(file);
      }
      CHECK(DeleteFileW(log_path));
    } else {
      CHECK(GetFileAttributesW(log_path) == INVALID_FILE_ATTRIBUTES);
    }
  }
  BOOL exists = GetFileAttributesExW(default_log, GetFileExInfoStandard, &after);
  CHECK(existed == exists);
  if (existed && exists) {
    CHECK(before.nFileSizeLow == after.nFileSizeLow);
    CHECK(before.nFileSizeHigh == after.nFileSizeHigh);
    CHECK(!CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime));
  }
  WCHAR *slash = wcsrchr(self, L'\\');
  CHECK(slash != NULL);
  if (slash) {
    WCHAR bundled[MAX_PATH];
    CHECK(credential_bundle_prepare(NULL, NULL, bundled) == ERROR_SUCCESS);
    HMODULE bridge = LoadLibraryW(bundled);
    CHECK(bridge != NULL);
    if (bridge) {
      CHECK(GetProcAddress(bridge, "ProbeStart") != NULL);
      CHECK(GetProcAddress(bridge, "ProbeStop") != NULL);
      FreeLibrary(bridge);
    }
  }
  if (argc >= 2) {
    BOOL winpe = credential_is_winpe();
    const WCHAR *bad[] = {L"--bogus", L"--run", L"--run extra", L"--attach", L"--detach",
                         L"--attach 0", L"--detach -1", L"--attach 4294967296",
                         L"--attach 12x", L"--ipc", L"--preview extra"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i)
      CHECK(command_result(argv[1], bad[i]) == ERROR_INVALID_PARAMETER);
    HANDLE guard = block_executable_host();
    CHECK(guard != NULL);
    if (guard) {
      DWORD expected = winpe ? ERROR_ALREADY_EXISTS : ERROR_NOT_SUPPORTED;
      CHECK(command_result_with_prompt(argv[1], L"", !winpe) == expected);
      CHECK(command_result_with_prompt(argv[1], L"", !winpe) == expected);
      swprintf_s(command, 1024, L"--log \"%s\"", log_path);
      CHECK(command_result_with_prompt(argv[1], command, !winpe) == expected);
      CloseHandle(guard);
      if (winpe)
        CHECK(DeleteFileW(log_path));
      else
        CHECK(GetFileAttributesW(log_path) == INVALID_FILE_ATTRIBUTES);
    }
    if (!winpe) {
      swprintf_s(command, 1024, L"--attach %lu", GetCurrentProcessId());
      CHECK(command_result_with_prompt(argv[1], command, TRUE) == ERROR_NOT_SUPPORTED);
    }
  }
  if (argc == 3) {
    /* A suspended opposite-architecture child never executes UI or bridge code. */
    swprintf_s(command, 1024, L"\"%s\" --preview", argv[2]);
    ZeroMemory(&pi, sizeof pi);
    made = CreateProcessW(argv[2], command, NULL, NULL, FALSE,
                          CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CHECK(made);
    if (made) {
      CHECK(same_architecture(pi.hProcess) == ERROR_BAD_EXE_FORMAT);
      if (argc >= 2) {
        WCHAR args[80];
        swprintf_s(args, 80, L"--attach %lu", pi.dwProcessId);
        BOOL winpe = credential_is_winpe();
        CHECK(command_result_with_prompt(argv[1], args, !winpe) ==
              (winpe ? ERROR_BAD_EXE_FORMAT : ERROR_NOT_SUPPORTED));
        swprintf_s(args, 80, L"--detach %lu", pi.dwProcessId);
        CHECK(command_result(argv[1], args) == ERROR_BAD_EXE_FORMAT);
      }
      TerminateProcess(pi.hProcess, ERROR_CANCELLED);
      WaitForSingleObject(pi.hProcess, 5000);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
    }
  }
  printf("runtime failures=%d (host lifecycle, PID validation, dispatch, architecture)\n", failures);
  return failures ? 1 : 0;
}
