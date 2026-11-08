#define WIN32_LEAN_AND_MEAN
#include "credential_ipc.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
static int failures;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      printf("FAIL line=%d %s\n", __LINE__, #x);                               \
      failures++;                                                              \
    }                                                                          \
  } while (0)
static DWORD target_pid;
static HWND target_window;
static BOOL CALLBACK find_window(HWND hwnd, LPARAM parameter) {
  (void)parameter;
  DWORD pid = 0;
  GetWindowThreadProcessId(hwnd, &pid);
  WCHAR cls[80];
  GetClassNameW(hwnd, cls, 80);
  if (pid == target_pid && !wcscmp(cls, L"CredentialUI.Window")) {
    target_window = hwnd;
    return FALSE;
  }
  return TRUE;
}
static void protocol_tests(void) {
  CredentialIpcRequest q = {0};
  q.magic = CREDENTIAL_IPC_MAGIC;
  q.version = CREDENTIAL_IPC_VERSION;
  q.size = sizeof q;
  q.request_id = 1;
  q.parent_pid = GetCurrentProcessId();
  q.timeout_ms = 1000;
  wcscpy_s(q.target, CREDENTIAL_TARGET_CAP, L"test.invalid");
  wcscpy_s(q.package, CREDENTIAL_PACKAGE_CAP, L"Negotiate");
  CHECK(credential_ipc_request_valid(&q));
  q.version++;
  CHECK(!credential_ipc_request_valid(&q));
  q.version--;
  q.flags = 16;
  CHECK(!credential_ipc_request_valid(&q));
  q.flags = 0;
  q.target[CREDENTIAL_TARGET_CAP - 1] = L'x';
  CHECK(!credential_ipc_request_valid(&q));
  CredentialIpcResponse r = {0};
  r.magic = CREDENTIAL_IPC_MAGIC;
  r.version = CREDENTIAL_IPC_VERSION;
  r.size = sizeof r;
  r.request_id = 1;
  r.result = ERROR_SUCCESS;
  wcscpy_s(r.username, CREDENTIAL_USERNAME_CAP, L"test");
  r.save = 1;
  CHECK(credential_ipc_response_valid(&r, 1));
  CHECK(!credential_ipc_response_valid(&r, 2));
  r.result = ERROR_CANCELLED;
  CHECK(!credential_ipc_response_valid(&r, 1));
  SecureZeroMemory(r.username, sizeof r.username);
  r.save = 0;
  CHECK(credential_ipc_response_valid(&r, 1));
  SecureZeroMemory(&r, sizeof r);
  CHECK(r.password[0] == 0);
  HANDLE rd, wr;
  CHECK(CreatePipe(&rd, &wr, NULL, 4096));
  char b[8] = {0};
  ULONGLONG start = GetTickCount64();
  CHECK(credential_ipc_read(rd, b, sizeof b, 60, NULL) == ERROR_TIMEOUT);
  CHECK(GetTickCount64() - start < 1000);
  DWORD n;
  WriteFile(wr, "x", 1, &n, NULL);
  CHECK(credential_ipc_read(rd, b, sizeof b, 60, NULL) == ERROR_TIMEOUT);
  CloseHandle(wr);
  CHECK(credential_ipc_read(rd, b, sizeof b, 60, NULL) != 0);
  CloseHandle(rd);
  printf("protocol validation, partial read, timeout, broken pipe checked\n");
}
static void run_gui(const WCHAR *exe, int scenario) {
  SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
  HANDLE qr, qw, rr, rw, cancel;
  CHECK(CreatePipe(&qr, &qw, &sa, 4096));
  CHECK(CreatePipe(&rr, &rw, &sa, 4096));
  SetHandleInformation(qw, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(rr, HANDLE_FLAG_INHERIT, 0);
  cancel = CreateEventW(&sa, TRUE, FALSE, NULL);
  WCHAR command[1024];
  swprintf_s(command, 1024, L"\"%s\" --ipc %llx %llx %llx", exe,
             (unsigned long long)(ULONG_PTR)qr,
             (unsigned long long)(ULONG_PTR)rw,
             (unsigned long long)(ULONG_PTR)cancel);
  STARTUPINFOW si = {0};
  si.cb = sizeof si;
  PROCESS_INFORMATION pi = {0};
  BOOL made = CreateProcessW(exe, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
  CHECK(made);
  if (!made)
    return;
  CloseHandle(qr);
  CloseHandle(rw);
  CredentialIpcRequest q = {0};
  q.magic = CREDENTIAL_IPC_MAGIC;
  q.version = CREDENTIAL_IPC_VERSION;
  q.size = sizeof q;
  q.request_id = (uint64_t)scenario + 1;
  q.parent_pid = GetCurrentProcessId();
  q.timeout_ms = scenario == 2 ? 1000 : 8000;
  q.options = CREDENTIAL_IPC_SAVE_ALLOWED;
  wcscpy_s(q.target, CREDENTIAL_TARGET_CAP, L"offline.test");
  wcscpy_s(q.package, CREDENTIAL_PACKAGE_CAP, L"Negotiate");
  wcscpy_s(q.caption, 128, L"IPC TEST");
  if (scenario == 4)
    q.magic = 0;
  CHECK(credential_ipc_write(qw, &q, sizeof q) == 0);
  CloseHandle(qw);
  target_pid = pi.dwProcessId;
  target_window = NULL;
  if (scenario != 4) {
    ULONGLONG limit = GetTickCount64() + 4000;
    do {
      EnumWindows(find_window, 0);
      if (target_window)
        break;
      Sleep(20);
    } while (GetTickCount64() < limit);
    CHECK(target_window != NULL);
  }
  if (target_window) {
    if (scenario == 0 || scenario == 5) {
      WCHAR user[514];
      if (scenario == 5) {
        for (int i = 0; i < 512; i++)
          user[i] = L'a';
        user[512] = 0;
      } else
        wcscpy_s(user, 514, L"DOMAIN\\OfflineUser");
      SendMessageW(GetDlgItem(target_window, 1001), WM_SETTEXT, 0,
                   (LPARAM)user);
      SendMessageW(GetDlgItem(target_window, 1002), WM_SETTEXT, 0,
                   (LPARAM)L"Offline-Password");
      SendMessageW(GetDlgItem(target_window, 1003), BM_SETCHECK, BST_CHECKED,
                   0);
      PostMessageW(target_window, WM_COMMAND, IDOK, 0);
      if (scenario == 5) {
        Sleep(150);
        CHECK(IsWindow(target_window));
        SendMessageW(GetDlgItem(target_window, 1001), WM_SETTEXT, 0,
                     (LPARAM)L"OfflineUser");
        PostMessageW(target_window, WM_COMMAND, IDOK, 0);
      }
    } else if (scenario == 1)
      PostMessageW(target_window, WM_CLOSE, 0, 0);
    else if (scenario == 3)
      SetEvent(cancel);
    else if (scenario == 6)
      PostMessageW(target_window, WM_COMMAND, IDCANCEL, 0);
    else if (scenario == 7)
      PostMessageW(target_window, WM_COMMAND, 1004, 0);
    else if (scenario == 8)
      PostMessageW(target_window, WM_KEYDOWN, VK_ESCAPE, 0);
    else if (scenario == 9)
      PostMessageW(target_window, WM_SYSCOMMAND, SC_CLOSE, 0);
  }
  CHECK(WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0);
  DWORD exit = 0;
  GetExitCodeProcess(pi.hProcess, &exit);
  CredentialIpcResponse r = {0};
  DWORD status = credential_ipc_read(rr, &r, sizeof r, 300, NULL);
  if (scenario == 4) {
    CHECK(status != 0);
    CHECK(exit == ERROR_INVALID_DATA);
  } else {
    CHECK(status == 0);
    CHECK(credential_ipc_response_valid(&r, q.request_id));
    if (scenario == 0 || scenario == 5) {
      CHECK(r.result == 0);
      CHECK(r.save == 1);
      CHECK(!wcscmp(r.password, L"Offline-Password"));
    } else
      CHECK(r.result == (scenario == 2 ? ERROR_TIMEOUT : ERROR_CANCELLED));
  }
  SecureZeroMemory(&r, sizeof r);
  CloseHandle(rr);
  CloseHandle(cancel);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  printf("gui scenario=%d exit=%lu\n", scenario, exit);
}
static void run_preview(const WCHAR *exe) {
  WCHAR command[1024];
  swprintf_s(command, 1024, L"\"%s\" --preview", exe);
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  si.cb = sizeof si;
  BOOL made = CreateProcessW(exe, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
  CHECK(made);
  if (!made)
    return;
  target_pid = pi.dwProcessId;
  target_window = NULL;
  ULONGLONG limit = GetTickCount64() + 4000;
  do {
    EnumWindows(find_window, 0);
    if (target_window)
      break;
    Sleep(20);
  } while (GetTickCount64() < limit);
  CHECK(target_window != NULL);
  if (target_window)
    PostMessageW(target_window, WM_CLOSE, 0, 0);
  DWORD wait = WaitForSingleObject(pi.hProcess, 5000), code = STILL_ACTIVE;
  CHECK(wait == WAIT_OBJECT_0);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
    WaitForSingleObject(pi.hProcess, 5000);
  }
  CHECK(GetExitCodeProcess(pi.hProcess, &code));
  CHECK(code == ERROR_SUCCESS);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  printf("preview exit=%lu\n", code);
}
int wmain(int argc, WCHAR **argv) {
  protocol_tests();
  if (argc == 2) {
    run_preview(argv[1]);
    for (int i = 0; i < 10; i++)
      run_gui(argv[1], i);
  }
  printf("failures=%d requestBytes=%zu responseBytes=%zu\n", failures,
         sizeof(CredentialIpcRequest), sizeof(CredentialIpcResponse));
  return failures ? 1 : 0;
}
