#define WIN32_LEAN_AND_MEAN
#include "credential_ipc.h"
#include "credential_runtime.h"
#include "credential_log.h"
#include <shellapi.h>
#include <stdlib.h>
#include <wchar.h>
typedef struct IpcLoad {
  HANDLE pipe, cancel;
  CredentialIpcRequest request;
  DWORD result;
  ULONGLONG start;
} IpcLoad;
static DWORD WINAPI load_request(void *data) {
  IpcLoad *load = (IpcLoad *)data;
  load->start = GetTickCount64();
  load->result = credential_ipc_read(load->pipe, &load->request,
                                     sizeof load->request, 10000, load->cancel);
  return 0;
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line,
                    int show_command) {
  (void)previous;
  (void)command_line;
  int argc = 0;
  WCHAR **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv)
    return ERROR_INVALID_PARAMETER;
  WCHAR log_path[MAX_PATH] = {0};
  BOOL logging = FALSE;
  int arguments = 1;
  for (int i = 1; i < argc; ++i) {
    if (!wcscmp(argv[i], L"--log")) {
      if (logging || i + 1 == argc ||
          credential_log_path(argv[i + 1], log_path)) {
        LocalFree(argv);
        return ERROR_INVALID_PARAMETER;
      }
      logging = TRUE;
      ++i;
    } else {
      argv[arguments++] = argv[i];
    }
  }
  argc = arguments;
  if (argc == 1 || (argc == 2 && (!wcscmp(argv[1], L"--status") ||
                                 !wcscmp(argv[1], L"--stop")))) {
    int result = credential_host_main(argc == 1 ? L"" : argv[1], log_path);
    LocalFree(argv);
    return result;
  }
  if (argc == 3 && (!wcscmp(argv[1], L"--attach") ||
                    !wcscmp(argv[1], L"--detach"))) {
    int result = credential_inject_main(argv[2], !wcscmp(argv[1], L"--attach"),
                                         log_path);
    LocalFree(argv);
    return result;
  }
  if (argc == 2 && !wcscmp(argv[1], L"--preview")) {
    LocalFree(argv);
    DWORD error = credential_log_prepare(log_path);
    if (error)
      return (int)error;
    return credential_ui_run(instance, show_command);
  }
  if (argc != 5 || wcscmp(argv[1], L"--ipc")) {
    LocalFree(argv);
    return ERROR_INVALID_PARAMETER;
  }
  HANDLE handles[3] = {0};
  for (int i = 0; i < 3; i++) {
    WCHAR *end;
    unsigned long long v = _wcstoui64(argv[i + 2], &end, 16);
    if (!v || *end || (unsigned long long)(ULONG_PTR)v != v) {
      LocalFree(argv);
      return ERROR_INVALID_PARAMETER;
    }
    handles[i] = (HANDLE)(ULONG_PTR)v;
  }
  LocalFree(argv);
  DWORD log_error = credential_log_prepare(log_path);
  if (log_error)
    return (int)log_error;
  IpcLoad load = {0};
  load.pipe = handles[0];
  load.cancel = handles[2];
  HANDLE worker = CreateThread(NULL, 0, load_request, &load, 0, NULL);
  if (!worker)
    return ERROR_NOT_ENOUGH_MEMORY;
  WaitForSingleObject(worker, INFINITE);
  CloseHandle(worker);
  CloseHandle(handles[0]);
  DWORD result = load.result;
  CredentialIpcRequest *q = &load.request;
  if (!result && !credential_ipc_request_valid(q))
    result = ERROR_INVALID_DATA;
  HANDLE parent = NULL;
  if (!result) {
    parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                         q->parent_pid);
    if (!parent)
      result = ERROR_INVALID_DATA;
  }
  if (!result && q->owner) {
    DWORD owner_pid = 0;
    GetWindowThreadProcessId((HWND)(ULONG_PTR)q->owner, &owner_pid);
    if (owner_pid != q->parent_pid)
      result = ERROR_INVALID_DATA;
  }
  CredentialUiResult r = {0};
  CredentialUiRequest ui = {0};
  CredentialIpcResponse response = {0};
  if (!result) {
    ui.owner = (HWND)(ULONG_PTR)q->owner;
    ui.parent_process = parent;
    ui.cancel = handles[2];
    ui.deadline = load.start + q->timeout_ms;
    ui.auth_error = q->auth_error;
    ui.retry = (q->options & CREDENTIAL_IPC_INPUT_PRESENT) != 0;
    ui.allow_save = (q->options & CREDENTIAL_IPC_SAVE_ALLOWED) != 0;
    ui.save = (q->options & CREDENTIAL_IPC_SAVE_CHECKED) != 0;
    wcscpy_s(ui.target, CREDENTIAL_TARGET_CAP, q->target);
    wcscpy_s(ui.caption, 128, q->caption);
    wcscpy_s(ui.message, CREDENTIAL_TEXT_CAP, q->message);
    wcscpy_s(ui.username, CREDENTIAL_USERNAME_CAP, q->username);
    result = credential_ui_prompt(instance, show_command, &ui, &r);
    if (result == ERROR_SUCCESS || result == ERROR_CANCELLED ||
        result == ERROR_TIMEOUT) {
      response.magic = CREDENTIAL_IPC_MAGIC;
      response.version = CREDENTIAL_IPC_VERSION;
      response.size = sizeof response;
      response.request_id = q->request_id;
      response.result = result;
      if (!result) {
        response.save = r.save ? 1u : 0u;
        wcscpy_s(response.username, CREDENTIAL_USERNAME_CAP, r.username);
        wcscpy_s(response.password, CREDENTIAL_PASSWORD_CAP, r.password);
      }
      DWORD sent = credential_ipc_write(handles[1], &response, sizeof response);
      if (sent)
        result = sent;
    }
  }
  SecureZeroMemory(&r, sizeof r);
  SecureZeroMemory(&response, sizeof response);
  SecureZeroMemory(&ui, sizeof ui);
  SecureZeroMemory(&load, sizeof load);
  if (parent)
    CloseHandle(parent);
  CloseHandle(handles[1]);
  CloseHandle(handles[2]);
  return (int)result;
}
