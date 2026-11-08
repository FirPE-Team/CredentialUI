#define WIN32_LEAN_AND_MEAN
#include "credential_control.h"
#include "inject.h"
#include "credential_runtime.h"
#include "credential_bundle.h"
#include "credential_environment.h"
#define MAX_TRACKED 256
typedef struct Tracked {
  DWORD pid;
  FILETIME created;
  ULONGLONG retry;
  BOOL attached, seen;
  DWORD error;
} Tracked;
int credential_host_main(const WCHAR *mode, const WCHAR *log_path) {
  BOOL stop = !wcscmp(mode, L"--stop"),
       status = !wcscmp(mode, L"--status");
  if (!stop && !status && *mode)
    return ERROR_INVALID_PARAMETER;
  if (!stop && !status) {
    int environment_error = credential_require_winpe();
    if (environment_error)
      return environment_error;
  }
  DWORD log_error = credential_log_prepare(log_path);
  if (log_error)
    return (int)log_error;
  WCHAR name[128], dll[MAX_PATH];
  credential_object_name(name, 128, L"Control");
  if (stop || status) {
    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
    if (!map)
      return ERROR_NOT_FOUND;
    CredentialControl *view = (CredentialControl *)MapViewOfFile(
        map, FILE_MAP_READ, 0, 0, sizeof(CredentialControl));
    if (!view) {
      CloseHandle(map);
      return ERROR_INVALID_DATA;
    }
    CredentialControl snapshot = *view;
    UnmapViewOfFile(view);
    CloseHandle(map);
    DWORD result = ERROR_NOT_FOUND;
    if (snapshot.magic == CREDENTIAL_CONTROL_MAGIC) {
      HANDLE owner = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                 FALSE, snapshot.pid);
      if (owner && WaitForSingleObject(owner, 0) == WAIT_TIMEOUT) {
        if (status) {
          result = snapshot.running ? 0 : ERROR_BUSY;
          credential_log(log_path, L"status", snapshot.pid, snapshot.installed,
                         snapshot.failures);
        } else {
          credential_object_name(name, 128, L"Stop");
          HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
          if (event) {
            SetEvent(event);
            CloseHandle(event);
            DWORD wait = WaitForSingleObject(owner, 20000);
            if (wait == WAIT_OBJECT_0) {
              DWORD code = 0;
              result = GetExitCodeProcess(owner, &code) ? code : GetLastError();
            } else
              result = ERROR_TIMEOUT;
          }
        }
      }
      if (owner)
        CloseHandle(owner);
    }
    if (stop)
      credential_log(log_path, L"stop", snapshot.pid, result, 0);
    return (int)result;
  }
  credential_object_name(name, 128, L"Instance");
  HANDLE mutex = CreateMutexW(NULL, TRUE, name);
  if (!mutex)
    return (int)GetLastError();
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(mutex);
    return ERROR_ALREADY_EXISTS;
  }
  credential_object_name(name, 128, L"Stop");
  HANDLE event = CreateEventW(NULL, TRUE, FALSE, name);
  if (!event) {
    CloseHandle(mutex);
    return (int)GetLastError();
  }
  ResetEvent(event);
  credential_object_name(name, 128, L"Control");
  HANDLE mapping =
      CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                         sizeof(CredentialControl), name);
  CredentialControl *control =
      mapping
          ? (CredentialControl *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0,
                                               0, sizeof(CredentialControl))
          : NULL;
  if (!control) {
    CloseHandle(event);
    CloseHandle(mutex);
    if (mapping)
      CloseHandle(mapping);
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  SecureZeroMemory(control, sizeof *control);
  control->magic = CREDENTIAL_CONTROL_MAGIC;
  control->pid = GetCurrentProcessId();
  ProcessIdToSessionId(control->pid, &control->session);
  control->running = 1;
  DWORD preparation = credential_bundle_prepare(NULL, NULL, dll);
  if (preparation) {
    credential_log(log_path, L"bundle-error", control->pid, preparation, 0);
    UnmapViewOfFile(control);
    CloseHandle(mapping);
    CloseHandle(event);
    ReleaseMutex(mutex);
    CloseHandle(mutex);
    return (int)preparation;
  }
  Tracked entries[MAX_TRACKED] = {0};
  credential_log(log_path, L"host-start", control->pid, 0, 0);
  do {
    for (size_t i = 0; i < MAX_TRACKED; i++)
      entries[i].seen = FALSE;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof entry;
    if (snapshot != INVALID_HANDLE_VALUE) {
      if (Process32FirstW(snapshot, &entry))
        do {
          if (_wcsicmp(entry.szExeFile, L"explorer.exe"))
            continue;
          DWORD session = 0;
          if (!ProcessIdToSessionId(entry.th32ProcessID, &session) ||
              session != control->session)
            continue;
          HANDLE process =
              OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                          FALSE, entry.th32ProcessID);
          if (!process)
            continue;
          WCHAR image[MAX_PATH], expected_image[MAX_PATH];
          DWORD length = MAX_PATH;
          GetWindowsDirectoryW(expected_image, MAX_PATH);
          wcscat_s(expected_image, MAX_PATH, L"\\explorer.exe");
          BOOL correct_image =
              QueryFullProcessImageNameW(process, 0, image, &length) &&
              !_wcsicmp(image, expected_image);
          FILETIME created, ex, kernel, user;
          BOOL valid =
              correct_image &&
              GetProcessTimes(process, &created, &ex, &kernel, &user) &&
              same_architecture(process) == ERROR_SUCCESS &&
              WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
          CloseHandle(process);
          if (!valid)
            continue;
          size_t slot = MAX_TRACKED;
          for (size_t i = 0; i < MAX_TRACKED; i++) {
            if (entries[i].pid == entry.th32ProcessID &&
                !CompareFileTime(&entries[i].created, &created)) {
              slot = i;
              break;
            }
          }
          if (slot == MAX_TRACKED) {
            for (size_t i = 0; i < MAX_TRACKED; i++)
              if (!entries[i].pid) {
                slot = i;
                entries[i].pid = entry.th32ProcessID;
                entries[i].created = created;
                break;
              }
          }
          if (slot == MAX_TRACKED)
            continue;
          Tracked *t = &entries[slot];
          t->seen = TRUE;
          if (!t->attached && GetTickCount64() >= t->retry &&
              WaitForSingleObject(event, 0) != WAIT_OBJECT_0) {
            DWORD result = inject_bridge(t->pid, &t->created, dll, TRUE, log_path);
            t->error = result;
            t->attached = result == 0;
            t->retry = GetTickCount64() + 5000;
            credential_log(log_path, L"host-attach", t->pid, result, 0);
          }
        } while (Process32NextW(snapshot, &entry));
      CloseHandle(snapshot);
    }
    control->installed = 0;
    control->failures = 0;
    for (size_t i = 0; i < MAX_TRACKED; i++) {
      if (entries[i].pid && !entries[i].seen)
        SecureZeroMemory(&entries[i], sizeof entries[i]);
      if (entries[i].attached)
        control->installed++;
      if (entries[i].error)
        control->failures++;
    }
  } while (WaitForSingleObject(event, 500) == WAIT_TIMEOUT);
  control->running = 0;
  DWORD cleanup_error = 0;
  for (size_t i = 0; i < MAX_TRACKED; i++)
    if (entries[i].pid && entries[i].attached) {
      DWORD result =
          inject_bridge(entries[i].pid, &entries[i].created, dll, FALSE, log_path);
      credential_log(log_path, L"host-detach", entries[i].pid, result, 0);
      if (result && remote_module(entries[i].pid, L"explorer.exe"))
        cleanup_error = result;
    }
  credential_log(log_path, L"host-stop", control->pid, 0, 0);
  UnmapViewOfFile(control);
  CloseHandle(mapping);
  CloseHandle(event);
  ReleaseMutex(mutex);
  CloseHandle(mutex);
  return (int)cleanup_error;
}
