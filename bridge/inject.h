#ifndef CREDENTIAL_INJECT_H
#define CREDENTIAL_INJECT_H
#include "credential_log.h"
#include <stdint.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <windows.h>
/* WOW64 state must match: x86 can target native x86 or WOW64 x86,
 * while x64 can target native x64. Cross-bitness injection is unsupported. */
static DWORD same_architecture(HANDLE process) {
  BOOL current_wow = FALSE, target_wow = FALSE;
  if (!IsWow64Process(GetCurrentProcess(), &current_wow) ||
      !IsWow64Process(process, &target_wow))
    return GetLastError();
  return current_wow == target_wow ? ERROR_SUCCESS : ERROR_BAD_EXE_FORMAT;
}
static uintptr_t remote_module(DWORD pid, const WCHAR *name) {
  HANDLE snapshot =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snapshot == INVALID_HANDLE_VALUE)
    return 0;
  MODULEENTRY32W entry = {0};
  entry.dwSize = sizeof entry;
  uintptr_t base = 0;
  if (Module32FirstW(snapshot, &entry))
    do {
      if (!_wcsicmp(wcschr(name, L'\\') ? entry.szExePath : entry.szModule,
                    name)) {
        base = (uintptr_t)entry.modBaseAddr;
        break;
      }
    } while (Module32NextW(snapshot, &entry));
  CloseHandle(snapshot);
  return base;
}
static DWORD remote_call(HANDLE process, uintptr_t address, void *argument,
                         DWORD *code) {
  HANDLE thread = CreateRemoteThread(
      process, NULL, 0, (LPTHREAD_START_ROUTINE)address, argument, 0, NULL);
  if (!thread)
    return GetLastError();
  DWORD wait = WaitForSingleObject(thread, 5000);
  DWORD result = 0;
  if (wait == WAIT_OBJECT_0) {
    if (!GetExitCodeThread(thread, code))
      result = GetLastError();
  } else
    result = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
  CloseHandle(thread);
  return result;
}
static DWORD inject_bridge(DWORD pid, const FILETIME *expected,
                           const WCHAR *dll, BOOL install,
                           const WCHAR *log_path) {
  HANDLE process =
      OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                  FALSE, pid);
  if (!process)
    return GetLastError();
  DWORD result = 0, code = 0;
  FILETIME created, exit, kernel, user;
  if (!GetProcessTimes(process, &created, &exit, &kernel, &user)) {
    result = GetLastError();
    goto done;
  }
  if (expected && CompareFileTime(expected, &created)) {
    result = ERROR_INVALID_PARAMETER;
    goto done;
  }
  result = same_architecture(process);
  if (result) {
    goto done;
  }
  uintptr_t remote = remote_module(pid, dll);
  if (!remote) {
    if (!install)
      goto done;
    size_t bytes = (wcslen(dll) + 1) * sizeof(WCHAR);
    void *buffer = VirtualAllocEx(process, NULL, bytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
      result = GetLastError();
      goto done;
    }
    if (!WriteProcessMemory(process, buffer, dll, bytes, NULL)) {
      result = GetLastError();
      VirtualFreeEx(process, buffer, 0, MEM_RELEASE);
      goto done;
    }
    uintptr_t load = (uintptr_t)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HMODULE origin = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)load, &origin);
    WCHAR path[MAX_PATH];
    if (!origin || !GetModuleFileNameW(origin, path, MAX_PATH)) {
      result = ERROR_PROC_NOT_FOUND;
      goto done;
    }
    WCHAR *module_name = wcsrchr(path, L'\\');
    module_name = module_name ? module_name + 1 : path;
    uintptr_t base = remote_module(pid, module_name);
    if (!base) {
      result = ERROR_MOD_NOT_FOUND;
      goto done;
    }
    result =
        remote_call(process, base + load - (uintptr_t)origin, buffer, &code);
    /* A timed-out remote loader may still use its argument. Do not free it in
     * that case. */
    if (result != ERROR_TIMEOUT)
      VirtualFreeEx(process, buffer, 0, MEM_RELEASE);
    if (result)
      goto done;
    remote = remote_module(pid, dll);
    if (!remote) {
      result = ERROR_DLL_INIT_FAILED;
      goto done;
    }
  }
  HMODULE image = LoadLibraryExW(dll, NULL, DONT_RESOLVE_DLL_REFERENCES);
  if (!image) {
    result = GetLastError();
    goto done;
  }
  FARPROC entry = GetProcAddress(image, install ? "ProbeStart" : "ProbeStop");
  if (!entry) {
    result = ERROR_PROC_NOT_FOUND;
    FreeLibrary(image);
    goto done;
  }
  CredentialBridgeOptions options = {0};
  options.size = sizeof options;
  if (log_path && *log_path &&
      credential_log_path(log_path, options.log_path)) {
    result = ERROR_INVALID_PARAMETER;
    FreeLibrary(image);
    goto done;
  }
  void *configuration = VirtualAllocEx(process, NULL, sizeof options,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!configuration) {
    result = GetLastError();
    FreeLibrary(image);
    goto done;
  }
  if (!WriteProcessMemory(process, configuration, &options, sizeof options,
                           NULL)) {
    result = GetLastError();
    VirtualFreeEx(process, configuration, 0, MEM_RELEASE);
    FreeLibrary(image);
    goto done;
  }
  result = remote_call(process, remote + (uintptr_t)entry - (uintptr_t)image,
                       configuration, &code);
  /* A timed-out bridge call may still be reading the configuration. */
  if (result != ERROR_TIMEOUT)
    VirtualFreeEx(process, configuration, 0, MEM_RELEASE);
  FreeLibrary(image);
  if (!result)
    result = code;
done:
  CloseHandle(process);
  return result;
}
#endif
