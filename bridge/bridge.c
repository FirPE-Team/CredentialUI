#define WIN32_LEAN_AND_MEAN
#include "credential_control.h"
#include "credential_ipc.h"
#include <lm.h>
#include <sspi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <wincred.h>
#include <windows.h>
typedef ULONG(SEC_ENTRY *PROMPT_FN)(PCWSTR, PCREDUI_INFOW, ULONG, PCWSTR,
                                    PSEC_WINNT_AUTH_IDENTITY_OPAQUE,
                                    PSEC_WINNT_AUTH_IDENTITY_OPAQUE *, int *,
                                    ULONG);
typedef PVOID(WINAPI *RESOLVE_FN)(PVOID, PCIMAGE_DELAYLOAD_DESCRIPTOR, PVOID,
                                  PVOID, PIMAGE_THUNK_DATA, ULONG);
static HMODULE g_self, g_provider, g_credui;
static WCHAR g_directory[MAX_PATH];
static WCHAR g_log_path[MAX_PATH];
static SRWLOCK g_log_lock = SRWLOCK_INIT;
static void **g_slot;
static PROMPT_FN g_original;
static void **g_write_slot;
static BOOL(WINAPI *g_write_original)(PCREDENTIALW, DWORD);
static SRWLOCK g_install_lock = SRWLOCK_INIT;
static HANDLE g_queue, g_cancel, g_host_stop, g_host_process;
static volatile LONG g_users;
static volatile LONG g_enabled, g_active, g_sequence;
static void log_event(const WCHAR *event, DWORD code, DWORD detail) {
  DWORD saved_error = GetLastError();
  AcquireSRWLockShared(&g_log_lock);
  credential_log(g_log_path, event, GetCurrentProcessId(), code, detail);
  ReleaseSRWLockShared(&g_log_lock);
  SetLastError(saved_error);
}
static DWORD configure_log(const CredentialBridgeOptions *options) {
  WCHAR path[MAX_PATH] = {0};
  if (options) {
    if (options->size != sizeof *options ||
        !wmemchr(options->log_path, 0, MAX_PATH))
      return ERROR_INVALID_PARAMETER;
    if (options->log_path[0] && credential_log_path(options->log_path, path))
      return ERROR_INVALID_PARAMETER;
  }
  AcquireSRWLockExclusive(&g_log_lock);
  wcscpy_s(g_log_path, MAX_PATH, path);
  ReleaseSRWLockExclusive(&g_log_lock);
  return ERROR_SUCCESS;
}
typedef struct PendingSave {
  DWORD thread;
  ULONGLONG deadline;
  PSEC_WINNT_AUTH_IDENTITY_OPAQUE identity;
  WCHAR target[CREDENTIAL_TARGET_CAP];
} PendingSave;
static PendingSave g_pending[64];
static SRWLOCK g_save_lock = SRWLOCK_INIT;
static void **g_net_slot;
static NET_API_STATUS(NET_API_FUNCTION *g_net_original)(LMSTR, DWORD, LPBYTE,
                                                        LPDWORD);
static HANDLE g_save_worker;
static void discard_pending(PendingSave *entry) {
  if (entry->identity)
    SspiFreeAuthIdentity(entry->identity);
  SecureZeroMemory(entry, sizeof *entry);
}
static void clear_pending(BOOL all) {
  AcquireSRWLockExclusive(&g_save_lock);
  for (size_t i = 0; i < 64; i++)
    if (g_pending[i].identity &&
        (all || GetTickCount64() >= g_pending[i].deadline))
      discard_pending(&g_pending[i]);
  ReleaseSRWLockExclusive(&g_save_lock);
}
static BOOL schedule_save(PSEC_WINNT_AUTH_IDENTITY_OPAQUE identity,
                          const WCHAR *target, ULONGLONG deadline) {
  PSEC_WINNT_AUTH_IDENTITY_OPAQUE copy = NULL;
  if (SspiCopyAuthIdentity(identity, &copy) != SEC_E_OK)
    return FALSE;
  if (SspiEncryptAuthIdentity(copy) != SEC_E_OK) {
    SspiFreeAuthIdentity(copy);
    return FALSE;
  }
  BOOL inserted = FALSE;
  AcquireSRWLockExclusive(&g_save_lock);
  for (size_t i = 0; i < 64; i++)
    if (g_pending[i].identity && g_pending[i].thread == GetCurrentThreadId())
      discard_pending(&g_pending[i]);
  for (size_t i = 0; i < 64; i++)
    if (!g_pending[i].identity) {
      g_pending[i].thread = GetCurrentThreadId();
      g_pending[i].deadline = deadline;
      g_pending[i].identity = copy;
      wcscpy_s(g_pending[i].target, CREDENTIAL_TARGET_CAP, target);
      inserted = TRUE;
      break;
    }
  ReleaseSRWLockExclusive(&g_save_lock);
  if (!inserted)
    SspiFreeAuthIdentity(copy);
  return inserted;
}
static DWORD commit_save(PendingSave *pending) {
  SECURITY_STATUS status = SspiDecryptAuthIdentity(pending->identity);
  if (status != SEC_E_OK)
    return (DWORD)status;
  ULONG type = 0, bytes = 0;
  PCWSTR target = NULL, user = NULL;
  PUCHAR blob = NULL;
  status = SspiPrepareForCredWrite(pending->identity, pending->target, &type,
                                   &target, &user, &blob, &bytes);
  DWORD result = (DWORD)status;
  if (status == SEC_E_OK) {
    DWORD persistence[CRED_TYPE_MAXIMUM] = {0};
    if (!CredGetSessionTypes(CRED_TYPE_MAXIMUM, persistence))
      result = GetLastError();
    else if (type >= CRED_TYPE_MAXIMUM ||
             persistence[type] < CRED_PERSIST_LOCAL_MACHINE)
      result = ERROR_NOT_SUPPORTED;
    else {
      CREDENTIALW credential = {0};
      credential.Type = type;
      credential.TargetName = (LPWSTR)target;
      WCHAR qualified[CREDENTIAL_USERNAME_CAP];
      if (user && !wcschr(user, L'\\') && !wcschr(user, L'@')) {
        if (wcslen(pending->target) + wcslen(user) + 1 >=
            CREDENTIAL_USERNAME_CAP) {
          result = ERROR_INVALID_PARAMETER;
          goto release;
        }
        swprintf_s(qualified, CREDENTIAL_USERNAME_CAP, L"%s\\%s",
                   pending->target, user);
        credential.UserName = qualified;
      } else
        credential.UserName = (LPWSTR)user;
      credential.CredentialBlob = blob;
      credential.CredentialBlobSize = bytes;
      credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
      result = CredWriteW(&credential, 0) ? 0 : GetLastError();
    }
  }
release:
  if (blob) {
    SecureZeroMemory(blob, bytes);
    SspiLocalFree(blob);
  }
  if (target)
    SspiLocalFree((PVOID)target);
  if (user)
    SspiLocalFree((PVOID)user);
  return result;
}
static NET_API_STATUS NET_API_FUNCTION observe_net_use(LMSTR server,
                                                       DWORD level,
                                                       LPBYTE buffer,
                                                       LPDWORD parameter) {
  NET_API_STATUS status = g_net_original(server, level, buffer, parameter);
  DWORD preserved = GetLastError();
  PendingSave pending = {0};
  AcquireSRWLockExclusive(&g_save_lock);
  for (size_t i = 0; i < 64; i++)
    if (g_pending[i].identity && g_pending[i].thread == GetCurrentThreadId()) {
      /* NetUse levels all start with local-name then remote-name pointers. */
      LPCWSTR remote_name =
          buffer && level >= 1 ? ((USE_INFO_1 *)buffer)->ui1_remote : NULL;
      if (remote_name && remote_name[0] == L'\\' && remote_name[1] == L'\\') {
        const WCHAR *host = remote_name + 2, *slash = wcschr(host, L'\\');
        size_t n = slash ? (size_t)(slash - host) : wcslen(host);
        if (wcslen(g_pending[i].target) == n &&
            !_wcsnicmp(host, g_pending[i].target, n)) {
          pending = g_pending[i];
          SecureZeroMemory(&g_pending[i], sizeof g_pending[i]);
        }
      }
      break;
    }
  ReleaseSRWLockExclusive(&g_save_lock);
  if (pending.identity) {
    DWORD result =
        status ? status
               : (GetTickCount64() >= pending.deadline ? ERROR_TIMEOUT
                                                       : commit_save(&pending));
    log_event(L"save-after-connect", result, status);
    discard_pending(&pending);
  }
  SetLastError(preserved);
  return status;
}
static BOOL stopped(void);
static DWORD WINAPI expire_saves(void *unused) {
  (void)unused;
  while (WaitForSingleObject(g_cancel, 1000) == WAIT_TIMEOUT && !stopped())
    clear_pending(FALSE);
  clear_pending(TRUE);
  return 0;
}
static void install_net_observer(void) {
  BYTE *base = (BYTE *)g_provider;
  IMAGE_NT_HEADERS *nt =
      (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
  DWORD rva =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
          .VirtualAddress;
  RESOLVE_FN resolve = (RESOLVE_FN)(void (*)(void))GetProcAddress(
      GetModuleHandleW(L"kernelbase.dll"), "ResolveDelayLoadedAPI");
  if (!rva || !resolve)
    return;
  for (PIMAGE_DELAYLOAD_DESCRIPTOR d =
           (PIMAGE_DELAYLOAD_DESCRIPTOR)(base + rva);
       d->DllNameRVA; d++) {
    if (!d->Attributes.RvaBased)
      continue;
    IMAGE_THUNK_DATA *names =
                         (IMAGE_THUNK_DATA *)(base + d->ImportNameTableRVA),
                     *iat =
                         (IMAGE_THUNK_DATA *)(base + d->ImportAddressTableRVA);
    for (size_t i = 0; names[i].u1.AddressOfData; i++) {
      if (IMAGE_SNAP_BY_ORDINAL(names[i].u1.Ordinal))
        continue;
      IMAGE_IMPORT_BY_NAME *name =
          (IMAGE_IMPORT_BY_NAME *)(base + names[i].u1.AddressOfData);
      if (strcmp((char *)name->Name, "NetUseAdd"))
        continue;
      if ((void *)iat[i].u1.Function == (void *)observe_net_use)
        return;
      void *native = resolve(base, d, NULL, NULL, &iat[i], 0);
      if (!native)
        return;
      DWORD old, tmp;
      void **slot = (void **)&iat[i].u1.Function;
      if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old))
        return;
      g_net_original = (NET_API_STATUS(NET_API_FUNCTION *)(LMSTR, DWORD, LPBYTE,
                                                           LPDWORD))native;
      if (InterlockedCompareExchangePointer(slot, (PVOID)observe_net_use,
                                            native) == native)
        g_net_slot = slot;
      VirtualProtect(slot, sizeof(void *), old, &tmp);
      return;
    }
  }
}
static BOOL WINAPI observe_write(PCREDENTIALW credential, DWORD flags) {
  BOOL ok = g_write_original(credential, flags);
  DWORD error = ok ? 0 : GetLastError();
  log_event(L"system-save", error, credential ? credential->Persist : 0);
  if (!ok)
    SetLastError(error);
  return ok;
}
static void install_save_observer(void) {
  BYTE *base = (BYTE *)g_provider;
  IMAGE_NT_HEADERS *nt =
      (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
  DWORD rva =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
          .VirtualAddress;
  RESOLVE_FN resolve = (RESOLVE_FN)(void (*)(void))GetProcAddress(
      GetModuleHandleW(L"kernelbase.dll"), "ResolveDelayLoadedAPI");
  if (!rva || !resolve)
    return;
  for (PIMAGE_DELAYLOAD_DESCRIPTOR d =
           (PIMAGE_DELAYLOAD_DESCRIPTOR)(base + rva);
       d->DllNameRVA; d++) {
    if (!d->Attributes.RvaBased)
      continue;
    IMAGE_THUNK_DATA *names =
                         (IMAGE_THUNK_DATA *)(base + d->ImportNameTableRVA),
                     *iat =
                         (IMAGE_THUNK_DATA *)(base + d->ImportAddressTableRVA);
    for (size_t i = 0; names[i].u1.AddressOfData; i++) {
      if (IMAGE_SNAP_BY_ORDINAL(names[i].u1.Ordinal))
        continue;
      IMAGE_IMPORT_BY_NAME *name =
          (IMAGE_IMPORT_BY_NAME *)(base + names[i].u1.AddressOfData);
      if (strcmp((char *)name->Name, "CredWriteW"))
        continue;
      if ((void *)iat[i].u1.Function == (void *)observe_write)
        return;
      void *native = resolve(base, d, NULL, NULL, &iat[i], 0);
      if (!native)
        return;
      DWORD old, tmp;
      void **slot = (void **)&iat[i].u1.Function;
      if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old))
        return;
      g_write_original = (BOOL(WINAPI *)(PCREDENTIALW, DWORD))native;
      if (InterlockedCompareExchangePointer(slot, (PVOID)observe_write,
                                            native) == native)
        g_write_slot = slot;
      VirtualProtect(slot, sizeof(void *), old, &tmp);
      return;
    }
  }
}
static BOOL stopped(void) {
  return (g_cancel && WaitForSingleObject(g_cancel, 0) == WAIT_OBJECT_0) ||
         (g_host_stop &&
          WaitForSingleObject(g_host_stop, 0) == WAIT_OBJECT_0) ||
         (g_host_process &&
          WaitForSingleObject(g_host_process, 0) == WAIT_OBJECT_0);
}
static DWORD remaining(ULONGLONG deadline) {
  ULONGLONG now = GetTickCount64();
  return now >= deadline ? 0 : (DWORD)(deadline - now);
}
static DWORD gui_request(const CredentialIpcRequest *request,
                         CredentialIpcResponse *response, DWORD *child_pid,
                         ULONGLONG deadline) {
  HANDLE req_read = NULL, req_write = NULL, res_read = NULL, res_write = NULL,
         job = NULL;
  SIZE_T attr_bytes = 0;
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
  BOOL attrs_ready = FALSE;
  SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
  STARTUPINFOEXW start = {0};
  PROCESS_INFORMATION process = {0};
  WCHAR exe[MAX_PATH], command[2 * MAX_PATH + 100];
  DWORD result = ERROR_GEN_FAILURE;
  HANDLE child_cancel = NULL;
  if (!CreatePipe(&req_read, &req_write, &sa, 4096) ||
      !CreatePipe(&res_read, &res_write, &sa, 4096))
    goto failed;
  if (!SetHandleInformation(req_write, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(res_read, HANDLE_FLAG_INHERIT, 0))
    goto failed;
  InitializeProcThreadAttributeList(NULL, 1, 0, &attr_bytes);
  attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),
                                                  HEAP_ZERO_MEMORY, attr_bytes);
  if (!attrs) {
    result = ERROR_OUTOFMEMORY;
    goto done;
  }
  if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_bytes))
    goto failed;
  attrs_ready = TRUE;
  if (!DuplicateHandle(GetCurrentProcess(), g_cancel, GetCurrentProcess(),
                       &child_cancel, SYNCHRONIZE, TRUE, 0))
    goto failed;
  HANDLE inherit[3] = {req_read, res_write, child_cancel};
  if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 inherit, sizeof inherit, NULL, NULL))
    goto failed;
  swprintf_s(exe, MAX_PATH, L"%s\\CredentialUI.exe", g_directory);
  swprintf_s(command, _countof(command), L"\"%s\" --ipc %llx %llx %llx", exe,
             (unsigned long long)(uintptr_t)req_read,
             (unsigned long long)(uintptr_t)res_write,
             (unsigned long long)(uintptr_t)child_cancel);
  start.StartupInfo.cb = sizeof start;
  start.lpAttributeList = attrs;
  if (!CreateProcessW(exe, command, NULL, NULL, TRUE,
                      CREATE_NO_WINDOW | CREATE_SUSPENDED |
                          EXTENDED_STARTUPINFO_PRESENT,
                      NULL, g_directory, &start.StartupInfo, &process))
    goto failed;
  job = CreateJobObjectW(NULL, NULL);
  if (!job)
    goto failed;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                               sizeof limits) ||
      !AssignProcessToJobObject(job, process.hProcess))
    goto failed;
  *child_pid = process.dwProcessId;
  AllowSetForegroundWindow(process.dwProcessId);
  CloseHandle(req_read);
  req_read = NULL;
  CloseHandle(res_write);
  res_write = NULL;
  if (ResumeThread(process.hThread) == (DWORD)-1)
    goto failed;
  result = credential_ipc_write(req_write, request, sizeof *request);
  if (result)
    goto done;
  CloseHandle(req_write);
  req_write = NULL;
  for (;;) {
    if (stopped()) {
      result = ERROR_CANCELLED;
      goto done;
    }
    if (!remaining(deadline)) {
      result = ERROR_TIMEOUT;
      goto done;
    }
    if (request->owner && !IsWindow((HWND)(ULONG_PTR)request->owner)) {
      result = ERROR_CANCELLED;
      goto done;
    }
    DWORD available = 0;
    if (!PeekNamedPipe(res_read, NULL, 0, NULL, &available, NULL)) {
      result = ERROR_BROKEN_PIPE;
      goto done;
    }
    if (available >= sizeof *response)
      break;
    DWORD wait = WaitForSingleObject(process.hProcess, 25);
    if (wait == WAIT_OBJECT_0) {
      if (!PeekNamedPipe(res_read, NULL, 0, NULL, &available, NULL) ||
          available < sizeof *response) {
        result = ERROR_BROKEN_PIPE;
        goto done;
      }
      break;
    }
    if (wait == WAIT_FAILED)
      goto failed;
  }
  result = credential_ipc_read(res_read, response, sizeof *response,
                               remaining(deadline), g_cancel);
  if (result)
    goto done;
  if (!credential_ipc_response_valid(response, request->request_id)) {
    result = ERROR_INVALID_DATA;
    goto done;
  }
  result = response->result;
  if (result == ERROR_SUCCESS && response->save &&
      !(request->options & CREDENTIAL_IPC_SAVE_ALLOWED)) {
    result = ERROR_INVALID_DATA;
    goto done;
  }
  goto done;

failed:
  result = GetLastError();
  if (!result)
    result = ERROR_GEN_FAILURE;
done:
  if (process.hProcess) {
    if (WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT)
      TerminateProcess(process.hProcess, ERROR_CANCELLED);
    CloseHandle(process.hProcess);
  }
  if (child_cancel)
    CloseHandle(child_cancel);
  if (process.hThread)
    CloseHandle(process.hThread);
  if (job)
    CloseHandle(job);
  if (attrs) {
    if (attrs_ready)
      DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);
  }
  if (req_read)
    CloseHandle(req_read);
  if (req_write)
    CloseHandle(req_write);
  if (res_read)
    CloseHandle(res_read);
  if (res_write)
    CloseHandle(res_write);
  return result;
}
static BOOL copy_text(WCHAR *out, size_t cap, const WCHAR *text) {
  if (!text) {
    out[0] = 0;
    return TRUE;
  }
  if (wcslen(text) >= cap)
    return FALSE;
  wcscpy_s(out, cap, text);
  return TRUE;
}
static ULONG SEC_ENTRY replacement(PCWSTR target, PCREDUI_INFOW ui, ULONG error,
                                   PCWSTR package,
                                   PSEC_WINNT_AUTH_IDENTITY_OPAQUE input,
                                   PSEC_WINNT_AUTH_IDENTITY_OPAQUE *output,
                                   int *save, ULONG flags) {
  PROMPT_FN original = g_original;
  if (!InterlockedCompareExchange(&g_enabled, 0, 0) || stopped() || !target ||
      !target[0] || !package || _wcsicmp(package, L"Negotiate") ||
      (flags & ~15u) || !output)
    return original(target, ui, error, package, input, output, save, flags);
  InterlockedIncrement(&g_users);
  ULONGLONG deadline = GetTickCount64() + CREDENTIAL_TIMEOUT_MS;
  for (;;) {
    if (stopped() || !g_enabled) {
      InterlockedDecrement(&g_users);
      return ERROR_CANCELLED;
    }
    if (!remaining(deadline)) {
      InterlockedDecrement(&g_users);
      return ERROR_TIMEOUT;
    }
    if (WaitForSingleObject(g_queue, 25) == WAIT_OBJECT_0)
      break;
  }
  InterlockedIncrement(&g_active);
  CredentialIpcRequest request = {0};
  CredentialIpcResponse response = {0};
  DWORD child = 0, result = 0;
  BOOL fallback = FALSE;
  request.magic = CREDENTIAL_IPC_MAGIC;
  request.version = CREDENTIAL_IPC_VERSION;
  request.size = sizeof request;
  request.request_id = ((uint64_t)GetCurrentProcessId() << 32) |
                       (DWORD)InterlockedIncrement(&g_sequence);
  request.parent_pid = GetCurrentProcessId();
  request.timeout_ms = remaining(deadline);
  if (request.timeout_ms < 1000) {
    result = ERROR_TIMEOUT;
    goto done;
  }
  request.auth_error = error;
  request.flags = flags;
  if (input)
    request.options |= CREDENTIAL_IPC_INPUT_PRESENT;
  if (save && !(flags & SSPIPFC_NO_CHECKBOX))
    request.options |= CREDENTIAL_IPC_SAVE_ALLOWED;
  if (save && *save && (request.options&CREDENTIAL_IPC_SAVE_ALLOWED))
    request.options |= CREDENTIAL_IPC_SAVE_CHECKED;
  if (!copy_text(request.target, CREDENTIAL_TARGET_CAP, target) ||
      !copy_text(request.package, CREDENTIAL_PACKAGE_CAP, package)) {
    fallback = TRUE;
    goto done;
  }
  if (ui) {
    request.owner = (uint64_t)(ULONG_PTR)ui->hwndParent;
    if (!copy_text(request.caption, 128, ui->pszCaptionText) ||
        !copy_text(request.message, CREDENTIAL_TEXT_CAP, ui->pszMessageText)) {
      fallback = TRUE;
      goto done;
    }
  }
  if (input) {
    PCWSTR user = NULL, domain = NULL, packed = NULL;
    SECURITY_STATUS status =
        SspiEncodeAuthIdentityAsStrings(input, &user, &domain, &packed);
    if (status != SEC_E_OK) {
      fallback = TRUE;
      goto done;
    }
    if (user && CredIsMarshaledCredentialW(user)) {
      fallback = TRUE;
    }
    if (user && user[0]) {
      size_t needed =
          wcslen(user) + (domain && domain[0] ? wcslen(domain) + 1 : 0);
      if (needed >= CREDENTIAL_USERNAME_CAP)
        fallback = TRUE;
      else if (domain && domain[0])
        swprintf_s(request.username, CREDENTIAL_USERNAME_CAP, L"%s\\%s", domain,
                   user);
      else
        wcscpy_s(request.username, CREDENTIAL_USERNAME_CAP, user);
    }
    if (packed) {
      SecureZeroMemory((PVOID)packed, wcslen(packed) * sizeof(WCHAR));
    }
    if (user)
      SspiLocalFree((PVOID)user);
    if (domain)
      SspiLocalFree((PVOID)domain);
    if (packed)
      SspiLocalFree((PVOID)packed);
    if (fallback)
      goto done;
  }
  log_event(L"prompt", error, (DWORD)request.request_id);
  result = gui_request(&request, &response, &child, deadline);
  if (!result) {
    WCHAR *user = response.username, *domain = L"",
          *slash = wcschr(user, L'\\');
    if (slash) {
      *slash = 0;
      domain = user;
      user = slash + 1;
      if (!domain[0] || !user[0] || wcschr(user, L'\\'))
        result = ERROR_INVALID_PARAMETER;
    }
    if (!result) {
      PSEC_WINNT_AUTH_IDENTITY_OPAQUE identity = NULL;
      SECURITY_STATUS status = SspiEncodeStringsAsAuthIdentity(
          user, domain, response.password, &identity);
      if (status == SEC_E_OK) {
        if (response.save && !(flags & SSPIPFC_CREDPROV_DO_NOT_SAVE)) {
          if (!g_net_slot || !schedule_save(identity, target, deadline))
            log_event(L"save-schedule", ERROR_NOT_SUPPORTED, 0);
        }
        *output = identity;
        if (save)
          *save = (int)response.save;
      } else
        result = (DWORD)status;
    }
  }
  if (result != ERROR_SUCCESS && result != ERROR_CANCELLED &&
      result != ERROR_TIMEOUT)
    fallback = TRUE;
  log_event(L"result", result, response.save);
done:
  SecureZeroMemory(&response, sizeof response);
  SecureZeroMemory(&request, sizeof request);
  InterlockedDecrement(&g_active);
  ReleaseSemaphore(g_queue, 1, NULL);
  InterlockedDecrement(&g_users);
  if (fallback) {
    log_event(L"fallback", result, 0);
    return original(target, ui, error, package, input, output, save, flags);
  }
  return result;
}
__declspec(dllexport) DWORD WINAPI ProbeStart(void *configuration) {
  DWORD result = ERROR_NOT_FOUND;
  AcquireSRWLockExclusive(&g_install_lock);
  result = configure_log((const CredentialBridgeOptions *)configuration);
  if (result) {
    ReleaseSRWLockExclusive(&g_install_lock);
    return result;
  }
  result = ERROR_NOT_FOUND;
  if (!g_directory[0]) {
    GetModuleFileNameW(g_self, g_directory, MAX_PATH);
    WCHAR *slash = wcsrchr(g_directory, L'\\');
    if (!slash) {
      result = ERROR_INVALID_NAME;
      goto done;
    }
    *slash = 0;
  }
  if (g_slot && *g_slot == (void *)replacement && !stopped()) {
    result = 0;
    goto done;
  }
  if (g_users) {
    result = ERROR_BUSY;
    goto done;
  }
  if (!g_queue)
    g_queue = CreateSemaphoreW(NULL, 1, 1, NULL);
  if (!g_cancel)
    g_cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
  else
    ResetEvent(g_cancel);
  if (!g_queue || !g_cancel) {
    result = GetLastError();
    goto done;
  }
  if (g_host_stop) {
    CloseHandle(g_host_stop);
    g_host_stop = NULL;
  }
  WCHAR stop_name[128];
  credential_object_name(stop_name, 128, L"Stop");
  g_host_stop = OpenEventW(SYNCHRONIZE, FALSE, stop_name);
  if (g_host_process) {
    CloseHandle(g_host_process);
    g_host_process = NULL;
  }
  credential_object_name(stop_name, 128, L"Control");
  HANDLE mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, stop_name);
  if (mapping) {
    CredentialControl *control = (CredentialControl *)MapViewOfFile(
        mapping, FILE_MAP_READ, 0, 0, sizeof(CredentialControl));
    if (control && control->magic == CREDENTIAL_CONTROL_MAGIC)
      g_host_process = OpenProcess(SYNCHRONIZE, FALSE, control->pid);
    if (control)
      UnmapViewOfFile(control);
    CloseHandle(mapping);
  }
  if (g_slot && *g_slot == (void *)replacement) {
    InterlockedExchange(&g_enabled, 1);
    install_save_observer();
    install_net_observer();
    if (g_save_worker &&
        WaitForSingleObject(g_save_worker, 0) == WAIT_OBJECT_0) {
      CloseHandle(g_save_worker);
      g_save_worker = NULL;
    }
    if (!g_save_worker)
      g_save_worker = CreateThread(NULL, 0, expire_saves, NULL, 0, NULL);
    result = 0;
    goto done;
  }
  if (!g_provider)
    g_provider = LoadLibraryW(L"ntlanman.dll");
  if (!g_provider) {
    result = GetLastError();
    goto done;
  }
  if (!g_credui)
    g_credui = LoadLibraryW(L"credui.dll");
  if (!g_credui) {
    result = GetLastError();
    goto done;
  }
  PROMPT_FN expected = (PROMPT_FN)(void (*)(void))GetProcAddress(
      g_credui, "SspiPromptForCredentialsW");
  if (!expected) {
    result = GetLastError();
    goto done;
  }
  BYTE *base = (BYTE *)g_provider;
  IMAGE_NT_HEADERS *nt =
      (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
  DWORD rva =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
          .VirtualAddress;
  if (!rva)
    goto done;
  for (PIMAGE_DELAYLOAD_DESCRIPTOR desc =
           (PIMAGE_DELAYLOAD_DESCRIPTOR)(base + rva);
       desc->DllNameRVA; desc++) {
    if (!desc->Attributes.RvaBased)
      continue;
    IMAGE_THUNK_DATA *names =
                         (IMAGE_THUNK_DATA *)(base + desc->ImportNameTableRVA),
                     *iat = (IMAGE_THUNK_DATA *)(base +
                                                 desc->ImportAddressTableRVA);
    for (size_t i = 0; names[i].u1.AddressOfData; i++) {
      if (IMAGE_SNAP_BY_ORDINAL(names[i].u1.Ordinal))
        continue;
      IMAGE_IMPORT_BY_NAME *name =
          (IMAGE_IMPORT_BY_NAME *)(base + names[i].u1.AddressOfData);
      if (strcmp((char *)name->Name, "SspiPromptForCredentialsW"))
        continue;
      if ((void *)iat[i].u1.Function != (void *)expected) {
        RESOLVE_FN resolve = (RESOLVE_FN)(void (*)(void))GetProcAddress(
            GetModuleHandleW(L"kernelbase.dll"), "ResolveDelayLoadedAPI");
        if (!resolve) {
          result = ERROR_PROC_NOT_FOUND;
          goto done;
        }
        PVOID resolved = resolve(base, desc, NULL, NULL, &iat[i], 0);
        log_event(L"resolve", resolved ? 0 : ERROR_PROC_NOT_FOUND, 0);
        if (resolved != (PVOID)expected ||
            (void *)iat[i].u1.Function != (void *)expected) {
          result = ERROR_INVALID_FUNCTION;
          goto done;
        }
      }
      void **slot = (void **)&iat[i].u1.Function;
      DWORD old, tmp;
      if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old)) {
        result = GetLastError();
        goto done;
      }
      g_original = expected;
      g_slot = slot;
      InterlockedExchange(&g_enabled, 1);
      PVOID prior = InterlockedCompareExchangePointer(slot, (PVOID)replacement,
                                                      (PVOID)expected);
      VirtualProtect(slot, sizeof(void *), old, &tmp);
      if (prior != (PVOID)expected) {
        g_slot = NULL;
        InterlockedExchange(&g_enabled, 0);
        result = ERROR_BUSY;
        goto done;
      }
      install_save_observer();
      install_net_observer();
      if (g_save_worker &&
          WaitForSingleObject(g_save_worker, 0) == WAIT_OBJECT_0) {
        CloseHandle(g_save_worker);
        g_save_worker = NULL;
      }
      if (!g_save_worker)
        g_save_worker = CreateThread(NULL, 0, expire_saves, NULL, 0, NULL);
      result = 0;
      log_event(L"installed", 0, (DWORD)((BYTE *)slot - base));
      goto done;
    }
  }
done:
  log_event(L"install", result, 0);
  ReleaseSRWLockExclusive(&g_install_lock);
  return result;
}
__declspec(dllexport) DWORD WINAPI ProbeStop(void *configuration) {
  DWORD result = 0;
  AcquireSRWLockExclusive(&g_install_lock);
  result = configure_log((const CredentialBridgeOptions *)configuration);
  if (result) {
    ReleaseSRWLockExclusive(&g_install_lock);
    return result;
  }
  InterlockedExchange(&g_enabled, 0);
  if (g_cancel)
    SetEvent(g_cancel);
  if (g_slot) {
    DWORD old, tmp;
    if (!VirtualProtect(g_slot, sizeof(void *), PAGE_READWRITE, &old)) {
      result = GetLastError();
      goto done;
    }
    PVOID previous = InterlockedCompareExchangePointer(
        g_slot, (PVOID)g_original, (PVOID)replacement);
    VirtualProtect(g_slot, sizeof(void *), old, &tmp);
    if (previous != (PVOID)replacement && previous != (PVOID)g_original)
      result = ERROR_BUSY;
    else
      g_slot = NULL;
  }
done:
  if (g_write_slot) {
    DWORD old, tmp;
    if (VirtualProtect(g_write_slot, sizeof(void *), PAGE_READWRITE, &old)) {
      InterlockedCompareExchangePointer(g_write_slot, (PVOID)g_write_original,
                                        (PVOID)observe_write);
      VirtualProtect(g_write_slot, sizeof(void *), old, &tmp);
      g_write_slot = NULL;
    }
  }
  if (g_net_slot) {
    DWORD old, tmp;
    if (VirtualProtect(g_net_slot, sizeof(void *), PAGE_READWRITE, &old)) {
      InterlockedCompareExchangePointer(g_net_slot, (PVOID)g_net_original,
                                        (PVOID)observe_net_use);
      VirtualProtect(g_net_slot, sizeof(void *), old, &tmp);
      g_net_slot = NULL;
    }
  }
  clear_pending(TRUE);
  if (g_save_worker &&
      WaitForSingleObject(g_save_worker, 2000) == WAIT_OBJECT_0) {
    CloseHandle(g_save_worker);
    g_save_worker = NULL;
  }
  log_event(L"stopped", result, (DWORD)g_active);
  ReleaseSRWLockExclusive(&g_install_lock);
  return result;
}
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    g_self = module;
    DisableThreadLibraryCalls(module);
  }
  return TRUE;
}
