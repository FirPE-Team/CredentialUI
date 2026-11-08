#ifndef CREDENTIAL_IPC_H
#define CREDENTIAL_IPC_H
#include "credential_ui.h"
#include <stdint.h>
#define CREDENTIAL_IPC_MAGIC 0x32495543u
#define CREDENTIAL_IPC_VERSION 2u
#define CREDENTIAL_TIMEOUT_MS 600000u
#define CREDENTIAL_IPC_INPUT_PRESENT 1u
#define CREDENTIAL_IPC_SAVE_ALLOWED 2u
#define CREDENTIAL_IPC_SAVE_CHECKED 4u
/* Explicit 8-byte packing and fixed-width owner/request id: independent of
 * pointer width. */
#pragma pack(push, 8)
typedef struct CredentialIpcRequest {
  DWORD magic, version, size, auth_error;
  uint64_t request_id, owner;
  DWORD flags, timeout_ms, parent_pid, options;
  WCHAR target[CREDENTIAL_TARGET_CAP];
  WCHAR package[CREDENTIAL_PACKAGE_CAP];
  WCHAR caption[128];
  WCHAR message[CREDENTIAL_TEXT_CAP];
  WCHAR username[CREDENTIAL_USERNAME_CAP];
} CredentialIpcRequest;
typedef struct CredentialIpcResponse {
  DWORD magic, version, size, result;
  uint64_t request_id;
  DWORD save, reserved;
  WCHAR username[CREDENTIAL_USERNAME_CAP];
  WCHAR password[CREDENTIAL_PASSWORD_CAP];
} CredentialIpcResponse;
#pragma pack(pop)
typedef char credential_ipc_request_fits_pipe
    [(sizeof(CredentialIpcRequest) <= 4096) ? 1 : -1];
typedef char credential_ipc_response_fits_pipe
    [(sizeof(CredentialIpcResponse) <= 4096) ? 1 : -1];
static __inline BOOL
credential_ipc_request_valid(const CredentialIpcRequest *q) {
  return q && q->magic == CREDENTIAL_IPC_MAGIC &&
         q->version == CREDENTIAL_IPC_VERSION && q->size == sizeof *q &&
         q->request_id && q->parent_pid && q->timeout_ms >= 1000 &&
         q->timeout_ms <= CREDENTIAL_TIMEOUT_MS && !(q->flags & ~15u) &&
         !(q->options & ~7u) &&
         (!(q->options&CREDENTIAL_IPC_SAVE_CHECKED)||(q->options&CREDENTIAL_IPC_SAVE_ALLOWED)) &&
         (!(q->flags&2u)||!(q->options&CREDENTIAL_IPC_SAVE_ALLOWED)) && q->target[0] &&
         !q->target[CREDENTIAL_TARGET_CAP - 1] && q->package[0] &&
         !q->package[CREDENTIAL_PACKAGE_CAP - 1] && !q->caption[127] &&
         !q->message[CREDENTIAL_TEXT_CAP - 1] &&
         !q->username[CREDENTIAL_USERNAME_CAP - 1];
}
static __inline BOOL
credential_ipc_response_valid(const CredentialIpcResponse *r, uint64_t id) {
  return r && r->magic == CREDENTIAL_IPC_MAGIC &&
         r->version == CREDENTIAL_IPC_VERSION && r->size == sizeof *r &&
         r->request_id == id && r->save <= 1 && !r->reserved &&
         !r->username[CREDENTIAL_USERNAME_CAP - 1] &&
         !r->password[CREDENTIAL_PASSWORD_CAP - 1] &&
         (r->result == ERROR_SUCCESS
              ? r->username[0] != 0
              : ((r->result == ERROR_CANCELLED || r->result == ERROR_TIMEOUT) &&
                 !r->save && !r->username[0] && !r->password[0]));
}
/* No blocking ReadFile until PeekNamedPipe has proved bytes are available. */
static __inline DWORD credential_ipc_read(HANDLE pipe, void *buffer, DWORD size,
                                          DWORD timeout, HANDLE cancel) {
  BYTE *at = (BYTE *)buffer;
  ULONGLONG start = GetTickCount64();
  while (size) {
    DWORD available = 0, received = 0;
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
      return ERROR_CANCELLED;
    if (GetTickCount64() - start >= timeout)
      return ERROR_TIMEOUT;
    if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL))
      return GetLastError();
    if (!available) {
      Sleep(10);
      continue;
    }
    DWORD chunk = available < size ? available : size;
    if (!ReadFile(pipe, at, chunk, &received, NULL) || !received)
      return ERROR_BROKEN_PIPE;
    at += received;
    size -= received;
  }
  return ERROR_SUCCESS;
}
static __inline DWORD credential_ipc_write(HANDLE pipe, const void *buffer,
                                           DWORD size) {
  DWORD written = 0;
  /* Each protocol message fits into its fresh 4096-byte pipe; one
   * writer/message per pipe. */
  if (!WriteFile(pipe, buffer, size, &written, NULL))
    return GetLastError();
  return written == size ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
}
#endif
