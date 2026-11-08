#ifndef CREDENTIAL_CONTROL_H
#define CREDENTIAL_CONTROL_H
#include "credential_log.h"
#include <stdio.h>
#include <windows.h>
#define CREDENTIAL_CONTROL_MAGIC 0x48495543u
typedef struct CredentialControl {
  DWORD magic, pid, session, running, installed, failures;
} CredentialControl;
static __inline void credential_object_name(WCHAR *out, size_t cap,
                                            const WCHAR *kind) {
  DWORD session = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &session);
#ifdef _WIN64
  const WCHAR *architecture = L"x64";
#else
  const WCHAR *architecture = L"x86";
#endif
  swprintf_s(out, cap, L"Local\\CredentialUI.%s.%s.%lu", architecture, kind,
             session);
}
#endif
