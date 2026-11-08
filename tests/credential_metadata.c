#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <wincred.h>
int wmain(int argc, WCHAR **argv) {
  PCREDENTIALW credential = NULL;
  if (!CredReadW(L"192.168.3.98", CRED_TYPE_DOMAIN_PASSWORD, 0, &credential)) {
    wprintf(L"read=%lu\n", GetLastError());
    return 0;
  }
  wprintf(L"type=%lu persist=%lu blobBytes=%lu flags=%lu user=%s\n",
          credential->Type, credential->Persist, credential->CredentialBlobSize,
          credential->Flags, credential->UserName ? credential->UserName : L"");
  BOOL remove =
      argc == 2 && !wcscmp(argv[1], L"--delete-test") &&
      credential->Persist == CRED_PERSIST_LOCAL_MACHINE &&
      credential->UserName &&
      (!_wcsicmp(credential->UserName, L"administrator") ||
       !_wcsicmp(credential->UserName, L"192.168.3.98\\administrator"));
  CredFree(credential);
  if (remove) {
    BOOL ok = CredDeleteW(L"192.168.3.98", CRED_TYPE_DOMAIN_PASSWORD, 0);
    wprintf(L"deleted=%d error=%lu\n", ok, ok ? 0 : GetLastError());
    return ok ? 0 : 1;
  }
  return 0;
}
