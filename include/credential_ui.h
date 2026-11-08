#ifndef CREDENTIAL_UI_H
#define CREDENTIAL_UI_H
#include <windows.h>
#define CREDENTIAL_TARGET_CAP 256
#define CREDENTIAL_PACKAGE_CAP 64
#define CREDENTIAL_TEXT_CAP 512
#define CREDENTIAL_USERNAME_CAP 512
#define CREDENTIAL_PASSWORD_CAP 512
typedef struct CredentialUiRequest {
  HWND owner;
  HANDLE parent_process, cancel;
  ULONGLONG deadline;
  DWORD auth_error;
  BOOL retry, allow_save, save;
  WCHAR target[CREDENTIAL_TARGET_CAP], caption[128],
      message[CREDENTIAL_TEXT_CAP];
  WCHAR username[CREDENTIAL_USERNAME_CAP];
} CredentialUiRequest;
typedef struct CredentialUiResult {
  DWORD result;
  BOOL save;
  WCHAR username[CREDENTIAL_USERNAME_CAP], password[CREDENTIAL_PASSWORD_CAP];
} CredentialUiResult;
int credential_ui_run(HINSTANCE instance, int show_command);
DWORD credential_ui_prompt(HINSTANCE instance, int show_command,
                           const CredentialUiRequest *request,
                           CredentialUiResult *result);
void credential_ui_set_status(HWND window, const wchar_t *text);
#endif
