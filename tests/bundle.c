#define WIN32_LEAN_AND_MEAN
#include "credential_bundle.h"
#include <stdio.h>
#include <wchar.h>
static int failures;
#define CHECK(x) do { if (!(x)) { printf("FAIL line=%d %s error=%lu\n", __LINE__, #x, GetLastError()); failures++; } } while (0)
typedef struct Preparation {
  HMODULE image;
  const WCHAR *source;
  WCHAR path[MAX_PATH];
  DWORD result;
} Preparation;
static DWORD WINAPI prepare(void *data) {
  Preparation *p = (Preparation *)data;
  p->result = credential_bundle_prepare(p->image, p->source, p->path);
  return 0;
}
static void corrupt(const WCHAR *path, BOOL truncate) {
  HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                            truncate ? CREATE_ALWAYS : OPEN_EXISTING, 0, NULL);
  CHECK(file != INVALID_HANDLE_VALUE);
  if (file != INVALID_HANDLE_VALUE) {
    DWORD written;
    CHECK(WriteFile(file, "BAD", 3, &written, NULL));
    CloseHandle(file);
  }
}
int wmain(int argc, WCHAR **argv) {
  if (argc != 2)
    return 2;
  WCHAR original_tmp[MAX_PATH], base[MAX_PATH], sandbox[MAX_PATH];
  DWORD original_length = GetEnvironmentVariableW(L"TMP", original_tmp, MAX_PATH);
  CHECK(original_length < MAX_PATH);
  CHECK(GetTempPathW(MAX_PATH, base) < MAX_PATH);
  swprintf_s(sandbox, MAX_PATH, L"%sCredentialUI.BundleTest.%lu.%llu", base,
             GetCurrentProcessId(), GetTickCount64());
  CHECK(CreateDirectoryW(sandbox, NULL));
  CHECK(SetEnvironmentVariableW(L"TMP", sandbox));
  HMODULE image = LoadLibraryExW(argv[1], NULL,
      LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
  CHECK(image != NULL);
  if (!image)
    return 1;
  WCHAR dll[MAX_PATH], exe[MAX_PATH], cache[MAX_PATH], root[MAX_PATH];
  /* Concurrent cold extraction must publish the same complete files. */
  Preparation work[4] = {0};
  HANDLE threads[4] = {0};
  for (int i = 0; i < 4; ++i) {
    work[i].image = image;
    work[i].source = argv[1];
    threads[i] = CreateThread(NULL, 0, prepare, &work[i], 0, NULL);
    CHECK(threads[i] != NULL);
  }
  for (int i = 0; i < 4; ++i) {
    if (threads[i]) {
      CHECK(WaitForSingleObject(threads[i], 15000) == WAIT_OBJECT_0);
      CloseHandle(threads[i]);
      if (work[i].result)
        printf("bundle preparation thread=%d result=%lu\n", i, work[i].result);
      CHECK(work[i].result == ERROR_SUCCESS);
      CHECK(!wcscmp(work[0].path, work[i].path));
    }
  }
  CHECK(credential_bundle_prepare(image, argv[1], dll) == ERROR_SUCCESS);
  if (!dll[0])
    return 1;
  wcscpy_s(cache, MAX_PATH, dll);
  *wcsrchr(cache, L'\\') = 0;
  swprintf_s(exe, MAX_PATH, L"%s\\CredentialUI.exe", cache);
  swprintf_s(root, MAX_PATH, L"%s\\CredentialUI", sandbox);
  HMODULE bridge = LoadLibraryW(dll);
  CHECK(bridge != NULL);
  if (bridge) {
    CHECK(GetProcAddress(bridge, "ProbeStart") != NULL);
    CHECK(GetProcAddress(bridge, "ProbeStop") != NULL);
    FreeLibrary(bridge);
  }
  WIN32_FILE_ATTRIBUTE_DATA before, after;
  CHECK(GetFileAttributesExW(dll, GetFileExInfoStandard, &before));
  CHECK(credential_bundle_prepare(image, argv[1], dll) == ERROR_SUCCESS);
  CHECK(GetFileAttributesExW(dll, GetFileExInfoStandard, &after));
  CHECK(!CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime));
  WCHAR output[MAX_PATH];
  corrupt(dll, FALSE);
  CHECK(credential_bundle_prepare(image, argv[1], output) == ERROR_CRC);
  CHECK(!output[0]);
  CHECK(DeleteFileW(dll));
  CHECK(credential_bundle_prepare(image, argv[1], output) == ERROR_SUCCESS);
  corrupt(exe, TRUE);
  CHECK(credential_bundle_prepare(image, argv[1], output) == ERROR_CRC);
  CHECK(!output[0]);
  CHECK(DeleteFileW(exe));
  CHECK(credential_bundle_prepare(image, argv[1], output) == ERROR_SUCCESS);
  /* A missing resource or unavailable source must fail before publishing. */
  CHECK(credential_bundle_prepare(GetModuleHandleW(NULL), argv[1], output) != 0);
  CHECK(!output[0]);
  CHECK(credential_bundle_prepare(image, L"Z:\\missing-bundle-source.exe", output) != 0);
  CHECK(!output[0]);
  FreeLibrary(image);
  CHECK(DeleteFileW(dll));
  CHECK(DeleteFileW(exe));
  CHECK(RemoveDirectoryW(cache));
  CHECK(RemoveDirectoryW(root));
  /* An existing non-directory at the cache root must be rejected. */
  HANDLE blocker = CreateFileW(root, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
  CHECK(blocker != INVALID_HANDLE_VALUE);
  if (blocker != INVALID_HANDLE_VALUE)
    CloseHandle(blocker);
  image = LoadLibraryExW(argv[1], NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
  CHECK(image != NULL);
  if (image) {
    CHECK(credential_bundle_prepare(image, argv[1], output) == ERROR_ACCESS_DENIED);
    CHECK(!output[0]);
    FreeLibrary(image);
  }
  CHECK(DeleteFileW(root));
  CHECK(SetEnvironmentVariableW(L"TMP", original_length ? original_tmp : NULL));
  CHECK(RemoveDirectoryW(sandbox));
  printf("bundle failures=%d (single EXE resource, concurrent extraction, reuse, corruption, missing input, blocked cache)\n", failures);
  return failures ? 1 : 0;
}
