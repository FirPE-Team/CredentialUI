#define WIN32_LEAN_AND_MEAN
#include "credential_bundle.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <wincrypt.h>

static DWORD directory(const WCHAR *path) {
  if (!CreateDirectoryW(path, NULL)) {
    DWORD error = GetLastError();
    /* PE builds may report ERROR_DIRECTORY rather than ALREADY_EXISTS for a
     * plain file. Inspect the object before deciding whether it is usable. */
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
      return error;
  }
  DWORD attributes = GetFileAttributesW(path);
  if (attributes == INVALID_FILE_ATTRIBUTES)
    return GetLastError();
  if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
    return ERROR_ACCESS_DENIED;
  return ERROR_SUCCESS;
}

/* Existing cache files are never trusted solely because their directory name
 * matches. Keep sharing restrictive while comparing the complete contents. */
static DWORD verify_file(const WCHAR *path, const BYTE *bytes, DWORD size) {
  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return GetLastError();
  BY_HANDLE_FILE_INFORMATION info;
  DWORD result = ERROR_CRC;
  if (!GetFileInformationByHandle(file, &info))
    result = GetLastError();
  else if (!(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                                    FILE_ATTRIBUTE_DIRECTORY)) &&
           !info.nFileSizeHigh && info.nFileSizeLow == size) {
    BYTE buffer[8192];
    DWORD offset = 0;
    result = ERROR_SUCCESS;
    while (offset < size) {
      DWORD count = size - offset, received = 0;
      if (count > sizeof buffer)
        count = sizeof buffer;
      if (!ReadFile(file, buffer, count, &received, NULL)) {
        result = GetLastError();
        break;
      }
      if (received != count || memcmp(buffer, bytes + offset, count)) {
        result = ERROR_CRC;
        break;
      }
      offset += count;
    }
  }
  CloseHandle(file);
  return result;
}

static DWORD publish_file_once(const WCHAR *path, const BYTE *bytes, DWORD size) {
  DWORD result = verify_file(path, bytes, size);
  if (result != ERROR_FILE_NOT_FOUND)
    return result;
  WCHAR temporary[MAX_PATH];
  HANDLE file = INVALID_HANDLE_VALUE;
  for (DWORD attempt = 0; attempt < 16; ++attempt) {
    if (swprintf_s(temporary, MAX_PATH, L"%s.%lu.%lu.%lu.tmp", path,
                   GetCurrentProcessId(), GetCurrentThreadId(), attempt) < 0)
      return ERROR_FILENAME_EXCED_RANGE;
    file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE)
      break;
    result = GetLastError();
    if (result != ERROR_FILE_EXISTS)
      return result;
  }
  if (file == INVALID_HANDLE_VALUE)
    return ERROR_FILE_EXISTS;
  DWORD written = 0;
  result = ERROR_SUCCESS;
  if (!WriteFile(file, bytes, size, &written, NULL))
    result = GetLastError();
  else if (written != size)
    result = ERROR_WRITE_FAULT;
  else if (!FlushFileBuffers(file))
    result = GetLastError();
  CloseHandle(file);
  if (!result && !MoveFileExW(temporary, path, MOVEFILE_WRITE_THROUGH)) {
    result = GetLastError();
    if (result == ERROR_ALREADY_EXISTS || result == ERROR_FILE_EXISTS)
      result = verify_file(path, bytes, size);
  }
  /* Only our exact temporary file is removed, never an existing published file. */
  DeleteFileW(temporary);
  return result ? result : verify_file(path, bytes, size);
}

static DWORD publish_file(const WCHAR *path, const BYTE *bytes, DWORD size) {
  DWORD result;
  /* A concurrent publisher can briefly hold the destination during rename.
   * Retry sharing conflicts without weakening content checks or replacing it. */
  for (DWORD attempt = 0; attempt < 50; ++attempt) {
    result = publish_file_once(path, bytes, size);
    if (result != ERROR_SHARING_VIOLATION || attempt == 49)
      return result;
    Sleep(10);
  }
  return result;
}

DWORD credential_bundle_prepare(HMODULE image, const WCHAR *source,
                                WCHAR dll[MAX_PATH]) {
  dll[0] = 0;
  if (!image)
    image = GetModuleHandleW(NULL);
  HRSRC resource = FindResourceW(image,
      MAKEINTRESOURCEW(CREDENTIAL_BRIDGE_RESOURCE), RT_RCDATA);
  if (!resource)
    return GetLastError();
  DWORD bridge_size = SizeofResource(image, resource);
  HGLOBAL loaded = LoadResource(image, resource);
  const BYTE *bridge = loaded ? (const BYTE *)LockResource(loaded) : NULL;
  if (!bridge || !bridge_size)
    return ERROR_RESOURCE_DATA_NOT_FOUND;
  WCHAR self[MAX_PATH];
  if (!source) {
    DWORD count = GetModuleFileNameW(NULL, self, MAX_PATH);
    if (!count || count >= MAX_PATH)
      return ERROR_FILENAME_EXCED_RANGE;
    source = self;
  }
  HANDLE input = CreateFileW(source, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (input == INVALID_HANDLE_VALUE)
    return GetLastError();
  DWORD result = ERROR_SUCCESS;
  LARGE_INTEGER length;
  HANDLE mapping = NULL;
  const BYTE *exe = NULL;
  HCRYPTPROV provider = 0;
  HCRYPTHASH hash = 0;
  if (!GetFileSizeEx(input, &length)) {
    result = GetLastError();
    goto done;
  }
  if (length.QuadPart <= 0 || length.QuadPart > MAXDWORD) {
    result = ERROR_FILE_TOO_LARGE;
    goto done;
  }
  mapping = CreateFileMappingW(input, NULL, PAGE_READONLY, 0, 0, NULL);
  if (!mapping || !(exe = (const BYTE *)MapViewOfFile(mapping, FILE_MAP_READ,
                                                      0, 0, 0))) {
    result = GetLastError();
    goto done;
  }
  if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES,
                             CRYPT_VERIFYCONTEXT) ||
      !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) ||
      !CryptHashData(hash, exe, (DWORD)length.QuadPart, 0) ||
      !CryptHashData(hash, bridge, bridge_size, 0)) {
    result = GetLastError();
    goto done;
  }
  BYTE digest[32];
  DWORD digest_size = sizeof digest;
  if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_size, 0)) {
    result = GetLastError();
    goto done;
  }
  WCHAR key[65], temporary[MAX_PATH], root[MAX_PATH], cache[MAX_PATH];
  for (size_t i = 0; i < sizeof digest; ++i)
    swprintf_s(key + i * 2, 65 - i * 2, L"%02x", (unsigned)digest[i]);
  DWORD count = GetTempPathW(MAX_PATH, temporary);
  if (!count || count >= MAX_PATH ||
      swprintf_s(root, MAX_PATH, L"%sCredentialUI", temporary) < 0) {
    result = ERROR_FILENAME_EXCED_RANGE;
    goto done;
  }
#ifdef _WIN64
  const WCHAR *architecture = L"x64";
#else
  const WCHAR *architecture = L"x86";
#endif
  if (swprintf_s(cache, MAX_PATH, L"%s\\%s-%s", root, architecture, key) < 0 ||
      swprintf_s(temporary, MAX_PATH, L"%s\\CredentialUI.exe", cache) < 0 ||
      swprintf_s(dll, MAX_PATH, L"%s\\CredentialUIBridge.dll", cache) < 0) {
    result = ERROR_FILENAME_EXCED_RANGE;
    goto done;
  }
  result = directory(root);
  if (!result)
    result = directory(cache);
  if (!result)
    result = publish_file(temporary, exe, (DWORD)length.QuadPart);
  if (!result)
    result = publish_file(dll, bridge, bridge_size);
done:
  if (hash)
    CryptDestroyHash(hash);
  if (provider)
    CryptReleaseContext(provider, 0);
  if (exe)
    UnmapViewOfFile(exe);
  if (mapping)
    CloseHandle(mapping);
  CloseHandle(input);
  if (result)
    dll[0] = 0;
  return result;
}
