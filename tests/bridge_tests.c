#define WIN32_LEAN_AND_MEAN
#include "../bridge/bridge.c"
#include <tlhelp32.h>
#include <stdio.h>
static LONG test_failures,fallback_count;
#define VERIFY(x) do{if(!(x)){printf("FAIL line=%d %s\n",__LINE__,#x);InterlockedIncrement(&test_failures);}}while(0)
static ULONG SEC_ENTRY fake_prompt(PCWSTR target,PCREDUI_INFOW ui,ULONG error,PCWSTR package,PSEC_WINNT_AUTH_IDENTITY_OPAQUE input,PSEC_WINNT_AUTH_IDENTITY_OPAQUE *output,int *save,ULONG flags){(void)target;(void)ui;(void)error;(void)package;(void)input;(void)output;(void)save;(void)flags;InterlockedIncrement(&fallback_count);return ERROR_NOT_SUPPORTED;}
typedef struct Drive {DWORD flags;const WCHAR *user;BOOL save;} Drive;
static DWORD test_child;static HWND test_window;
static BOOL CALLBACK find_gui(HWND hwnd,LPARAM parameter){(void)parameter;DWORD pid;GetWindowThreadProcessId(hwnd,&pid);WCHAR cls[80];GetClassNameW(hwnd,cls,80);if(pid==test_child&&!wcscmp(cls,L"CredentialUI.Window")){test_window=hwnd;return FALSE;}return TRUE;}
static DWORD WINAPI drive_gui(void *data){Drive *drive=(Drive*)data;ULONGLONG end=GetTickCount64()+8000;test_window=NULL;
 while(GetTickCount64()<end){HANDLE shot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);PROCESSENTRY32W entry={0};entry.dwSize=sizeof entry;if(shot!=INVALID_HANDLE_VALUE){if(Process32FirstW(shot,&entry))do{if(entry.th32ParentProcessID==GetCurrentProcessId()&&!_wcsicmp(entry.szExeFile,L"CredentialUI.exe")){test_child=entry.th32ProcessID;EnumWindows(find_gui,0);if(test_window)break;}}while(Process32NextW(shot,&entry));CloseHandle(shot);}if(test_window)break;Sleep(20);}
 VERIFY(test_window!=NULL);if(!test_window)return 1;
 HWND remember=GetDlgItem(test_window,1003);VERIFY(IsWindowEnabled(remember)==!(drive->flags&SSPIPFC_NO_CHECKBOX));
 SendMessageW(GetDlgItem(test_window,1001),WM_SETTEXT,0,(LPARAM)drive->user);SendMessageW(GetDlgItem(test_window,1002),WM_SETTEXT,0,(LPARAM)L"Offline-password");if(IsWindowEnabled(remember))SendMessageW(remember,BM_SETCHECK,drive->save?BST_CHECKED:BST_UNCHECKED,0);PostMessageW(test_window,WM_COMMAND,IDOK,0);return 0;
}
static void identity_case(const WCHAR *name,const WCHAR *expected_user,const WCHAR *expected_domain,DWORD flags,BOOL selected){
 Drive drive={flags,name,selected};HANDLE driver=CreateThread(NULL,0,drive_gui,&drive,0,NULL);VERIFY(driver!=NULL);PSEC_WINNT_AUTH_IDENTITY_OPAQUE identity=NULL;int save=0;
 ULONG result=replacement(L"offline.invalid",NULL,5,L"Negotiate",NULL,&identity,&save,flags);VERIFY(result==0);VERIFY(identity!=NULL);VERIFY(save==((flags&SSPIPFC_NO_CHECKBOX)?0:selected));
 if(identity){PCWSTR user=NULL,domain=NULL,packed=NULL;VERIFY(SspiEncodeAuthIdentityAsStrings(identity,&user,&domain,&packed)==SEC_E_OK);VERIFY(user&&!wcscmp(user,expected_user));VERIFY((domain&&!wcscmp(domain,expected_domain))||(!domain&&!expected_domain[0]));if(user)SspiLocalFree((PVOID)user);if(domain)SspiLocalFree((PVOID)domain);if(packed){SecureZeroMemory((void*)packed,wcslen(packed)*sizeof(WCHAR));SspiLocalFree((PVOID)packed);}SspiFreeAuthIdentity(identity);}
 WaitForSingleObject(driver,10000);CloseHandle(driver);printf("identity case flags=%lu completed\n",flags);
}
static NET_API_STATUS NET_API_FUNCTION failed_net(LMSTR server,DWORD level,LPBYTE buffer,LPDWORD error){(void)server;(void)level;(void)buffer;(void)error;return ERROR_ACCESS_DENIED;}
int wmain(void){GetModuleFileNameW(NULL,g_directory,MAX_PATH);WCHAR *slash=wcsrchr(g_directory,L'\\');if(!slash)return 2;*slash=0;g_original=fake_prompt;g_enabled=1;g_queue=CreateSemaphoreW(NULL,1,1,NULL);g_cancel=CreateEventW(NULL,TRUE,FALSE,NULL);
 PSEC_WINNT_AUTH_IDENTITY_OPAQUE output=NULL;int save=0;VERIFY(replacement(L"offline.invalid",NULL,0,L"OtherPackage",NULL,&output,&save,0)==ERROR_NOT_SUPPORTED);VERIFY(replacement(L"offline.invalid",NULL,0,L"Negotiate",NULL,&output,&save,16)==ERROR_NOT_SUPPORTED);VERIFY(fallback_count==2);
 identity_case(L"OfflineUser",L"OfflineUser",L"",0,FALSE);identity_case(L"DOMAIN\\OfflineUser",L"OfflineUser",L"DOMAIN",0,FALSE);identity_case(L"OfflineUser@example.invalid",L"OfflineUser@example.invalid",L"",SSPIPFC_NO_CHECKBOX,FALSE);identity_case(L"OfflineUser",L"OfflineUser",L"",SSPIPFC_CREDPROV_DO_NOT_SAVE,TRUE);
 PSEC_WINNT_AUTH_IDENTITY_OPAQUE pending=NULL;VERIFY(SspiEncodeStringsAsAuthIdentity(L"OfflineUser",L"",L"Offline-password",&pending)==SEC_E_OK);VERIFY(schedule_save(pending,L"offline.invalid",GetTickCount64()+1000));SspiFreeAuthIdentity(pending);g_net_original=failed_net;USE_INFO_1 info={0};info.ui1_remote=L"\\\\offline.invalid\\Share";VERIFY(observe_net_use(NULL,1,(LPBYTE)&info,NULL)==ERROR_ACCESS_DENIED);for(size_t i=0;i<64;i++)VERIFY(!g_pending[i].identity);
 clear_pending(TRUE);CloseHandle(g_queue);CloseHandle(g_cancel);printf("bridge failures=%ld fallbackCalls=%ld\n",test_failures,fallback_count);return test_failures?1:0;
}
