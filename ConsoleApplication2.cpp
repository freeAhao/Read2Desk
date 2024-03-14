#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <tchar.h> 
#include <lmcons.h>
#include <vector>
#include <TlHelp32.h>

using namespace std;

const unsigned char pattern[] = {0x48, 0x89, 0x4C, 0x24, 0x78, 0x33, 0xFF, 0x89, 0x7C, 0x24, 0x5C, 0x4C, 0x8B, 0x3D, '?', '?', '?', '?'};
const unsigned char version_pattern[] = {0x41, 0xb8, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x15, '?', '?', '?', '?', 0x48, 0x8b, 0xce, 0xe8}; 

uintptr_t FindPattern(HANDLE hProcess, uintptr_t start, uintptr_t end, const unsigned char* pattern, size_t patternSize) {
    vector<unsigned char> buffer(end - start);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPVOID)start, buffer.data(), end - start, &bytesRead))
        return 0;

    for (size_t i = 0; i < end - start - patternSize; ++i) {
        bool found = true;
        bool foundOffset = false;
        int offset = -1;
        for (size_t j = 0; j < patternSize; ++j) {
            if (!foundOffset && pattern[j] == '?') {
                offset = j+1;
            }
            if (pattern[j] != '?' && offset != -1) {
                foundOffset = true;
            }
            if (pattern[j] != '?' && buffer[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found)
            return start + i + offset;
    }
    return 0;
}

// Function to get process ID by name and non-SYSTEM user
DWORD GetProcessIdByNonSystemUser(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(processEntry);
        if (Process32First(snapshot, &processEntry)) {
            do {
                if (!_wcsicmp(processEntry.szExeFile, processName)) {
                    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processEntry.th32ProcessID);
                    if (hProcess != NULL) {
                        HANDLE hToken;
                        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                            TOKEN_OWNER* pTokenOwner;
                            DWORD dwSizeNeeded;
                            GetTokenInformation(hToken, TokenOwner, NULL, 0, &dwSizeNeeded);
                            pTokenOwner = (TOKEN_OWNER*)LocalAlloc(LPTR, dwSizeNeeded);
                            if (pTokenOwner != NULL) {
                                if (GetTokenInformation(hToken, TokenOwner, pTokenOwner, dwSizeNeeded, &dwSizeNeeded)) {
                                    SID_NAME_USE sidType;
                                    wchar_t name[UNLEN + 1];
                                    wchar_t domain[UNLEN + 1];
                                    DWORD cchName = UNLEN + 1;
                                    DWORD cchDomain = UNLEN + 1;
                                    if (LookupAccountSid(NULL, pTokenOwner->Owner, name, &cchName, domain, &cchDomain, &sidType)) {
                                        wcout << "Process:" << processName << "("<< name <<")   Pid:" << processEntry.th32ProcessID << endl;
                                        if (wcscmp(name, L"SYSTEM") != 0) {
                                            processId = processEntry.th32ProcessID;
                                            break;
                                        }
                                    }
                                }
                                LocalFree(pTokenOwner);
                            }
                            CloseHandle(hToken);
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processId;
}

struct Struct_4_7_0_2 {
    char __padding_1[0x188];
    char temporaryPassword[16];
    char __padding_2[0x10];
    char password[16];
    char __padding_3[0xD0];
    char deviceCode[16];
    char __padding_4[0x1F0];
    char phoneNumber[16];
    char __padding_5[0x10];
    char email[32];
};

struct Struct_4_7_2_1 {
    char __padding_1[0x190];
    char temporaryPassword[16];
    char __padding_2[0x10];
    char password[16];
    char __padding_3[0x1B0];
    char deviceCode[16];
    char __padding_4[0x110];
    char phoneNumber[16];
    char __padding_5[0x10];
    char email[32];
};

int main() {
	// 获取进程ID
    DWORD processId = GetProcessIdByNonSystemUser(L"ToDesk.exe");
    if (processId == 0) {
        cerr << "Process not found." << endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        DWORD error= GetLastError();
        cerr << "Failed to open process. Error Code:" << error << "  PID" << processId << endl;
        return 1;
    }

    MODULEINFO moduleInfo;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        cerr << "Faile to Enum Process." << endl;
        CloseHandle(hProcess);
        return 1;
    }
	for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
		TCHAR szModName[MAX_PATH];
        if (!GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
            continue;
        }

        if (_tcsstr(szModName, _T("ToDesk.exe")) == NULL) {
            continue;
        }

		GetModuleInformation(hProcess, hMods[i], &moduleInfo, sizeof(moduleInfo));
		uintptr_t baseAddr = (uintptr_t)moduleInfo.lpBaseOfDll;
		uintptr_t endAddr = baseAddr + moduleInfo.SizeOfImage;

		uintptr_t versionAddr = FindPattern(hProcess, baseAddr, endAddr, version_pattern, sizeof(version_pattern));
		char version[7] = {0};
        if (versionAddr != 0) {
			unsigned int offset;
			ReadProcessMemory(hProcess, (LPVOID)(versionAddr - 4), &offset, sizeof(offset), nullptr);
			ReadProcessMemory(hProcess, (LPVOID)(versionAddr + offset), version, sizeof(version), nullptr);
            cout << "Version:" << version << " -- " << hex << versionAddr << endl;
        }
		uintptr_t foundAddr = FindPattern(hProcess, baseAddr, endAddr, pattern, sizeof(pattern));
		if (foundAddr != 0) {
			unsigned int offset;
			ReadProcessMemory(hProcess, (LPVOID)(foundAddr - 4), &offset, sizeof(offset), nullptr);
			uintptr_t structPtr;
			ReadProcessMemory(hProcess, (LPVOID)(foundAddr + offset), &structPtr, sizeof(structPtr), nullptr);
            cout << "Struct Addr:" << hex << structPtr << endl;

            if (strcmp(version, "4.7.0.2")==0)
            {
				Struct_4_7_0_2 myStruct;
				ReadProcessMemory(hProcess, (LPVOID)(structPtr+i), &myStruct, sizeof(Struct_4_7_0_2), nullptr);
				cout << "设备代码: " << myStruct.deviceCode << endl;
				cout << "临时密码: " << myStruct.temporaryPassword << endl;
				cout << "安全密码: " << myStruct.password << endl;
				cout << "电话号码: " << myStruct.phoneNumber << endl;
				cout << "邮箱: " << myStruct.email << endl;
            }
            else if (strcmp(version, "4.7.2.1") == 0)
            {
				Struct_4_7_2_1 myStruct;
				ReadProcessMemory(hProcess, (LPVOID)(structPtr+i), &myStruct, sizeof(Struct_4_7_2_1), nullptr);
				cout << "设备代码: " << myStruct.deviceCode << endl;
				cout << "临时密码: " << myStruct.temporaryPassword << endl;
				cout << "安全密码: " << myStruct.password << endl;
				cout << "电话号码: " << myStruct.phoneNumber << endl;
				cout << "邮箱: " << myStruct.email << endl;
            }
		}
		else {
			cout << "Pattern not found." << endl;
		}
    }

    CloseHandle(hProcess);
    return 0;
}