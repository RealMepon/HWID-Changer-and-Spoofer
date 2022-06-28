#include <windows.h>
#include <iostream>
#include <string>
#include <limits>
#include "MyMACAddr.h"
#include <random>
#include <conio.h> 
using namespace std;

#define color_black      0
#define color_dark_blue  1
#define color_dark_green 2
#define color_light_blue 3
#define color_dark_red   4
#define color_magenta    5
#define color_orange     6
#define color_light_gray 7
#define color_gray       8
#define color_blue       9
#define color_green     10
#define color_cyan      11
#define color_red       12
#define color_pink      13
#define color_yellow    14
#define color_white     15
#define _WIN32_WINNT  0x0500

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
HWND hWnd = GetConsoleWindow();

int number;
WCHAR ProductId[255];
WCHAR HwProfileGuid[255];
WCHAR MachineGuid[255];
WCHAR MachineId[255];
WCHAR HardwareId[255];
DWORD bufferSize = 255 * sizeof(WCHAR);
MyMACAddr* ptr = new MyMACAddr();

BOOL IsRunAsAdministrator()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:

    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fIsRunAsAdmin;
}



string wchar_to_string(WCHAR wchar[255])
{
    wstring w_string = wchar;
    string str(w_string.begin(), w_string.end());
    return str;
}

string get_uuid() {
    static random_device dev;
    static mt19937 rng(dev());

    uniform_int_distribution<int> dist(0, 15);

    const char* v = "0123456789abcdef";
    const bool dash[] = { 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0 };

    string res;
    for (int i = 0; i < 16; i++) {
        if (dash[i]) res += "-";
        res += v[dist(rng)];
        res += v[dist(rng)];
    }
    return res;
}

void show_logo()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color_red);
    std::cout << R"(  
  __  __ ______ _____   ____  _   ___          __     _____  ______ 
 |  \/  |  ____|  __ \ / __ \| \ | \ \        / /\   |  __ \|  ____|
 | \  / | |__  | |__) | |  | |  \| |\ \  /\  / /  \  | |__) | |__   
 | |\/| |  __| |  ___/| |  | | . ` | \ \/  \/ / /\ \ |  _  /|  __|  
 | |  | | |____| |    | |__| | |\  |  \  /\  / ____ \| | \ \| |____ 
 |_|  |_|______|_|     \____/|_| \_|   \/  \/_/    \_\_|  \_\______|)";
    cout << "\n\n\n";
    SetConsoleTextAttribute(hConsole, color_white);
}

void AdaptersSummary(MyMACAddr& ptr)
{
    unordered_map<string, string> list = ptr.getAdapters();
    for (auto& itm : list)
    {
        cout << "Name: " << itm.first << "\t\tMAC Address: " << itm.second << endl;
    }
}



int main()
{
    SetConsoleTitle(L"MEPONWARE");
    if (!IsRunAsAdministrator())
    {
        SetConsoleTextAttribute(hConsole, color_red);
        cout << "Run the program as administrator!";
        SetConsoleTextAttribute(hConsole, color_white);
        Sleep(5000);
        return 0;
    }
    while (true)
    {
        ShowWindow(hWnd, SW_SHOWMAXIMIZED);
        show_logo();
        SetConsoleTextAttribute(hConsole, color_green);
        cout << "SystemInfo:\n";
        SetConsoleTextAttribute(hConsole, color_white);
        RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", RRF_RT_REG_SZ, NULL, MachineGuid, &bufferSize);
        bufferSize = 255 * sizeof(WCHAR);
        wcout << "MachineGuid: " << MachineGuid;
        RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid", RRF_RT_REG_SZ, NULL, HwProfileGuid, &bufferSize);
        bufferSize = 255 * sizeof(WCHAR);
        string HwProfileGuid_new = wchar_to_string(HwProfileGuid);
        HwProfileGuid_new.erase(std::remove(HwProfileGuid_new.begin(), HwProfileGuid_new.end(), '{'), HwProfileGuid_new.end());
        HwProfileGuid_new.erase(std::remove(HwProfileGuid_new.begin(), HwProfileGuid_new.end(), '}'), HwProfileGuid_new.end());
        cout << "\nHardwareGuid: " << HwProfileGuid_new;
        RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId", RRF_RT_REG_SZ, NULL, ProductId, &bufferSize);
        bufferSize = 255 * sizeof(WCHAR);
        wcout << "\nProductId: " << ProductId;
        RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId", RRF_RT_REG_SZ, NULL, MachineId, &bufferSize);
        bufferSize = 255 * sizeof(WCHAR);
        string MachineId_new = wchar_to_string(MachineId);
        MachineId_new.erase(std::remove(MachineId_new.begin(), MachineId_new.end(), '{'), MachineId_new.end());
        MachineId_new.erase(std::remove(MachineId_new.begin(), MachineId_new.end(), '}'), MachineId_new.end());
        cout << "\nMachineId: " << MachineId_new;

        RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareId", RRF_RT_REG_SZ, NULL, HardwareId, &bufferSize);
        bufferSize = 255 * sizeof(WCHAR);
        string HardwareId_new = wchar_to_string(HardwareId);
        HardwareId_new.erase(std::remove(HardwareId_new.begin(), HardwareId_new.end(), '{'), HardwareId_new.end());
        HardwareId_new.erase(std::remove(HardwareId_new.begin(), HardwareId_new.end(), '}'), HardwareId_new.end());
        cout << "\nHardwareId: " << HardwareId_new;
        SetConsoleTextAttribute(hConsole, color_green);
        cout << "\n\nNetwork Details:\n";
        SetConsoleTextAttribute(hConsole, color_white);
        ptr->showAdapterList();
        SetConsoleTextAttribute(hConsole, color_pink);
        cout << "\n\nSpoof Options:\n";
        SetConsoleTextAttribute(hConsole, color_yellow);
        cout << "[1] Spoof all\n";
        SetConsoleTextAttribute(hConsole, color_blue);
        cout << "[2] Spoof MAC-adress\n";
        SetConsoleTextAttribute(hConsole, color_orange);
        cout << "[3] Spoof Machine Guid\n[4] Spoof HwProfileGuid\n[5] Spoof Product Id\n[6] Spoof Machine Id\n[7] Spoof Computer Hardware Id\n";
        SetConsoleTextAttribute(hConsole, color_green);
        cout << "[8] HELP\n";
        SetConsoleTextAttribute(hConsole, color_red);
        cout << "[99] Exit";
        SetConsoleTextAttribute(hConsole, color_white);

        cout << "\n\nNumber: ";
        cin >> number;
        system("CLS");
        switch(number)
        {
        case 1:
        {
            string uuid = get_uuid();
            show_logo();
            system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid /t REG_SZ /d " + uuid + " /f").c_str());
            system("CLS");
            wcout << "Debug: Machine Guid changed from " << MachineGuid;
            cout << " to " << uuid;
            uuid = get_uuid();
            system(("REG ADD \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001\" /v HwProfileGuid /t REG_SZ /d " + uuid + " /f").c_str());
            cout << "\nDebug: HwProfileGuid changed from " << HwProfileGuid_new << " to " << uuid;
            uuid = get_uuid();
            system(("REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductId /t REG_SZ /d " + uuid + " /f").c_str());
            cout << "\nDebug: ProductId changed from " << ProductId << " to " << uuid;
            uuid = get_uuid();
            system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v MachineId /t REG_SZ /d " + uuid + " /f").c_str());
            cout << "\nDebug: MachineId changed from " << MachineId_new << " to " << uuid;
            uuid = get_uuid();
            system(("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d " + uuid + " /f").c_str());
            cout << "\nDebug: HardwareId changed from " << HardwareId_new << " to " << uuid;
            Sleep(4000);
            system("CLS");
            cout << "Changing MAC...";
            Sleep(2000);
            system("CLS");
            ptr->AssingRndMAC();
            break;
        }
        case 2:
        {
            ptr->AssingRndMAC();
            break;
        }
        case 3:
        {
            string uuid = get_uuid();
            show_logo();
            system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid /t REG_SZ /d " + uuid + " /f").c_str());
            system("CLS");
            wcout << "Debug: Machine Guid changed from " << MachineGuid;
            cout << " to " << uuid;
            Sleep(4000);
            system("CLS");
            break;
        }
        case 4:
        {
            string uuid = get_uuid();
            show_logo();
            system(("REG ADD \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001\" /v HwProfileGuid /t REG_SZ /d " + uuid + " /f").c_str());
            cout << "Debug: HwProfileGuid changed from " << HwProfileGuid_new << " to " << uuid;
            Sleep(4000);
            system("CLS");
            break;
        }
        case 5:
        {
            string uuid = get_uuid();
            show_logo();
            system(("REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductId /t REG_SZ /d " + uuid + " /f").c_str());
            cout << "Debug: ProductId changed from " << ProductId << " to " << uuid;
            Sleep(4000);
            system("CLS");
            break;
        }
        case 6:
        {
            string uuid = get_uuid();
            show_logo();
            system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v MachineId /t REG_SZ /d " + uuid + " /f").c_str());
            cout << "Debug: MachineId changed from " << MachineId_new << " to " << uuid;
            Sleep(4000);
            system("CLS");
            break;
        }
        case 7:
        {
            string uuid = get_uuid();
            show_logo();
            system(("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d " + uuid + " /f").c_str());
            cout << "Debug: HardwareId changed from " << HardwareId_new << " to " << uuid;
            Sleep(4000);
            system("CLS");
            break;
        }
        case 8:
        {
            show_logo();
            cout << " If you got banned in a game, I recommend you to use the \"Spoof all\" function.\n If you just want to try the program, I recommend functions 2-7.\n After a change has been made, the program resets itself and your change is applied.\n The program only works if it was started as an administrator\n\nPress ENTER to continue.";
            _getch();
            system("CLS");
            break;
        }
        case 99:
            return 0;
        default:
            show_logo();
            cout << "Error: You entered an incorrect number";
            Sleep(3000);
            system("CLS");
            break;
        }         
    }
}