// PrecisionSpooferV2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "col.h"
#include <thread>
#include <random>
#include "SkCrypt.h"
#include <TlHelp32.h>
#include <comdef.h>
#include <Wbemidl.h>
#include "mapper/kdmapper.hpp"
#include "drv.h"
#include <chrono>
#include <xlocbuf>
#include <codecvt>
#pragma comment(lib, "wbemuuid.lib")

#pragma warning(disable : 4996)

static void Clear()
{
    system(("cls"));
}


enum class WmiQueryError {
    None,
    BadQueryFailure,
    PropertyExtractionFailure,
    ComInitializationFailure,
    SecurityInitializationFailure,
    IWbemLocatorFailure,
    IWbemServiceConnectionFailure,
    BlanketProxySetFailure,
};

struct WmiQueryResult
{
    std::vector<std::wstring> ResultList;
    WmiQueryError Error = WmiQueryError::None;
    std::wstring ErrorDescription;
};

WmiQueryResult getWmiQueryResult(std::wstring wmiQuery, std::wstring propNameOfResultObject, bool allowEmptyItems = false) {

    WmiQueryResult retVal;
    retVal.Error = WmiQueryError::None;
    retVal.ErrorDescription = L"";

    HRESULT hres;


    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pclsObj = NULL;
    VARIANT vtProp;


    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        retVal.Error = WmiQueryError::ComInitializationFailure;
        retVal.ErrorDescription = L"Failed to initialize COM library. Error code : " + std::to_wstring(hres);
    }
    else
    {
        // Step 2: --------------------------------------------------
        // Set general COM security levels --------------------------
        // note: JUCE Framework users should comment this call out,
        // as this does not need to be initialized to run the query.
        // see https://social.msdn.microsoft.com/Forums/en-US/48b5626a-0f0f-4321-aecd-17871c7fa283/unable-to-call-coinitializesecurity?forum=windowscompatibility 
        hres = CoInitializeSecurity(
            NULL,
            -1,                          // COM authentication
            NULL,                        // Authentication services
            NULL,                        // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
            RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
            NULL,                        // Authentication info
            EOAC_NONE,                   // Additional capabilities 
            NULL                         // Reserved
        );


        if (FAILED(hres))
        {
            retVal.Error = WmiQueryError::SecurityInitializationFailure;
            retVal.ErrorDescription = L"Failed to initialize security. Error code : " + std::to_wstring(hres);
        }
        else
        {
            // Step 3: ---------------------------------------------------
            // Obtain the initial locator to WMI -------------------------
            pLoc = NULL;

            hres = CoCreateInstance(
                CLSID_WbemLocator,
                0,
                CLSCTX_INPROC_SERVER,
                IID_IWbemLocator, (LPVOID*)&pLoc);

            if (FAILED(hres))
            {
                retVal.Error = WmiQueryError::IWbemLocatorFailure;
                retVal.ErrorDescription = L"Failed to create IWbemLocator object. Error code : " + std::to_wstring(hres);
            }
            else
            {
                // Step 4: -----------------------------------------------------
                // Connect to WMI through the IWbemLocator::ConnectServer method

                pSvc = NULL;

                // Connect to the root\cimv2 namespace with
                // the current user and obtain pointer pSvc
                // to make IWbemServices calls.
                hres = pLoc->ConnectServer(
                    _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
                    NULL,                    // User name. NULL = current user
                    NULL,                    // User password. NULL = current
                    0,                       // Locale. NULL indicates current
                    NULL,                    // Security flags.
                    0,                       // Authority (for example, Kerberos)
                    0,                       // Context object 
                    &pSvc                    // pointer to IWbemServices proxy
                );

                // Connected to ROOT\\CIMV2 WMI namespace

                if (FAILED(hres))
                {
                    retVal.Error = WmiQueryError::IWbemServiceConnectionFailure;
                    retVal.ErrorDescription = L"Could not connect to Wbem service.. Error code : " + std::to_wstring(hres);
                }
                else
                {
                    // Step 5: --------------------------------------------------
                    // Set security levels on the proxy -------------------------

                    hres = CoSetProxyBlanket(
                        pSvc,                        // Indicates the proxy to set
                        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
                        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
                        NULL,                        // Server principal name 
                        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
                        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
                        NULL,                        // client identity
                        EOAC_NONE                    // proxy capabilities 
                    );

                    if (FAILED(hres))
                    {
                        retVal.Error = WmiQueryError::BlanketProxySetFailure;
                        retVal.ErrorDescription = L"Could not set proxy blanket. Error code : " + std::to_wstring(hres);
                    }
                    else
                    {
                        // Step 6: --------------------------------------------------
                        // Use the IWbemServices pointer to make requests of WMI ----

                        // For example, get the name of the operating system
                        pEnumerator = NULL;
                        hres = pSvc->ExecQuery(
                            bstr_t("WQL"),
                            bstr_t(wmiQuery.c_str()),
                            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                            NULL,
                            &pEnumerator);

                        if (FAILED(hres))
                        {
                            retVal.Error = WmiQueryError::BadQueryFailure;
                            retVal.ErrorDescription = L"Bad query. Error code : " + std::to_wstring(hres);
                        }
                        else
                        {
                            // Step 7: -------------------------------------------------
                            // Get the data from the query in step 6 -------------------

                            pclsObj = NULL;
                            ULONG uReturn = 0;

                            while (pEnumerator)
                            {
                                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
                                    &pclsObj, &uReturn);

                                if (0 == uReturn)
                                {
                                    break;
                                }

                                // VARIANT vtProp;

                                // Get the value of desired property
                                hr = pclsObj->Get(propNameOfResultObject.c_str(), 0, &vtProp, 0, 0);
                                if (S_OK != hr) {
                                    retVal.Error = WmiQueryError::PropertyExtractionFailure;
                                    retVal.ErrorDescription = L"Couldn't extract property: " + propNameOfResultObject + L" from result of query. Error code : " + std::to_wstring(hr);
                                }
                                else {
                                    BSTR val = vtProp.bstrVal;

                                    // Sometimes val might be NULL even when result is S_OK
                                    // Convert NULL to empty string (otherwise "std::wstring(val)" would throw exception)
                                    if (NULL == val) {
                                        if (allowEmptyItems) {
                                            retVal.ResultList.push_back(std::wstring(L""));
                                        }
                                    }
                                    else {
                                        retVal.ResultList.push_back(std::wstring(val));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Cleanup
    // ========

    VariantClear(&vtProp);
    if (pclsObj)
        pclsObj->Release();

    if (pSvc)
        pSvc->Release();

    if (pLoc)
        pLoc->Release();

    if (pEnumerator)
        pEnumerator->Release();

    CoUninitialize();

    return retVal;
}

void queryAndPrintResult(std::wstring query, std::wstring propNameOfResultObject)
{
    WmiQueryResult res;
    res = getWmiQueryResult(query, propNameOfResultObject);

    if (res.Error != WmiQueryError::None) {
        std::wcout << "Got this error while executing query: " << std::endl;
        std::wcout << res.ErrorDescription << std::endl;
        return; // Exitting function
    }

    for (const auto& item : res.ResultList) {
        std::wcout << item << std::endl;
    }
}

std::wstring queryAndReturnResult(std::wstring query, std::wstring propNameOfResultObject)
{
    WmiQueryResult res;
    res = getWmiQueryResult(query, propNameOfResultObject);

    if (res.Error != WmiQueryError::None) {
        std::wcout << "Got this error while executing query: " << std::endl;
        std::wcout << res.ErrorDescription << std::endl;
        return NULL; // Exitting function
    }

    for (const auto& item : res.ResultList) {
        return item;
    }
}

std::unique_ptr<std::thread> soarwazhere;
std::unique_ptr<std::thread> runtime;
void WriteLine(std::string text)
{
    std::cout << dye::white("   [") << dye::red("%") << dye::white("] ") << text << std::endl;
}
void Write(std::string text)
{
    std::cout << dye::white("   [") << dye::red("%") << dye::white("] ") << text;
}

std::string GenerateRand(const std::string& hwid) {
    std::string serial = hwid;
    std::srand(static_cast<unsigned int>(time(nullptr)));
    int index = std::rand() % serial.length();
    static const char charset[] = "0123456789ABCDEF";
    char replacement = charset[std::rand() % (sizeof(charset) - 1)];
    serial[index] = replacement;
    int numChanges = std::rand() % 6 + 1;
    for (int i = 0; i < numChanges; ++i) {
        index = std::rand() % serial.length();
        replacement = charset[std::rand() % (sizeof(charset) - 1)];
        serial[index] = replacement;
    }

    return serial;
}

std::string GenerateString(int length)
{
    auto randchar = []() -> char
    {
        const char charset[] = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };
    std::string str(length, 0);
    std::generate_n(str.begin(), length, randchar);
    return str;
}
static void TitleBS()
{
    while (true)
    {
        std::string title = GenerateString(10) + (" / .gg/fncheat");
        SetConsoleTitleA(title.c_str());
        Sleep(150);
    }
}

std::string ws2s(const std::wstring& wstr)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;
    return converterX.to_bytes(wstr);
}

static void SerialChecker()
{
    Write("Diskdrive : ");  queryAndPrintResult(L"SELECT SerialNumber FROM Win32_DiskDrive", L"SerialNumber");
    Sleep(2000);
}


bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr) {
    UNREFERENCED_PARAMETER(param1);
    UNREFERENCED_PARAMETER(param2);
    UNREFERENCED_PARAMETER(allocationPtr);
    UNREFERENCED_PARAMETER(allocationSize);
    UNREFERENCED_PARAMETER(mdlptr);
    Log("[+] Callback example called" << std::endl);

    /*
    This callback occurs before call driver entry and
    can be usefull to pass more customized params in
    the last step of the mapping procedure since you
    know now the mapping address and other things
    */
    return true;
}

HANDLE iqvw64e_device_handle;

static void Spoof()
{
    iqvw64e_device_handle = intel_driver::Load();

    if (iqvw64e_device_handle == INVALID_HANDLE_VALUE) {
        std::cout << dye::red("  FAILED TO LOAD VULN DRIVER, PLEASE CONTACT SUPPORT @ .GG/FNCHEAT.") << std::endl;
        Beep(1000, 1000);
        Sleep(-1);
    }

    NTSTATUS exitCode = 0;
    if (!kdmapper::MapDriver(iqvw64e_device_handle, drv.data(), 0, 0, free, true, false, false, callbackExample, &exitCode)) {
        intel_driver::Unload(iqvw64e_device_handle);
    }

    if (!intel_driver::Unload(iqvw64e_device_handle)) {
        std::cout << dye::red("  FAILED TO UNLOAD VULN DRIVER, PLEASE CONTACT SUPPORT IMMEDIATLY @ .GG/FNCHEAT.") << std::endl;
        Beep(1000, 1000);
        Sleep(-1);
    }
}

static void SpooferMenu()
{
    Clear();
    std::cout << "" << std::endl;
    Write("Spoof ? (Y/N) -> ");
    std::string lol;
    std::cin >> lol;
    if (lol == "y" || lol == "Y" || lol == "Yes" || lol == "yes")
    {
        Spoof();
    }
    WriteLine("Successfully Spoofed.");
    Sleep(1500);
    Write("Refresh WMI ? (Y/N) -> ");
    std::string lol2;
    std::cin >> lol2;
    if (lol2 == "y" || lol2 == "Y" || lol2 == "Yes" || lol2 == "yes")
    {
        int lol = system("taskkill /f /im WmiPrvSE.exe >nul");
    }
    lol3:
    WriteLine("Successfully Refreshed WMI Tables.");
    Sleep(2000);
    Write("Check Disks ? (Y/N) -> ");
    std::string lol22;
    std::cin >> lol22;
    if (lol22 == "y" || lol22 == "Y" || lol22 == "Yes" || lol22 == "yes")
    {
        SerialChecker();
    }
    Write("All Operations Completed Successfully.");
    Sleep(-1);
}

static BOOL SetConsoleSize(int cols, int rows) {
    HWND hWnd;
    HANDLE hConOut;
    CONSOLE_FONT_INFO fi;
    CONSOLE_SCREEN_BUFFER_INFO bi;
    int w, h, bw, bh;
    RECT rect = { 0, 0, 0, 0 };
    COORD coord = { 0, 0 };
    hWnd = GetConsoleWindow();
    if (hWnd) {
        hConOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConOut && hConOut != (HANDLE)-1) {
            if (GetCurrentConsoleFont(hConOut, FALSE, &fi)) {
                if (GetClientRect(hWnd, &rect)) {
                    w = rect.right - rect.left;
                    h = rect.bottom - rect.top;
                    if (GetWindowRect(hWnd, &rect)) {
                        bw = rect.right - rect.left - w;
                        bh = rect.bottom - rect.top - h;
                        if (GetConsoleScreenBufferInfo(hConOut, &bi)) {
                            coord.X = bi.dwSize.X;
                            coord.Y = bi.dwSize.Y;
                            if (coord.X < cols || coord.Y < rows) {
                                if (coord.X < cols) {
                                    coord.X = cols;
                                }
                                if (coord.Y < rows) {
                                    coord.Y = rows;
                                }
                                if (!SetConsoleScreenBufferSize(hConOut, coord)) {
                                    return FALSE;
                                }
                            }
                            return SetWindowPos(hWnd, NULL, rect.left, rect.top, cols * fi.dwFontSize.X + bw, rows * fi.dwFontSize.Y + bh, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);
                        }
                    }
                }
            }
        }
    }
    return FALSE;
}

static void NULLVOID()
{
    nullptr;
}

void RuntimeProtetion()
{
    while (true)
    {
        if (IsDebuggerPresent()) {
            std::cout << dye::red("  Dissasembler Found, Please Close All Disassemblers before using Precision Spoofer.") << std::endl;
            Beep(1000, 1000);
            Sleep(2000);
            abort();
        }
    }
}


int main()
{
    SetConsoleSize(64,18);
    soarwazhere.reset(new std::thread(TitleBS));
    runtime.reset(new std::thread(RuntimeProtetion));
start:
    Clear();
    Sleep(1000);
    std::cout << std::endl;
    NULLVOID();
    NULLVOID();
    Write("License : ");
    std::string lol;
    std::cin >> lol;
    if (lol == "soarwazhere") {
        WriteLine("Valid Licnesee.");
        Beep(1000, 100);
        Sleep(2000);
        NULLVOID();
        NULLVOID();
        NULLVOID();
        NULLVOID();
        NULLVOID();
        NULLVOID();
        NULLVOID();
        NULLVOID();
        SpooferMenu();
        NULLVOID();
        NULLVOID();
        NULLVOID();
        NULLVOID();
        NULLVOID();
        NULLVOID();
    }
    else
    {
        std::cout << std::endl;
        std::cout << dye::red("    Could Not Validate Session (Incorrect Licnesee).") << std::endl;
        NULLVOID();
        Beep(1000, 1000);
        Sleep(2000);
        goto start;
    }
}