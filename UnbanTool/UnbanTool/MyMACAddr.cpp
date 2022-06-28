
#include "MyMACAddr.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

MyMACAddr::MyMACAddr()
{

	srand((unsigned)time(0));
}

MyMACAddr::~MyMACAddr()
{
}


string MyMACAddr::GenRandMAC()
{
	stringstream temp;
	int number = 0;
	string result;

	for (int i = 0; i < 6; i++)
	{
		number = rand() % 254;
		temp << setfill('0') << setw(2) << hex << number;
		if (i != 5)
		{
			temp << "-";
		}
	}
	result = temp.str();

	for (auto& c : result)
	{
		c = toupper(c);
	}

	return result;
}

void MyMACAddr::showAdapterList()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		cerr << "Error allocating memory needed to call GetAdaptersinfo." << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << "Error allocating memory needed to call GetAdaptersinfo" << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			cout << "ComboIndex: \t" << pAdapter->ComboIndex << endl;
			cout << "\tAdapter Name: \t" << pAdapter->AdapterName << endl;
			cout << "\tAdapter Desc: \t" << pAdapter->Description << endl;
			cout << "\tAdapter Addr: \t";
			for (i = 0; i < pAdapter->AddressLength; i++) {
				if (i == (pAdapter->AddressLength - 1))
					printf("%.2X\n", (int)pAdapter->Address[i]);
				else
					printf("%.2X-", (int)pAdapter->Address[i]);
			}
			cout << "\tIP Address: \t" << pAdapter->IpAddressList.IpAddress.String << endl;
			cout << "\tIP Mask: \t" << pAdapter->IpAddressList.IpMask.String << endl;
			cout << "\tGateway: \t" << pAdapter->GatewayList.IpAddress.String << endl;
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << "GetAdaptersInfo failed with error: " << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);
}

unordered_map<string, string> MyMACAddr::getAdapters()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	unordered_map<string, string> result;
	stringstream temp;
	string str_mac;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		cerr << "Error allocating memory needed to call GetAdaptersinfo" << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << "Error allocating memory needed to call GetAdaptersinfo\n" << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			for (UINT i = 0; i < pAdapter->AddressLength; i++) {
				temp << setfill('0') << setw(2) << hex << (int)pAdapter->Address[i];
				if (i != pAdapter->AddressLength - 1)
				{
					temp << "-";
				}
			}
			str_mac = temp.str();
			temp.str("");
			temp.rdbuf();
			for (auto& c : str_mac)
			{
				c = toupper(c);
			}

			result.insert({ pAdapter->Description, str_mac });
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << "GetAdaptersInfo failed with error: " << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	return result;
}


void MyMACAddr::AssingRndMAC()
{

	vector <string> list;
	unordered_map<string, string> AdapterDetails = getAdapters();
	for (auto& itm : AdapterDetails)
	{
		list.push_back(itm.first);
	}

	cout << "\n[+]List of Available Adapters: " << endl;
	int range = 0;
	for (auto itm = list.begin(); itm != list.end(); itm++)
	{
		cout << '\t' << range + 1 << ")" << *itm << endl;
		range++;
	}

	cout << "[*]Selection: ";

	int selection = 0;
	cin >> selection;
	if (cin.fail() || (selection < 1) || (selection > range))
	{
		cin.clear();
		cin.ignore(numeric_limits<streamsize>::max(), '\n');
		cerr << "[!]Invalid Selection Input!" << endl;
		return;
	}

	cout << "----------------------------------------------" << endl;
	cout << "[-]Selected Adapter is: " << list.at(selection - 1) << endl;
	cout << "[+]Old MAC: " << AdapterDetails.at(list.at(selection - 1)) << endl;

	wstring wstr(list.at(selection - 1).begin(), list.at(selection - 1).end());
	const wchar_t* wAdapterName = wstr.c_str();

	bool bRet = false;
	HKEY hKey = NULL;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}"),
		0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{

		DWORD dwIndex = 0;
		TCHAR Name[1024];
		DWORD cName = 1024;
		while (RegEnumKeyEx(hKey, dwIndex, Name, &cName,
			NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			HKEY hSubKey = NULL;
			if (RegOpenKeyEx(hKey, Name, 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS)
			{
				BYTE Data[1204];
				DWORD cbData = 1024;
				if (RegQueryValueEx(hSubKey, _T("DriverDesc"), NULL, NULL, Data, &cbData) == ERROR_SUCCESS)
				{

					if (_tcscmp((TCHAR*)Data, wAdapterName) == 0)
					{
						string temp = GenRandMAC();
						string newMAC = temp;
						temp.erase(std::remove(temp.begin(), temp.end(), '-'), temp.end());

						wstring wstr_newMAC(temp.begin(), temp.end());
						const wchar_t* newMACAddr = wstr_newMAC.c_str();


						if (RegSetValueEx(hSubKey, _T("NetworkAddress"), 0, REG_SZ,
							(const BYTE*)newMACAddr, sizeof(TCHAR) * ((DWORD)_tcslen(newMACAddr) + 1)) == ERROR_SUCCESS)
						{
							cout << "[+]New Random MAC: " << newMAC << endl;
							DisableEnableConnections(false, wAdapterName);
							DisableEnableConnections(true, wAdapterName);
						}
					}
				}
				RegCloseKey(hSubKey);
			}
			cName = 1024;
			dwIndex++;
		}
		RegCloseKey(hKey);
	}
	else
	{
		cerr << "[!]Cannot Access Registry - Open program as admin." << endl;
		return;
	}
	cout << "----------------------------------------------" << endl;

}

HRESULT MyMACAddr::DisableEnableConnections(BOOL bEnable, const wchar_t* AdapterName)
{
	HRESULT hr = E_FAIL;

	CoInitialize(NULL);

	INetConnectionManager* pNetConnectionManager = NULL;
	hr = CoCreateInstance(CLSID_ConnectionManager,
		NULL,
		CLSCTX_LOCAL_SERVER | CLSCTX_NO_CODE_DOWNLOAD,
		IID_INetConnectionManager,
		reinterpret_cast<LPVOID*>(&pNetConnectionManager)
	);
	if (SUCCEEDED(hr))
	{

		IEnumNetConnection* pEnumNetConnection;
		pNetConnectionManager->EnumConnections(NCME_DEFAULT, &pEnumNetConnection);

		ULONG ulCount = 0;
		BOOL fFound = FALSE;
		hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

		HRESULT hrT = S_OK;


		do
		{
			NETCON_PROPERTIES* pProps = NULL;
			INetConnection* pConn;

		
			hrT = pEnumNetConnection->Next(1, &pConn, &ulCount);

			if (SUCCEEDED(hrT) && 1 == ulCount)
			{
			
				hrT = pConn->GetProperties(&pProps);

				if (S_OK == hrT)
				{
				

					if (bEnable && (_tcscmp((TCHAR*)pProps->pszwDeviceName, AdapterName) == 0))
					{
						
						printf("[+]Enabling adapter: %S...\n", pProps->pszwDeviceName);
						hr = pConn->Connect();
					}
					else if (_tcscmp((TCHAR*)pProps->pszwDeviceName, AdapterName) == 0)
					{
						printf("[+]Disabling adapter: %S...\n", pProps->pszwDeviceName);
						hr = pConn->Disconnect();
					}

					CoTaskMemFree(pProps->pszwName);
					CoTaskMemFree(pProps->pszwDeviceName);
					CoTaskMemFree(pProps);
				}

				pConn->Release();
				pConn = NULL;
			}

		} while (SUCCEEDED(hrT) && 1 == ulCount && !fFound);

		if (FAILED(hrT))
		{
			hr = hrT;
		}

		pEnumNetConnection->Release();
	}

	if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_RETRY))
	{
		printf("Could not enable or disable connection (0x%08x)\r\n", hr);
	}

	pNetConnectionManager->Release();
	CoUninitialize();

	return hr;
}