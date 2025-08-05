#include <stdio.h>
#include <windows.h>
#pragma warning(disable : 4996)
// get NT Headers, Sections Header
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

size_t ptr_msgboxa = 0;

void iatHook(char *module, const char *szHook_ApiName, size_t callback, size_t &apiAddr)
{
	auto dir_ImportTable = getNtHdr(module)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];	// IAT
	auto impModuleList = (IMAGE_IMPORT_DESCRIPTOR *)&module[dir_ImportTable.VirtualAddress];		// pointer to IMAGE_IMPORT_DESCRIPTOR
	// traversal all DLLs until null DESCRIPTOR
	for (; impModuleList->Name; impModuleList++)
	{
		auto arr_callVia = (IMAGE_THUNK_DATA *)&module[impModuleList->FirstThunk];			// pointer to IAT
		auto arr_apiNames = (IMAGE_THUNK_DATA *)&module[impModuleList->OriginalFirstThunk];		// pointer to INT
		for (int i = 0; arr_apiNames[i].u1.Function; i++)
		{
			auto curr_impApi = (PIMAGE_IMPORT_BY_NAME)&module[arr_apiNames[i].u1.Function];		// current API name
			
			if (!strcmp(szHook_ApiName, (char *)curr_impApi->Name))					// compare wanted API name
			{
				apiAddr = arr_callVia[i].u1.Function;						// save MessageBoxA's address
				arr_callVia[i].u1.Function = callback;						// replace with callback
				break;
			}
		}
	}
}

int main(int argc, char **argv)
{

	void (*ptr)(UINT, LPCSTR, LPCSTR, UINT) = [](UINT hwnd, LPCSTR lpText, LPCSTR lpTitle, UINT uType) {
		printf("[hook] MessageBoxA(%i, \"%s\", \"%s\", %i)", hwnd, lpText, lpTitle, uType);
		((UINT(*)(UINT, LPCSTR, LPCSTR, UINT))ptr_msgboxa)(hwnd, "msgbox got hooked", "alert", uType);
	};

	iatHook((char *)GetModuleHandle(NULL), "MessageBoxA", (size_t)ptr, ptr_msgboxa);
	MessageBoxA(0, "Iat Hook Test", "title", 0);
	return 0;
}
