/**
 * msgbox.c
 * $ gcc -static msgbox.c -o msgbox.exe 
 * Windows APT Warfare:
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <windows.h>
int main(void) {
	// 參數由左而右依序 push 進 stack (16 bytes)
	MessageBoxA(0, "hi there", "info", 0);
	// "info" 以二進制存入 .rdata 區段 (5 bytes) 的開頭處
	// "hi there" 以二進制存入 .rdata 區段 offset+5 的位址之上
	// complier 生成引入函數指標表（.idata 區段），來儲存 call function 的 address
	// complier 習慣將程式碼內容存入 .text 區段中
	// 在動態記憶體中，各個資料的絕對位址為「該模組的的 ImageBase + 區段 offset + 該資料在區段上的 offset」
	getchar();

	return 0;
}
