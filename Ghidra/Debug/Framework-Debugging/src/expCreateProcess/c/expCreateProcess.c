/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdio.h>
#include <Windows.h>
#include <debugapi.h>
#include <shellapi.h>

int __declspec(dllexport) func(char* msg) {
	printf("%s\n", msg);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	OutputDebugStringW(L"Starting\n");
	LPWSTR *argvW;
	int argc = 0;
	argvW = CommandLineToArgvW(GetCommandLine(), &argc);
	if (argvW != NULL) {
		LocalFree(argvW);
	} else {
		return 0;
	}
	wprintf(L"argc: %d\n", argc);
	if (argc != 1) {
		func("I'm the child");
		return 1;
	}
	STARTUPINFO sStartupInfo = {sizeof(sStartupInfo)};
	PROCESS_INFORMATION sProcessInformation = {0};
	wprintf(L"Me: %s\n", argvW[0]);
	BOOL result = CreateProcessW(argvW[0], L"expCreateProcess child", NULL, NULL, FALSE, 0, NULL, NULL, &sStartupInfo, &sProcessInformation);
	if (result == FALSE) {
		DWORD le = GetLastError();
		fprintf(stderr, "Could not create child process: %d\n", le);
		wchar_t err[1024];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, le, 0, err, sizeof(err), NULL);
		fwprintf(stderr, L"  Message: '%s'\n", err);
		DebugBreak();
		return -1;
	}
	Sleep(100); // Hack: Try to ensure process is created before hitting break on 'work'
	func("I'm the parent: ");
	printf("  %p,%p (%d,%d)\n", sProcessInformation.hProcess, sProcessInformation.hThread, sProcessInformation.dwProcessId, sProcessInformation.dwThreadId);
	CloseHandle(sProcessInformation.hThread);
	CloseHandle(sProcessInformation.hProcess);
	return 0;
}
