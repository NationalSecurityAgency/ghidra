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
#include <process.h>

__declspec(dllexport) unsigned int WINAPI work(DWORD* param) {
	printf("I'm %d, PID: %d\n", *param, GetCurrentProcessId());
	for (int i = 0; i < 10; i++) {
		Sleep(1);
	}
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	DWORD zero = 0;
	DWORD one = 1;
	HANDLE thread = _beginthreadex(NULL, 0, work, &one, 0, NULL);
	if (thread == NULL) {
		fprintf(stderr, "Could not create child thread\n");
		DebugBreak();
		return -1;
	}
	Sleep(100); // Hack: Try to ensure thread is created before hitting break on 'work'
	CloseHandle(thread);
	return work(&zero);
}
