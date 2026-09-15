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

#ifdef WIN32
#include <Windows.h>
#include <debugapi.h>
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

DLLEXPORT volatile char overwrite[] = "Hello, World!";

#ifdef WIN32
int DLLEXPORT main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow);
int DLLEXPORT wrapputs(volatile char* output);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    return main(hInstance, hPrevInstance, pCmdLine, nCmdShow);
}

int DLLEXPORT main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	wrapputs(overwrite);
	return overwrite[0]; 
}

int DLLEXPORT wrapputs(volatile char* output) {
	OutputDebugString(output);
}
#else
int wrapputs(volatile char* output) {
	puts(output);
}

int main(int argc, char** output) {
	wrapputs(overwrite);
	return overwrite[0];
}
#endif
