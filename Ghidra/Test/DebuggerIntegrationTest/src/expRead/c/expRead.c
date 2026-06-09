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
#ifdef WIN32
#include <Windows.h>
#include <debugapi.h>
#include <io.h>
#define DLLEXPORT __declspec(dllexport)
#else
#include <unistd.h>
#define DLLEXPORT
#endif

#ifdef WIN32
int DLLEXPORT main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow);
int DLLEXPORT wrapread(int const fd, void * const buffer, unsigned const buffer_size);
#else
int wrapread(int fd, void * buffer, int buffer_size);
#endif

#ifdef WIN32
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    return main(hInstance, hPrevInstance, pCmdLine, nCmdShow);
}

int DLLEXPORT main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	char c;
	wrapread(0, &c, sizeof(c));
}

int DLLEXPORT wrapread(int const fd, void * const buffer, unsigned const buffer_size) {
	_read(fd, buffer, buffer_size);
}

#else
int main(int argc, char** argv) {
	char c;
	wrapread(0, &c, sizeof(c));
}

int wrapread(int fd, void * buffer, int buffer_size) {
	read(fd, buffer, buffer_size);
}
#endif

