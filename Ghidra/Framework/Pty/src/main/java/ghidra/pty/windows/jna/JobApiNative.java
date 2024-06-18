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
package ghidra.pty.windows.jna;

import com.sun.jna.Native;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef.BOOL;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.win32.StdCallLibrary;

import ghidra.pty.windows.jna.ConsoleApiNative.SECURITY_ATTRIBUTES;

public interface JobApiNative extends StdCallLibrary {
	JobApiNative INSTANCE = Native.load("kernel32.dll", JobApiNative.class);

	HANDLE CreateJobObjectW(SECURITY_ATTRIBUTES.ByReference lpJobAttributes, WString lpName);

	BOOL AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess);

	BOOL TerminateJobObject(HANDLE hJob, int uExitCode);
}
