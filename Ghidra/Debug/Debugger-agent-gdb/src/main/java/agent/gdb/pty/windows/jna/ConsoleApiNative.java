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
package agent.gdb.pty.windows.jna;

import java.util.List;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.*;
import com.sun.jna.win32.StdCallLibrary;

public interface ConsoleApiNative extends StdCallLibrary {
	ConsoleApiNative INSTANCE = Native.load("Kernel32.dll", ConsoleApiNative.class);
	BOOL FAIL = new BOOL(false);

	BOOL CreatePipe(HANDLEByReference hReadPipe, HANDLEByReference hWritePipe,
			SECURITY_ATTRIBUTES.ByReference lpPipeAttributes, DWORD nSize);

	HRESULT CreatePseudoConsole(COORD.ByValue size, HANDLE hInput, HANDLE hOutput,
			DWORD dwFlags,
			HANDLEByReference phPC);

	void ClosePseudoConsole(HANDLE hPC);

	BOOL InitializeProcThreadAttributeList(Pointer lpAttributeList,
			DWORD dwAttributeCount, DWORD dwFlags, UINTByReference lpSize);

	BOOL UpdateProcThreadAttribute(
			Pointer lpAttributeList,
			DWORD dwFlags,
			DWORD Attribute,
			PVOID lpValue,
			DWORD cbSize,
			PVOID lpPreviousValue,
			ULONGLONGByReference lpReturnSize);

	BOOL CreateProcessW(
			WString lpApplicationName,
			WString lpCommandLine,
			WinBase.SECURITY_ATTRIBUTES lpProcessAttributes,
			WinBase.SECURITY_ATTRIBUTES lpThreadAttributes,
			boolean bInheritHandles,
			DWORD dwCreationFlags,
			Pointer lpEnvironment,
			WString lpCurrentDirectory,
			STARTUPINFOEX lpStartupInfo,
			WinBase.PROCESS_INFORMATION lpProcessInformation);

	/*
	BOOL GetConsoleMode(
			HANDLE hConsoleMode,
			DWORDByReference dwMode);
	
	BOOL CreateProcessWithTokenW(
			HANDLE hToken,
			DWORD dwLogonFlags,
			WString lpApplicationName,
			WString lpCommandLine,
			DWORD dwCreationFlags,
			Pointer lpEnvironment,
			WString lpCurrentDirectory,
			STARTUPINFOEX lpStartupInfo,
			WinBase.PROCESS_INFORMATION lpProcessInformation);
	
	BOOL LogonUserW(
			WString lpUsername,
			WString lpDomain,
			WString lpPassword,
			DWORD dwLogonType,
			DWORD dwLogonProvider,
			HANDLEByReference phToken);
	*/

	public static class COORD extends Structure implements Structure.ByValue {
		public static class ByReference extends COORD
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("X", "Y");

		public short X;
		public short Y;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class SECURITY_ATTRIBUTES extends Structure {
		public static class ByReference extends SECURITY_ATTRIBUTES
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder(
			"nLength", "lpSecurityDescriptor", "bInheritedHandle");

		public DWORD nLength;
		public ULONGLONG lpSecurityDescriptor;
		public BOOL bInheritedHandle;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class PROC_THREAD_ATTRIBUTE_LIST extends Structure {
		public static class ByReference extends PROC_THREAD_ATTRIBUTE_LIST
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder(
			"dwFlags", "Size", "Count", "Reserved", "Unknown");

		public DWORD dwFlags;
		public ULONG Size;
		public ULONG Count;
		public ULONG Reserved;
		public ULONGLONG Unknown;
		//public PROC_THREAD_ATTRIBUTE_ENTRY Entries[0];

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class STARTUPINFOEX extends Structure {
		public static class ByReference extends STARTUPINFOEX
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder(
			"StartupInfo", "lpAttributeList");

		public WinBase.STARTUPINFO StartupInfo;
		public Pointer lpAttributeList;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

}
