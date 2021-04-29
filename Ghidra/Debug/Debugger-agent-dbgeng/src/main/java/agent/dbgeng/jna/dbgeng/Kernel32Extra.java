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
package agent.dbgeng.jna.dbgeng;

import java.util.List;

import com.sun.jna.*;
import com.sun.jna.platform.win32.BaseTSD.ULONG_PTR;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import agent.dbgeng.jna.dbgeng.WinNTExtra.EXCEPTION_POINTERS;

public interface Kernel32Extra extends StdCallLibrary {
	Kernel32Extra INSTANCE =
		Native.loadLibrary("kernel32", Kernel32Extra.class, W32APIOptions.DEFAULT_OPTIONS);

	interface VectoredHandlerCallback extends StdCallCallback {
		LONG EXCEPTION_CONTINUE_EXECUTION = new LONG(0xffffffff);
		LONG EXCEPTION_CONTINUE_SEARCH = new LONG(0x0);

		LONG invoke(EXCEPTION_POINTERS.ByReference ExceptionInfo);
	}

	interface HandlerRoutineCallback extends StdCallCallback {
		int CTRL_C_EVENT = 0;
		int CTRL_CLOSE_EVENT = 2;
		int CTRL_LOGOFF_EVENT = 5;
		int CTRL_SHUTDOWN_EVENT = 6;

		boolean invoke(DWORD dwCtrlType);
	}

	public static class PROCESSENTRY32W extends Structure {
		public static class ByReference extends PROCESSENTRY32W implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("dwSize", "cntUsage",
			"th32ProcessID", "th32DefaultHeapID", "th32ModuleID", "cntThreads",
			"th32ParentProcessID", "pcPriClassBase", "dwFlags", "szExeFile");

		public DWORD dwSize;
		public DWORD cntUsage;
		public DWORD th32ProcessID;
		public ULONG_PTR th32DefaultHeapID;
		public DWORD th32ModuleID;
		public DWORD cntThreads;
		public DWORD th32ParentProcessID;
		public DWORD pcPriClassBase;
		public DWORD dwFlags;
		public char[] szExeFile = new char[WinDef.MAX_PATH];

		public PROCESSENTRY32W() {
			dwSize = new DWORD(size());
		}

		public PROCESSENTRY32W(Pointer p) {
			super(p);
			read();
		}

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class THREADENTRY32 extends Structure {
		public static class ByReference extends THREADENTRY32 implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("dwSize", "cntUsage",
			"th32ThreadID", "th32OwnerProcessID", "tpBasePri", "tpDeltaPri", "dwFlags");

		public DWORD dwSize;
		public DWORD cntUsage;
		public DWORD th32ThreadID;
		public DWORD th32OwnerProcessID;
		public LONG tpBasePri;
		public LONG tpDeltaPri;
		public DWORD dwFlags;

		public THREADENTRY32() {
			dwSize = new DWORD(size());
		}

		public THREADENTRY32(Pointer p) {
			super(p);
			read();
		}

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	Pointer AddVectoredExceptionHandler(ULONG FirstHandler,
			Kernel32Extra.VectoredHandlerCallback VectoredHandler);

	boolean SetConsoleCtrlHandler(HandlerRoutineCallback HandlerRoutine, boolean Add);

	boolean Process32FirstW(HANDLE hSnapshot, PROCESSENTRY32W lppe);

	boolean Process32NextW(HANDLE hSnapshot, PROCESSENTRY32W lppe);

	boolean Thread32First(HANDLE hSnapshot, THREADENTRY32 lpte);

	boolean Thread32Next(HANDLE hSnapshot, THREADENTRY32 lpte);
}
