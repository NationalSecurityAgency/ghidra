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
package agent.gdb.pty.windows;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import com.sun.jna.*;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HANDLE;

import agent.gdb.pty.PtyChild;
import agent.gdb.pty.local.LocalWindowsNativeProcessPtySession;
import agent.gdb.pty.windows.jna.ConsoleApiNative;
import agent.gdb.pty.windows.jna.ConsoleApiNative.STARTUPINFOEX;
import ghidra.dbg.util.ShellUtils;

public class ConPtyChild extends ConPtyEndpoint implements PtyChild {
	private final Handle pseudoConsoleHandle;

	public ConPtyChild(Handle writeHandle, Handle readHandle, Handle pseudoConsoleHandle) {
		super(writeHandle, readHandle);
		this.pseudoConsoleHandle = pseudoConsoleHandle;
	}

	protected STARTUPINFOEX prepareStartupInfo() {
		STARTUPINFOEX si = new STARTUPINFOEX();
		si.StartupInfo.cb = new DWORD(si.size());
		si.StartupInfo.hStdOutput = new HANDLE();
		si.StartupInfo.hStdError = new HANDLE();
		si.StartupInfo.hStdInput = new HANDLE();
		si.StartupInfo.dwFlags = WinBase.STARTF_USESTDHANDLES;

		// Discover the size required for the thread attrs list and allocate
		UINTByReference bytesRequired = new UINTByReference();
		// NB. This will "fail." See Remarks on MSDN.
		ConsoleApiNative.INSTANCE.InitializeProcThreadAttributeList(
			null, ConPty.DW_ONE, ConPty.DW_ZERO, bytesRequired);
		// NB. Memory frees itself in .finalize()
		si.lpAttributeList = new Memory(bytesRequired.getValue().intValue());
		// Initialize it
		if (!ConsoleApiNative.INSTANCE.InitializeProcThreadAttributeList(
			si.lpAttributeList, ConPty.DW_ONE, ConPty.DW_ZERO, bytesRequired)
				.booleanValue()) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}

		// Set the pseudoconsole information into the list
		if (!ConsoleApiNative.INSTANCE.UpdateProcThreadAttribute(
			si.lpAttributeList, ConPty.DW_ZERO,
			ConPty.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
			new PVOID(pseudoConsoleHandle.getNative().getPointer()),
			new DWORD(Native.POINTER_SIZE),
			null, null).booleanValue()) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}

		return si;
	}

	@Override
	public LocalWindowsNativeProcessPtySession session(String[] args, Map<String, String> env)
			throws IOException {
		/**
		 * TODO: How to incorporate environment into CreateProcess?
		 */

		STARTUPINFOEX si = prepareStartupInfo();
		PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

		if (!ConsoleApiNative.INSTANCE.CreateProcessW(
			null /*lpApplicationName*/,
			new WString(ShellUtils.generateLine(Arrays.asList(args))),
			null /*lpProcessAttributes*/,
			null /*lpThreadAttributes*/,
			false /*bInheritHandles*/,
			ConPty.EXTENDED_STARTUPINFO_PRESENT /*dwCreationFlags*/,
			null /*lpEnvironment*/,
			null /*lpCurrentDirectory*/,
			si /*lpStartupInfo*/,
			pi /*lpProcessInformation*/).booleanValue()) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}

		return new LocalWindowsNativeProcessPtySession(pi.dwProcessId.intValue(),
			pi.dwThreadId.intValue(),
			new Handle(pi.hProcess), new Handle(pi.hThread));
	}

	@Override
	public String nullSession() throws IOException {
		throw new UnsupportedOperationException("ConPTY does not have a name");
	}
}
