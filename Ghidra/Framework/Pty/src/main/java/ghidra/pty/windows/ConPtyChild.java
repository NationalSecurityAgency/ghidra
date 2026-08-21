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
package ghidra.pty.windows;

import java.io.File;
import java.io.IOException;
import java.util.*;

import com.sun.jna.*;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HANDLE;

import ghidra.pty.PtyChild;
import ghidra.pty.ShellUtils;
import ghidra.pty.ShellUtils.Shell;
import ghidra.pty.local.LocalWindowsNativeProcessPtySession;
import ghidra.pty.windows.jna.ConsoleApiNative;
import ghidra.pty.windows.jna.ConsoleApiNative.STARTUPINFOEX;
import ghidra.pty.windows.jna.JobApiNative;

public class ConPtyChild extends ConPtyEndpoint implements PtyChild {

	public ConPtyChild(Handle writeHandle, Handle readHandle,
			PseudoConsoleHandle pseudoConsoleHandle) {
		super(writeHandle, readHandle, pseudoConsoleHandle);
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

	private boolean isImplicitCmd(String[] args) {
		if (args.length < 1) {
			return false; // Really shouldn't, but let Windows decide how to fail
		}
		String lower0 = args[0].toLowerCase();
		if (lower0.endsWith(".bat") || lower0.endsWith(".cmd")) {
			return true;
		}
		/**
		 * I'm on the fence about this. While it's pretty clear that invoking a .bat file, which
		 * implicitly prefixes <code>cmd /c</code>, ought to escape the metacharacters, I'm not
		 * certain about when a user explicitly invokes <code>cmd /c</code>. I think it should let
		 * the metacharacters through, i.e., cmd should be permitted to do what the user probably
		 * intended. Still, if someone using this API unwittingly puts the <code>cmd /c</code>
		 * prefix on a user-supplied command line without sanitizing, they could create a
		 * vulnerability.
		 */
		/*if (args.length < 2) {
			return false;
		}
		if (!"/c".equals(args[1])) {
			return false;
		}
		if ("cmd".equals(lower0) || "cmd.exe".equals(lower0) || lower0.endsWith("\\cmd") ||
			lower0.endsWith("\\cmd.exe")) {
			return true;
		}*/
		return false;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * <b>WARNING:</b> If arg[0], i.e., the application name, is a batch file, Windows will
	 * automatically invoke it using <code>cmd /c</code>. This method is aware of this implicit
	 * invocation and, upon detecting it, will appropriately escape cmd's metacharacters.
	 * <em>However</em>, if a client explicitly invokes <code>cmd /c</code> with any part of the
	 * command line formed from user-supplied arguments, IT MUST sanitize those arguments itself.
	 * This can be achieved using {@link Shell#generateArgument(String)} of
	 * {@link Shell#WINDOWS_CMD}.
	 */
	@Override
	public LocalWindowsNativeProcessPtySession session(String[] args, Map<String, String> env,
			File workingDirectory, Collection<TermMode> mode) throws IOException {
		/**
		 * TODO: How to control local echo?
		 */

		HANDLE hJob = JobApiNative.INSTANCE.CreateJobObjectW(null, null);
		if (hJob == null) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}

		STARTUPINFOEX si = prepareStartupInfo();
		PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

		Shell shell = isImplicitCmd(args) ? Shell.WINDOWS_CMD : Shell.WINDOWS;
		String commandLine = ShellUtils.generateLine(Arrays.asList(args), shell);

		if (!ConsoleApiNative.INSTANCE.CreateProcessW(
			null /*lpApplicationName*/,
			new WString(commandLine),
			null /*lpProcessAttributes*/,
			null /*lpThreadAttributes*/,
			false /*bInheritHandles*/,
			new DWORD(Kernel32.EXTENDED_STARTUPINFO_PRESENT |
				Kernel32.CREATE_UNICODE_ENVIRONMENT) /*dwCreationFlags*/,
			env == null ? null : new WString(ShellUtils.generateEnvBlock(env)),
			workingDirectory == null ? null
					: new WString(workingDirectory.getAbsolutePath()) /*lpCurrentDirectory*/,
			si /*lpStartupInfo*/,
			pi /*lpProcessInformation*/).booleanValue()) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}

		if (!JobApiNative.INSTANCE.AssignProcessToJobObject(hJob, pi.hProcess).booleanValue()) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}

		return new LocalWindowsNativeProcessPtySession(pi.dwProcessId.intValue(),
			pi.dwThreadId.intValue(), new Handle(pi.hProcess), new Handle(pi.hThread), "ConPTY",
			new Handle(hJob));
	}

	@Override
	public String nullSession(Collection<TermMode> mode) throws IOException {
		throw new UnsupportedOperationException("ConPTY does not have a name");
	}

	@Override
	public void setWindowSize(short cols, short rows) {
		pseudoConsoleHandle.resize(rows, cols);
	}
}
