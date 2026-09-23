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
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.Charset;
import java.util.*;

import com.microsoft.win32.*;

import ghidra.pty.PtyChild;
import ghidra.pty.ShellUtils;
import ghidra.pty.ShellUtils.Shell;
import ghidra.pty.local.LocalWindowsNativeProcessPtySession;

public class ConPtyChild extends ConPtyEndpoint implements PtyChild {

	public ConPtyChild(Handle writeHandle, Handle readHandle,
			PseudoConsoleHandle pseudoConsoleHandle) {
		super(writeHandle, readHandle, pseudoConsoleHandle);
	}

	protected MemorySegment prepareStartupInfo(Arena arena, MemorySegment cs) {
		MemorySegment sie = _STARTUPINFOEXW.allocate(arena);
		MemorySegment si = _STARTUPINFOEXW.StartupInfo(sie);
		_STARTUPINFOW.cb(si, (int) sie.byteSize());
		_STARTUPINFOW.hStdOutput(si, arena.allocate(win32_h.HANDLE));
		_STARTUPINFOW.hStdError(si, arena.allocate(win32_h.HANDLE));
		_STARTUPINFOW.hStdInput(si, arena.allocate(win32_h.HANDLE));
		_STARTUPINFOW.dwFlags(si, win32_h.STARTF_USESTDHANDLES());

		// Discover the size required for the thread attrs list and allocate
		MemorySegment bytesRequired = arena.allocate(win32_h.UINT);
		// NB. This will "fail." See Remarks on MSDN.
		win32_h.InitializeProcThreadAttributeList(cs, MemorySegment.NULL, 1, 0, bytesRequired);
		MemorySegment attrs = arena.allocate(bytesRequired.get(win32_h.UINT, 0));
		_STARTUPINFOEXW.lpAttributeList(sie, attrs);
		// Initialize it
		Win32Err.checkFalse(
			win32_h.InitializeProcThreadAttributeList(cs, attrs, 1, 0, bytesRequired), cs);
		// Set the pseudoconsole information into the list
		Win32Err.checkFalse(win32_h.UpdateProcThreadAttribute(cs, attrs, 0,
			win32_h.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE(), pseudoConsoleHandle.asSegment(),
			win32_h.HANDLE.byteSize(), MemorySegment.NULL, MemorySegment.NULL), cs);
		return sie;
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
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			Handle hJob = new Handle(Win32Err.checkNull(
				win32_h.CreateJobObjectW(cs, MemorySegment.NULL, MemorySegment.NULL), cs));
			MemorySegment sie = prepareStartupInfo(arena, cs);
			MemorySegment pi = _PROCESS_INFORMATION.allocate(arena);

			Shell shell = isImplicitCmd(args) ? Shell.WINDOWS_CMD : Shell.WINDOWS;
			String commandLine = ShellUtils.generateLine(Arrays.asList(args), shell);

			Charset utf16le = Charset.forName("UTF-16LE");
			Win32Err.checkFalse(win32_h.CreateProcessW(cs,
				MemorySegment.NULL, // lpApplicationName
				arena.allocateFrom(commandLine, utf16le), // lpCommandLine
				MemorySegment.NULL, // lpProcessAttributes
				MemorySegment.NULL, // lpThreadAttributes
				0, // bInheritHandles = false
				win32_h.EXTENDED_STARTUPINFO_PRESENT() |
					win32_h.CREATE_UNICODE_ENVIRONMENT(), // dwCreationFlags
				env == null ? MemorySegment.NULL
						: arena.allocateFrom(ShellUtils.generateEnvBlock(env),
							utf16le), // lpEnvironment
				workingDirectory == null ? MemorySegment.NULL
						: arena.allocateFrom(workingDirectory.getAbsolutePath(),
							utf16le), // lpCurrentDirectory
				sie, // lpStartupInfo
				pi), cs); // lpProcessInformation

			Win32Err.checkFalse(win32_h.AssignProcessToJobObject(cs, hJob.asSegment(),
				_PROCESS_INFORMATION.hProcess(pi)), cs);

			return new LocalWindowsNativeProcessPtySession(
				_PROCESS_INFORMATION.dwProcessId(pi),
				_PROCESS_INFORMATION.dwThreadId(pi),
				new Handle(_PROCESS_INFORMATION.hProcess(pi)),
				new Handle(_PROCESS_INFORMATION.hThread(pi)),
				"ConPTY",
				hJob);
		}
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
