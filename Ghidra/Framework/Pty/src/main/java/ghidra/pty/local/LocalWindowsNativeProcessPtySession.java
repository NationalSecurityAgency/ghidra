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
package ghidra.pty.local;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.microsoft.win32.win32_h;

import ghidra.pty.PtySession;
import ghidra.pty.windows.Handle;
import ghidra.pty.windows.Win32Err;
import ghidra.util.Msg;

public class LocalWindowsNativeProcessPtySession implements PtySession {
	private final int pid;
	//private final int tid;
	private final Handle processHandle;
	//private final Handle threadHandle;
	private final String ptyName;
	private final Handle jobHandle;

	public LocalWindowsNativeProcessPtySession(int pid, int tid, Handle processHandle,
			Handle threadHandle, String ptyName, Handle jobHandle) {
		this.pid = pid;
		//this.tid = tid;
		this.processHandle = processHandle;
		//this.threadHandle = threadHandle;
		this.ptyName = ptyName;
		this.jobHandle = jobHandle;

		Msg.info(this, "local Windows Pty session. PID = " + pid);
	}

	protected int doWaitExited(int millis) throws TimeoutException {
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			MemorySegment lpExitCode = arena.allocate(win32_h.DWORD);
			while (true) {
				int result = Win32Err.checkWaitFailed(
					win32_h.WaitForSingleObject(cs, processHandle.asSegment(), millis), cs);
				if (result == win32_h.WAIT_OBJECT_0() || result == win32_h.WAIT_ABANDONED()) {
					Win32Err.checkFalse(
						win32_h.GetExitCodeProcess(cs, processHandle.asSegment(), lpExitCode), cs);
					int exitCode = lpExitCode.get(win32_h.DWORD, 0);
					if (exitCode == win32_h.STILL_ACTIVE()) {
						continue;
					}
					return exitCode;
				}
				if (result == win32_h.WAIT_TIMEOUT()) {
					throw new TimeoutException();
				}
				else {
					throw new AssertionError(
						"Unrecognized Wait result: %d (0x%x)".formatted(result, result));
				}
			}
		}
	}

	@Override
	public int waitExited() {
		try {
			return doWaitExited(-1);
		}
		catch (TimeoutException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public int waitExited(long timeout, TimeUnit unit) throws TimeoutException {
		long millis = TimeUnit.MILLISECONDS.convert(timeout, unit);
		if (millis > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("Too long a timeout");
		}
		return doWaitExited((int) millis);
	}

	@Override
	public void destroyForcibly() {
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			Win32Err.checkFalse(win32_h.TerminateJobObject(cs, jobHandle.asSegment(), 1), cs);
		}
	}

	@Override
	public String description() {
		return "process " + pid + " on " + ptyName;
	}

	@Override
	public ProcessHandle handle() {
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			MemorySegment lpExitCode = arena.allocate(win32_h.DWORD);
			Optional<ProcessHandle> result = ProcessHandle.of(pid);
			Win32Err.checkFalse(
				win32_h.GetExitCodeProcess(cs, processHandle.asSegment(), lpExitCode), cs);
			int exitCode = lpExitCode.get(win32_h.DWORD, 0);
			if (exitCode == win32_h.STILL_ACTIVE()) {
				return result.orElse(null);
			}
			return null;
		}
	}
}
