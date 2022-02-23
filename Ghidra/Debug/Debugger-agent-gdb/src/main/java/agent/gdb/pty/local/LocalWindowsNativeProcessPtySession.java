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
package agent.gdb.pty.local;

import com.sun.jna.LastErrorException;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.ptr.IntByReference;

import agent.gdb.pty.PtySession;
import agent.gdb.pty.windows.Handle;
import ghidra.util.Msg;

public class LocalWindowsNativeProcessPtySession implements PtySession {
	//private final int pid;
	//private final int tid;
	private final Handle processHandle;
	//private final Handle threadHandle;

	public LocalWindowsNativeProcessPtySession(int pid, int tid, Handle processHandle,
			Handle threadHandle) {
		//this.pid = pid;
		//this.tid = tid;
		this.processHandle = processHandle;
		//this.threadHandle = threadHandle;

		Msg.info(this, "local Windows Pty session. PID = " + pid);
	}

	@Override
	public int waitExited() throws InterruptedException {
		while (true) {
			switch (Kernel32.INSTANCE.WaitForSingleObject(processHandle.getNative(), -1)) {
				case Kernel32.WAIT_OBJECT_0:
				case Kernel32.WAIT_ABANDONED:
					IntByReference lpExitCode = new IntByReference();
					Kernel32.INSTANCE.GetExitCodeProcess(processHandle.getNative(), lpExitCode);
					if (lpExitCode.getValue() != WinBase.STILL_ACTIVE) {
						return lpExitCode.getValue();
					}
				case Kernel32.WAIT_TIMEOUT:
					throw new AssertionError();
				case Kernel32.WAIT_FAILED:
					throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
			}
		}
	}

	@Override
	public void destroyForcibly() {
		if (!Kernel32.INSTANCE.TerminateProcess(processHandle.getNative(), 1)) {
			int error = Kernel32.INSTANCE.GetLastError();
			switch (error) {
				case Kernel32.ERROR_ACCESS_DENIED:
					/**
					 * This indicates the process has already terminated. It's unclear to me whether
					 * or not that is the only possible cause of this error.
					 */
					return;
			}
			throw new LastErrorException(error);
		}
	}
}
