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
package agent.dbgeng.dbgeng;

import agent.dbgeng.jna.dbgeng.WinNTExtra;

public class DebugEventInformation {

	private int type;
	private DebugProcessId pid;
	private DebugThreadId tid;
	private DebugSessionId sid;
	private int executingProcessorType = WinNTExtra.Machine.IMAGE_FILE_MACHINE_AMD64.val;

	public DebugEventInformation(int type, int pid, int tid) {
		this.type = type;
		this.pid = new DebugProcessId(pid);
		this.tid = new DebugThreadId(tid);
	}

	public int getType() {
		return type;
	}

	public DebugSessionId getSessionId() {
		return sid;
	}

	public DebugProcessId getProcessId() {
		return pid;
	}

	public DebugThreadId getThreadId() {
		return tid;
	}

	public void setThread(DebugThreadId tid) {
		this.tid = tid;
	}

	public void setProcess(DebugProcessId pid) {
		this.pid = pid;
	}

	public void setSession(DebugSessionId sid) {
		this.sid = sid;
	}

	public int getExecutingProcessorType() {
		return executingProcessorType;
	}

	public void setExecutingProcessorType(int execType) {
		this.executingProcessorType = execType;
	}

}
