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

import agent.gdb.pty.PtySession;
import ghidra.util.Msg;

/**
 * A pty session consisting of a local process and its descendants
 */
public class LocalProcessPtySession implements PtySession {
	private final Process process;

	public LocalProcessPtySession(Process process) {
		this.process = process;
		Msg.info(this, "local Pty session. PID = " + process.pid());
	}

	@Override
	public Integer waitExited() throws InterruptedException {
		return process.waitFor();
	}

	@Override
	public void destroyForcibly() {
		process.destroyForcibly();
	}
}
