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
package agent.lldb.manager.evt;

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.lldb.DebugThreadInfo;

/**
 * The event corresponding with SBThread.eBroadcastBitSelectedFrameChanged
 */
public class LldbSelectedFrameChangedEvent extends AbstractLldbEvent<String> {
	private final String id;
	private StateType state;
	private SBThread thread;
	private SBFrame frame;

	/**
	 * The selected thread ID must be specified by lldb.
	 * 
	 * @param frame
	 * @param id lldb-provided id
	 */
	public LldbSelectedFrameChangedEvent(DebugThreadInfo info) {
		super(DebugClient.getId(info.thread));
		this.id = DebugClient.getId(thread);
		this.state = info.thread.GetProcess().GetState();
		this.thread = info.thread;
		this.frame = info.frame;
	}

	/**
	 * Get the selected thread ID
	 * 
	 * @return the thread ID
	 */
	public String getThreadId() {
		return id;
	}

	public StateType getState() {
		return state;
	}

	public SBThread getThread() {
		return thread;
	}

	public SBFrame getFrame() {
		return frame;
	}

}
