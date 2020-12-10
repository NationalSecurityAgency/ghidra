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
package agent.gdb.manager.reason;

import agent.gdb.manager.GdbStackFrame;
import agent.gdb.manager.GdbThread;
import agent.gdb.manager.impl.GdbStackFrameImpl;
import agent.gdb.manager.impl.GdbThreadImpl;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;

/**
 * The inferior stopped because a thread hit a breakpoint
 */
public class GdbBreakpointHitReason implements GdbReason {
	private final GdbMiFieldList frame;
	private final long bkptno;
	private final int threadId;

	public GdbBreakpointHitReason(GdbMiFieldList info) {
		this.bkptno = Long.parseLong(info.getString("bkptno"));
		this.threadId = Integer.parseInt(info.getString("thread-id"));
		this.frame = info.getFieldList("frame");
	}

	/**
	 * Get the ID of the breakpoint that was hit
	 * 
	 * @return the breakpoint number
	 */
	public long getBreakpointId() {
		return bkptno;
	}

	/**
	 * Get the stack frame where the breakpoint was hit
	 * 
	 * TODO: Why would this ever be non-zero, again?
	 * 
	 * @param thread the thread
	 * @return the frame
	 */
	public GdbStackFrame getFrame(GdbThread thread) {
		return GdbStackFrameImpl.fromFieldList((GdbThreadImpl) thread, frame);
	}

	/**
	 * Get the ID of the thread that hit the breakpoint
	 * 
	 * @return the thread ID
	 */
	public int getThreadId() {
		return threadId;
	}

	@Override
	public String toString() {
		return "<GdbReason breakpoint-hit: bkpt=" + bkptno + ",thread-id=" + threadId + ">";
	}

	@Override
	public String desc() {
		return "Breakpoint " + bkptno + " hit";
	}
}
