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
package agent.gdb.manager.impl.cmd;

import java.util.ArrayList;
import java.util.List;

import agent.gdb.manager.GdbStackFrame;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;

public class GdbStackListFramesCommand extends AbstractGdbCommandWithThreadId<List<GdbStackFrame>> {
	protected final GdbThreadImpl thread;

	public GdbStackListFramesCommand(GdbManagerImpl manager, GdbThreadImpl thread) {
		super(manager, thread.getId());
		this.thread = thread;
	}

	@Override
	protected String encode(String threadPart) {
		return "-stack-list-frames" + threadPart;
	}

	@Override
	public List<GdbStackFrame> complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		GdbMiFieldList stack = done.assumeStack();
		List<GdbStackFrame> result = new ArrayList<>(stack.size());
		for (Object obj : stack.get("frame")) {
			GdbMiFieldList f = (GdbMiFieldList) obj;
			GdbStackFrame frame = GdbStackFrameImpl.fromFieldList(thread, f);
			result.add(frame);
		}
		return result;
	}
}
