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
package agent.lldb.manager.cmd;

import SWIG.*;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.*;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link LldbManager#continue()}
 */
public class LldbContinueCommand extends AbstractLldbCommand<Void> {

	private SBProcess process;

	public LldbContinueCommand(LldbManagerImpl manager, SBProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			pending.claim(evt);
			boolean b = evt instanceof LldbCommandErrorEvent ||
				!pending.findAllOf(LldbRunningEvent.class).isEmpty();
			return b;
		}
		else if (evt instanceof LldbRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			boolean b = !pending.findAllOf(AbstractLldbCompletedCommandEvent.class).isEmpty();
			return b;
		}
		return false;
	}

	@Override
	public Void complete(LldbPendingCommand<?> pending) {
		/*
		DebugProcessInfo info = created.getInfo();
		DebugThreadInfo tinfo = info.initialThreadInfo;
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId tid = so.getThreadIdByHandle(tinfo.handle);
		return manager.getThread(tid);
		*/
		return null;
	}
	
	@Override
	public void invoke() {
		SBError res = process.Continue();
		if (!res.Success()) {
			SBStream stream = new SBStream();
			res.GetDescription(stream);
			Msg.error(this, stream.GetData());
		}
	}
}
