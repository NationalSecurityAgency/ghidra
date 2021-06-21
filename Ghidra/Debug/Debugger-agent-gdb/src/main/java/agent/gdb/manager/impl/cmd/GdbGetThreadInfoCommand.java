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

import java.util.List;

import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;

/**
 * Implementation of {@link GdbManagerImpl#getThreadInfo()}
 */
public class GdbGetThreadInfoCommand extends AbstractGdbCommandWithThreadId<GdbThreadInfo> {

	public GdbGetThreadInfoCommand(GdbManagerImpl manager, Integer threadId) {
		super(manager, threadId);
	}

	@Override
	protected String encode(String threadPart) {
		return "-thread-info " + threadId; // Note the trailing space
	}

	@Override
	public Integer impliesCurrentThreadId() {
		return null;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	@Override
	public GdbThreadInfo complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		List<GdbMiFieldList> infoList = done.assumeThreadInfoList();
		return GdbThreadInfo.parseInfo(infoList.get(0));
	}
}
