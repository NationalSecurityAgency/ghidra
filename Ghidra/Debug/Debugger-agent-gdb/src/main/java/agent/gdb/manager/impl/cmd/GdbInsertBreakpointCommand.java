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

import org.apache.commons.text.StringEscapeUtils;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.breakpoint.GdbBreakpointInfo;
import agent.gdb.manager.breakpoint.GdbBreakpointType;
import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.*;

/**
 * Implementation of {@link GdbInferior#insertBreakpoint(String)}
 */
public class GdbInsertBreakpointCommand extends AbstractGdbCommandWithThreadId<GdbBreakpointInfo> {
	private final String loc;
	private final GdbBreakpointType type;

	public GdbInsertBreakpointCommand(GdbManagerImpl manager, Integer threadId, String loc,
			GdbBreakpointType type) {
		super(manager, threadId);
		this.loc = loc;
		this.type = type;
	}

	@Override
	protected String makeThreadPart() {
		return threadId == null ? "" : " -p " + threadId;
	}

	protected static String esc(String param) {
		return '"' + StringEscapeUtils.escapeJava(param) + '"';
	}

	@Override
	protected String encode(String threadPart) {
		String cmd;
		switch (type) {
			case BREAKPOINT:
				return "-break-insert" + threadPart + " " + esc(loc);
			case HW_BREAKPOINT:
				return "-break-insert -h" + threadPart + " " + esc(loc);
			case DPRINTF:
				return "-dprintf-insert" + threadPart + " " + esc(loc);
			case HW_WATCHPOINT:
				cmd = "watch -l " + loc; // escaping here causes GDB to treat as literal???
				return "-interpreter-exec" + threadPart + " console " + esc(cmd);
			case READ_WATCHPOINT:
				cmd = "rwatch -l " + loc;
				return "-interpreter-exec" + threadPart + " console " + esc(cmd);
			case ACCESS_WATCHPOINT:
				cmd = "awatch -l " + loc;
				return "-interpreter-exec" + threadPart + " console " + esc(cmd);
			default:
				throw new IllegalArgumentException("type=" + type);
		}
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (super.handle(evt, pending)) {
			return true;
		}
		else if (evt instanceof GdbBreakpointCreatedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public GdbBreakpointInfo complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		if (type.isWatchpoint()) {
			GdbBreakpointCreatedEvent evt = pending.findSingleOf(GdbBreakpointCreatedEvent.class);
			return evt.getBreakpointInfo();
		}
		GdbBreakpointInfo bkpt =
			GdbBreakpointInfo.parse(done.getInfo(), manager.currentInferior().getId());
		// GDB does not give notification for breakpoints added by GDB/MI commands
		manager.doBreakpointCreated(bkpt, pending);
		return bkpt;
	}
}
