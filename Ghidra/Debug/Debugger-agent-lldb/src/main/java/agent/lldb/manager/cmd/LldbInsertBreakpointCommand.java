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

import java.math.BigInteger;

import SWIG.*;
import agent.lldb.manager.breakpoint.*;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link LldbBreakpointInsertions#insertBreakpoint(String)}
 */
public class LldbInsertBreakpointCommand extends AbstractLldbCommand<LldbBreakpointInfo> {
	//private List<Long> locations;
	private final LldbBreakpointType type;
	private LldbBreakpointInfo bkpt;
	private int len;
	private final String expression;
	private final BigInteger loc;

	public LldbInsertBreakpointCommand(LldbManagerImpl manager, String expression,
			LldbBreakpointType type) {
		super(manager);
		this.type = type;
		this.expression = expression;
		this.loc = null;
	}

	public LldbInsertBreakpointCommand(LldbManagerImpl manager, long loc, int len,
			LldbBreakpointType type) {
		super(manager);
		this.len = len;
		this.type = type;
		this.expression = null;
		this.loc = BigInteger.valueOf(loc);
	}

	@Override
	public LldbBreakpointInfo complete(LldbPendingCommand<?> pending) {
		SBTarget currentSession = manager.getCurrentSession();
		manager.doBreakpointCreated(currentSession, bkpt.getBreakpoint(), pending);
		return bkpt;
	}

	@Override
	public void invoke() {
		SBTarget currentSession = manager.getCurrentSession();
		if (type.equals(LldbBreakpointType.BREAKPOINT) ||
			type.equals(LldbBreakpointType.HW_BREAKPOINT)) {
			SBBreakpoint bpt;
			// TODO: HW_BREAKPOINT not handled here!
			if (loc != null) {
				bpt = currentSession.BreakpointCreateByAddress(loc);
			}
			else {
				bpt = currentSession.BreakpointCreateByRegex(expression);
			}
			bpt.SetEnabled(true);
			bkpt = new LldbBreakpointInfo(bpt, manager.getCurrentProcess());
		}
		else {
			boolean read = true;
			boolean write = true;
			SBError error = new SBError();
			len = 8;
			if (type.equals(LldbBreakpointType.READ_WATCHPOINT)) {
				write = false;
			}
			if (type.equals(LldbBreakpointType.WRITE_WATCHPOINT)) {
				read = false;
			}
			SBWatchpoint wpt = currentSession.WatchAddress(loc, len, read, write, error);
			if (!error.Success()) {
				SBStream stream = new SBStream();
				error.GetDescription(stream);
				Msg.error(this, error.GetType() + ":" + stream.GetData());
				return;
			}
			if (!wpt.IsValid()) {
				Msg.error(this, "Error creating watchpoint");
				return;
			}
			wpt.SetEnabled(true);
			bkpt = new LldbBreakpointInfo(wpt, manager.getCurrentProcess());
		}
	}
}
