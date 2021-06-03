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
package agent.dbgeng.manager.cmd;

import agent.dbgeng.dbgeng.DebugBreakpoint;
import agent.dbgeng.dbgeng.DebugBreakpoint.*;
import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.manager.breakpoint.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import ghidra.comm.util.BitmaskSet;

/**
 * Implementation of {@link DbgBreakpointInsertions#insertBreakpoint(String)}
 */
public class DbgInsertBreakpointCommand extends AbstractDbgCommand<DbgBreakpointInfo> {
	//private List<Long> locations;
	private final DbgBreakpointType type;
	private DbgBreakpointInfo bkpt;
	private int len;
	private final String expression;
	private final Long loc;

	public DbgInsertBreakpointCommand(DbgManagerImpl manager, String expression,
			DbgBreakpointType type) {
		super(manager);
		this.type = type;
		this.expression = expression;
		this.loc = null;
	}

	public DbgInsertBreakpointCommand(DbgManagerImpl manager, long loc, int len,
			DbgBreakpointType type) {
		super(manager);
		this.len = len;
		this.type = type;
		this.expression = null;
		this.loc = loc;
	}

	@Override
	public DbgBreakpointInfo complete(DbgPendingCommand<?> pending) {
		//manager.doBreakpointCreated(bkpt, pending);
		return bkpt;
	}

	@Override
	public void invoke() {
		DebugControl control = manager.getControl();
		BreakType bt = BreakType.DATA;
		if (type.equals(DbgBreakpointType.BREAKPOINT)) {
			bt = BreakType.CODE;
		}
		// 2 for BU, 1 for BP
		DebugBreakpoint bp = control.addBreakpoint/*2*/(bt);
		if (bt.equals(BreakType.DATA)) {
			BitmaskSet<BreakAccess> access = BitmaskSet.of(BreakAccess.EXECUTE);
			if (type.equals(DbgBreakpointType.ACCESS_WATCHPOINT)) {
				access = BitmaskSet.of(BreakAccess.READ, BreakAccess.WRITE);
			}
			if (type.equals(DbgBreakpointType.READ_WATCHPOINT)) {
				access = BitmaskSet.of(BreakAccess.READ);
			}
			if (type.equals(DbgBreakpointType.HW_WATCHPOINT)) {
				access = BitmaskSet.of(BreakAccess.WRITE);
			}
			if (type.equals(DbgBreakpointType.HW_BREAKPOINT)) {
				access = BitmaskSet.of(BreakAccess.EXECUTE);
				len = 1;
			}
			bp.setDataParameters(len, access);
		}
		if (loc != null) {
			bp.setOffset(loc);
		}
		else {
			bp.setOffsetExpression(expression);
		}
		bp.addFlags(BreakFlags.ENABLED);

		bkpt = new DbgBreakpointInfo(bp, manager.getCurrentProcess());
	}
}
