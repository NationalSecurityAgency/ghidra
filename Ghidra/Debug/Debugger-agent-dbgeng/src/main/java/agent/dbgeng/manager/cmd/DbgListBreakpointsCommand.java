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

import java.util.*;

import agent.dbgeng.dbgeng.DebugBreakpoint;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.manager.impl.DbgManagerImpl;

/**
 * Implementation of {@link DbgProcess#listBreakpoints()}
 */
public class DbgListBreakpointsCommand extends AbstractDbgCommand<Map<Long, DbgBreakpointInfo>> {

	private List<DebugBreakpoint> breakpoints;

	public DbgListBreakpointsCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public Map<Long, DbgBreakpointInfo> complete(DbgPendingCommand<?> pending) {
		Map<Long, DbgBreakpointInfo> list = new LinkedHashMap<>();
		for (DebugBreakpoint bpt : breakpoints) {
			DbgBreakpointInfo info = new DbgBreakpointInfo(bpt, manager.getCurrentProcess());
			list.put((long) bpt.getId(), info);
		}
		return list;
	}

	@Override
	public void invoke() {
		breakpoints = manager.getControl().getBreakpoints();
	}
}
