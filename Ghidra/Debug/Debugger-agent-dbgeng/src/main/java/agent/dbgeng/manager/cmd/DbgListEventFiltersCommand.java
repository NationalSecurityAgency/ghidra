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

import java.util.ArrayList;
import java.util.List;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_SPECIFIC_FILTER_PARAMETERS;
import agent.dbgeng.manager.DbgEventFilter;
import agent.dbgeng.manager.impl.DbgEventFilterImpl;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public class DbgListEventFiltersCommand
		extends AbstractDbgCommand<List<DbgEventFilter>> {
	private List<DbgEventFilter> result;

	public DbgListEventFiltersCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<DbgEventFilter> complete(DbgPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		result = new ArrayList<>();
		DebugControl control = manager.getControl();
		DebugFilterInformation info = control.getNumberEventFilters();
		DebugSpecificFilterInformation exc =
			control.getSpecificFilterParameters(0, info.getNumberEvents());
		for (int i = 0; i < info.getNumberEvents(); i++) {
			String text = control.getEventFilterText(i);
			String cmd = control.getEventFilterCommand(i);
			DEBUG_SPECIFIC_FILTER_PARAMETERS p = exc.getParameter(i);
			DbgEventFilterImpl f =
				new DbgEventFilterImpl(i, text, cmd, p.ExecutionOption.intValue(),
					p.ContinueOption.intValue());
			result.add(f);
		}
	}
}
