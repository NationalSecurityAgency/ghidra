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
import agent.dbgeng.manager.DbgExceptionFilter;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public class DbgListExceptionFiltersCommand
		extends AbstractDbgCommand<List<DbgExceptionFilter>> {
	private List<DbgExceptionFilter> result;

	public DbgListExceptionFiltersCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<DbgExceptionFilter> complete(DbgPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		result = new ArrayList<>();
		DebugControl control = manager.getControl();
		DebugFilterInformation info = control.getNumberEventFilters();
		int nEvents = info.getNumberEvents();
		int nExcs = info.getNumberSpecificExceptions();
		DebugSpecificFilterInformation spec = control.getSpecificFilterParameters(0, nEvents);
		DebugExceptionFilterInformation exc =
			control.getExceptionFilterParameters(nEvents, null, nExcs);
		result = new ArrayList<>();
	}
}
