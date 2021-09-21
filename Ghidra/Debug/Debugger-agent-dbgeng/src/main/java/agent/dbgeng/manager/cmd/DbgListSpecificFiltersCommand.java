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

import agent.dbgeng.dbgeng.DebugSpecificFilterInformation;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_SPECIFIC_FILTER_PARAMETERS;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public class DbgListSpecificFiltersCommand
		extends AbstractDbgCommand<List<DEBUG_SPECIFIC_FILTER_PARAMETERS>> {
	private List<DEBUG_SPECIFIC_FILTER_PARAMETERS> result;

	public DbgListSpecificFiltersCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<DEBUG_SPECIFIC_FILTER_PARAMETERS> complete(DbgPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		result = new ArrayList<>();
		// TODO set parameters
		DebugSpecificFilterInformation filterInfo =
			manager.getControl().getSpecificFilterParameters(0, 0);
		for (int i = 0; i < filterInfo.getNumberOfParameters(); i++) {
			DEBUG_SPECIFIC_FILTER_PARAMETERS fi = filterInfo.getParameter(i);
			result.add(fi);
		}
	}
}
