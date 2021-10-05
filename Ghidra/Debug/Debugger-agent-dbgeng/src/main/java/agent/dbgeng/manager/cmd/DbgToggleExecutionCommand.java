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

import com.sun.jna.platform.win32.WinDef.ULONG;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugControl.DebugFilterExecutionOption;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_EXCEPTION_FILTER_PARAMETERS;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_SPECIFIC_FILTER_PARAMETERS;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public class DbgToggleExecutionCommand
		extends AbstractDbgCommand<Void> {

	private int index;
	private DebugFilterExecutionOption optionCont;

	public DbgToggleExecutionCommand(DbgManagerImpl manager, int index,
			DebugFilterExecutionOption optionCont) {
		super(manager);
		this.index = index;
		this.optionCont = optionCont;
	}

	@Override
	public void invoke() {
		DebugControl control = manager.getControl();
		DebugFilterInformation info = control.getNumberEventFilters();
		int nEvents = info.getNumberEvents();
		int nExcs = info.getNumberSpecificExceptions();
		if (index < nEvents) {
			DebugSpecificFilterInformation exc =
				control.getSpecificFilterParameters(0, nEvents);
			DEBUG_SPECIFIC_FILTER_PARAMETERS p = exc.getParameter(index);
			p.ExecutionOption = new ULONG(optionCont.ordinal());
			control.setSpecificFilterParameters(0, nEvents, exc);
		}
		else {
			DebugExceptionFilterInformation exc =
				control.getExceptionFilterParameters(nEvents, null, nExcs);
			DEBUG_EXCEPTION_FILTER_PARAMETERS p = exc.getParameter(index);
			p.ExecutionOption = new ULONG(optionCont.ordinal());
			control.setExceptionFilterParameters(nExcs, exc);
		}
	}
}
