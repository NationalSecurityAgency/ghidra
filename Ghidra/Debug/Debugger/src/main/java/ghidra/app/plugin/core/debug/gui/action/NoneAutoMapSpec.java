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
package ghidra.app.plugin.core.debug.gui.action;

import java.util.Collection;
import java.util.List;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.ProgramManager;
import ghidra.debug.api.action.AutoMapSpec;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceEvent;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class NoneAutoMapSpec implements AutoMapSpec {
	public static final String CONFIG_NAME = "0_MAP_NONE";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return "Do Not Auto-Map";
	}

	@Override
	public Icon getMenuIcon() {
		return DebuggerResources.ICON_CONFIG;
	}

	@Override
	public Collection<TraceEvent<?, ?>> getChangeTypes() {
		return List.of();
	}

	@Override
	public boolean objectHasType(TraceObjectValue value) {
		return false;
	}

	@Override
	public String getInfoForObjects(Trace trace, long snap) {
		return "";
	}

	@Override
	public boolean hasTask() {
		return false;
	}

	@Override
	public void runTask(PluginTool tool, Trace trace, long snap) {
		// Don't bother launching a task that does nothing
	}

	@Override
	public List<Program> programs(ProgramManager programManager) {
		return List.of();
	}

	@Override
	public boolean performMapping(DebuggerStaticMappingService mappingService, Trace trace,
			long snap, List<Program> programs, TaskMonitor monitor) throws CancelledException {
		return false;
	}
}
