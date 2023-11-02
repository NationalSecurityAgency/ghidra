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

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceConflictedMappingException;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OneToOneAutoMapSpec implements AutoMapSpec {
	public static final String CONFIG_NAME = "2_MAP_ONE_TO_ONE";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return "Auto-Map Identically (1-to-1)";
	}

	@Override
	public Collection<TraceChangeType<?, ?>> getChangeTypes() {
		return List.of();
	}

	@Override
	public void performMapping(DebuggerStaticMappingService mappingService, Trace trace,
			ProgramManager programManager, TaskMonitor monitor) throws CancelledException {
		Program program = programManager.getCurrentProgram();
		if (program == null) {
			return;
		}
		try {
			mappingService.addIdentityMapping(trace, program,
				Lifespan.nowOn(trace.getProgramView().getSnap()), false);
		}
		catch (TraceConflictedMappingException e) {
			// aww well
		}
	}
}
