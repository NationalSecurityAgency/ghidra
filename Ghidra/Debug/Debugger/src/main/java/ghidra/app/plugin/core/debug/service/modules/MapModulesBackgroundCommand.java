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
package ghidra.app.plugin.core.debug.service.modules;

import java.util.Collection;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.ModuleMapEntry;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MapModulesBackgroundCommand extends BackgroundCommand {
	private final DebuggerStaticMappingService service;
	private final Collection<ModuleMapEntry> entries;

	public MapModulesBackgroundCommand(DebuggerStaticMappingService service,
			Collection<ModuleMapEntry> entries) {
		super("Map modules", true, true, true);
		this.service = service;
		this.entries = entries;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		try {
			service.addModuleMappings(entries, monitor, true);
		}
		catch (CancelledException e) {
			return false;
		}
		return true;
	}
}
