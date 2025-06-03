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
package ghidra.app.plugin.core.debug.gui.modules;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.program.model.address.Address;
import ghidra.trace.model.modules.TraceModule;

public class ModuleRow {
	private final DebuggerModulesProvider provider;
	private final TraceModule module;

	public ModuleRow(DebuggerModulesProvider provider, TraceModule module) {
		this.provider = provider;
		this.module = module;
	}

	public TraceModule getModule() {
		return module;
	}

	public void setName(String name) {
		try (Transaction tx = module.getTrace().openTransaction("Renamed module")) {
			module.setName(0, name);
		}
	}

	public String getShortName() {
		return DebuggerStaticMappingUtils.computeModuleShortName(module.getName(0));
	}

	public String getName() {
		return module.getName(0);
	}

	public String getMapping() {
		// TODO: Cache this? Would flush on:
		//    1. Mapping changes
		//    2. Range/Life changes to this module
		//    3. Snapshot navigation
		return DebuggerStaticMappingUtils.computeMappedFiles(module.getTrace(),
			provider.current.getSnap(), module.getRange(0));
	}

	public Address getBase() {
		return module.getBase(0);
	}

	public Address getMaxAddress() {
		return module.getMaxAddress(0);
	}

	public long getLength() {
		return module.getLength(0);
	}
}
