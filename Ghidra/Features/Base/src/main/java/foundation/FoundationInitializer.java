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
package foundation;

import ghidra.app.factory.GhidraToolStateFactory;
import ghidra.app.util.GhidraFileOpenDataFlavorHandlerService;
import ghidra.framework.ModuleInitializer;
import ghidra.framework.PluggableServiceRegistry;
import ghidra.framework.data.ToolStateFactory;
import ghidra.framework.main.datatree.GhidraDataFlavorHandlerService;
import ghidra.program.database.*;

public class FoundationInitializer implements ModuleInitializer {
	@Override
	public void run() {
		PluggableServiceRegistry.registerPluggableService(ToolStateFactory.class,
			new GhidraToolStateFactory());
		PluggableServiceRegistry.registerPluggableService(GhidraDataFlavorHandlerService.class,
			new GhidraDataFlavorHandlerService());
		PluggableServiceRegistry.registerPluggableService(
			GhidraFileOpenDataFlavorHandlerService.class,
			new GhidraFileOpenDataFlavorHandlerService());
		PluggableServiceRegistry.registerPluggableService(DataTypeArchiveMergeManagerFactory.class,
			new GhidraDataTypeArchiveMergeManagerFactory());
		PluggableServiceRegistry.registerPluggableService(ProgramMultiUserMergeManagerFactory.class,
			new GhidraProgramMultiUserMergeManagerFactory());
	}

	@Override
	public String getName() {
		return "Base Module";
	}
}
