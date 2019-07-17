/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.diff;

import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.ServiceListener;

public class DiffServiceProvider implements ServiceProvider {
	
	private ServiceProvider serviceProvider;
	private ProgramDiffPlugin programDiffPlugin;
	private DiffProgramManager diffProgramManager;
	private DiffGoToService diffGoToService;
	
	DiffServiceProvider(ServiceProvider serviceProvider, ProgramDiffPlugin programDiffPlugin) {
		this.serviceProvider = serviceProvider;
		this.programDiffPlugin = programDiffPlugin;
		this.diffProgramManager = new DiffProgramManager(this.programDiffPlugin);
		GoToService goToService = serviceProvider.getService(GoToService.class);
		this.diffGoToService = new DiffGoToService(goToService, programDiffPlugin);
	}

	public void addServiceListener(ServiceListener listener) {
		serviceProvider.addServiceListener(listener);
	}

	public <T> T getService(Class<T> serviceClass) {
		if (serviceClass == ProgramManager.class) {
			return serviceClass.cast( diffProgramManager );
		}
		else if (serviceClass == GoToService.class) {
			return serviceClass.cast( diffGoToService );
		}
		return serviceProvider.getService(serviceClass);
	}

	public void removeServiceListener(ServiceListener listener) {
		serviceProvider.removeServiceListener(listener);
	}

}
