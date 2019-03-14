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
package ghidra.app.services;

import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.programtree.ViewProviderService;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * Service to manage generic views; the view controls what shows up in the code
 * browser.
 */
@ServiceInfo(defaultProvider = ProgramTreePlugin.class, description = "Manage generic views")
public interface ViewManagerService extends ViewService {

	/**
	 * Set the current view to the provider with the given name.
	 * 
	 * @param viewName
	 */
	public void setCurrentViewProvider(String viewName);

	/**
	 * Get the current view provider.
	 */
	public ViewProviderService getCurrentViewProvider();

	/**
	 * Notification that a view name has changed.
	 * 
	 * @param vps service whose name has changed
	 * @param oldName old name of the service
	 */
	public void viewNameChanged(ViewProviderService vps, String oldName);

}
