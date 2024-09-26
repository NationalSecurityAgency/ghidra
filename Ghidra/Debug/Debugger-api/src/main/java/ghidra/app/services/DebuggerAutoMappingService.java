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

import ghidra.debug.api.action.AutoMapSpec;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.trace.model.Trace;

/**
 * The service to query auto-map settings
 */
@ServiceInfo(defaultProviderName = "ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPlugin")
public interface DebuggerAutoMappingService {
	/**
	 * Get the auto-map setting currently active in the Modules provider
	 * 
	 * @return the current setting
	 */
	AutoMapSpec getAutoMapSpec();

	/**
	 * Get the current auto-map setting for the given trace
	 * 
	 * @param trace the trace
	 * @return the auto-map setting for the trace, or the setting in the Modules provider, if the
	 *         trace does not have its own setting.
	 */
	AutoMapSpec getAutoMapSpec(Trace trace);
}
