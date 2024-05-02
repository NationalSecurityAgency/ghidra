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

import java.util.Collection;
import java.util.List;

import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.listing.Program;

/**
 * The service for launching Trace RMI targets in the GUI.
 */
@ServiceInfo(
	description = "Manages and presents launchers for Trace RMI Targets",
	defaultProviderName = "ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin")
public interface TraceRmiLauncherService {
	/**
	 * Get all offers for the given program
	 * 
	 * @param program the program
	 * @return the offers
	 */
	Collection<TraceRmiLaunchOffer> getOffers(Program program);

	/**
	 * Get offers with a saved configuration, ordered by most-recently-saved
	 * 
	 * @param program the program
	 * @return the offers
	 */
	List<TraceRmiLaunchOffer> getSavedOffers(Program program);
}
