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
package ghidra.debug.spi.tracermi;

import java.util.Collection;

import ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiHandler;
import ghidra.app.services.InternalTraceRmiService;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A factory of launch offers
 * 
 * <p>
 * Each factory is instantiated only once for the entire application, even when multiple tools are
 * open. Thus, {@link #init(PluginTool)} and {@link #dispose(PluginTool)} will be invoked for each
 * tool.
 */
public interface TraceRmiLaunchOpinion extends ExtensionPoint {
	/**
	 * Register any options
	 * 
	 * @param tool the tool
	 */
	default void registerOptions(Options options) {
	}

	/**
	 * Check if a change in the given option requires a refresh of offers
	 * 
	 * @param optionName the name of the option that changed
	 * @return true to refresh, false otherwise
	 */
	default boolean requiresRefresh(String optionName) {
		return false;
	}

	/**
	 * Generate or retrieve a collection of offers based on the current program.
	 * 
	 * <p>
	 * Take care trying to "validate" a particular mechanism. For example, it is <em>not</em>
	 * appropriate to check that GDB exists, nor to execute it to derive its version.
	 * 
	 * <ol>
	 * <li>It's possible the user has dependencies installed in non-standard locations. I.e., the
	 * user needs a chance to configure things <em>before</em> the UI decides whether or not to
	 * display them.</li>
	 * <li>The menus are meant to display <em>all</em> possibilities installed in Ghidra, even if
	 * some dependencies are missing on the local system. Discovery of the feature is most
	 * important. Knowing a feature exists may motivate a user to obtain the required dependencies
	 * and try it out.</li>
	 * <li>An offer is only promoted to the quick-launch menu upon <em>successful</em> connection.
	 * I.e., the entries there are already validated; they've worked at least once before.</li>
	 * </ol>
	 * 
	 * @param plugin the Trace RMI launcher service plugin. <b>NOTE:</b> to get access to the Trace
	 *            RMI (connection) service, use the {@link InternalTraceRmiService}, so that the
	 *            offers can register the connection's resources. See
	 *            {@link TraceRmiHandler#registerResources(Collection)}. Resource registration is
	 *            required for the Disconnect button to completely terminate the back end.
	 * @param program the current program. While this is not <em>always</em> used by the launcher,
	 *            it is implied that the user expects the debugger to do something with the current
	 *            program, even if it's just informing the back-end debugger of the target image.
	 * @return the offers. The order is ignored, since items are displayed alphabetically.
	 */
	public Collection<TraceRmiLaunchOffer> getOffers(TraceRmiLauncherServicePlugin plugin,
			Program program);
}
