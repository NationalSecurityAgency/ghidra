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

import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.services.DebuggerWatchesService;
import ghidra.framework.plugintool.PluginTool;

/**
 * The factory for tracking specifications based on watches
 * 
 * <p>
 * This will generate an "address-of-watch" tracking specification for each watch currently in the
 * watches service, i.e., configured in the Watches window.
 */
public class WatchLocationTrackingSpecFactory implements LocationTrackingSpecFactory {

	@Override
	public List<LocationTrackingSpec> getSuggested(PluginTool tool) {
		DebuggerWatchesService watchesService = tool.getService(DebuggerWatchesService.class);
		if (watchesService == null) {
			return List.of();
		}
		return watchesService.getWatches()
				.stream()
				.filter(WatchLocationTrackingSpec::isTrackable)
				.map(WatchLocationTrackingSpec::fromWatch)
				.collect(Collectors.toList());
	}

	@Override
	public LocationTrackingSpec parseSpec(String name) {
		if (!name.startsWith(WatchLocationTrackingSpec.CONFIG_PREFIX)) {
			return null;
		}
		String expression = name.substring(WatchLocationTrackingSpec.CONFIG_PREFIX.length());
		return new WatchLocationTrackingSpec(expression);
	}
}
