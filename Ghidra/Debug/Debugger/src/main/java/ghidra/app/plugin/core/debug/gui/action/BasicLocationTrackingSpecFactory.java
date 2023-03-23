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
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import ghidra.framework.plugintool.PluginTool;

/**
 * The factory for the basic location tracking specs: NONE, PC, SP
 */
public class BasicLocationTrackingSpecFactory implements LocationTrackingSpecFactory {
	public static final List<LocationTrackingSpec> ALL = List.of(
		NoneLocationTrackingSpec.INSTANCE,
		PCLocationTrackingSpec.INSTANCE,
		PCByRegisterLocationTrackingSpec.INSTANCE,
		PCByStackLocationTrackingSpec.INSTANCE,
		SPLocationTrackingSpec.INSTANCE);

	public static final Map<String, LocationTrackingSpec> BY_CONFIG_NAME = ALL.stream()
			.collect(Collectors.toUnmodifiableMap(
				LocationTrackingSpec::getConfigName,
				Function.identity()));

	@Override
	public List<LocationTrackingSpec> getSuggested(PluginTool tool) {
		return ALL;
	}

	@Override
	public LocationTrackingSpec parseSpec(String name) {
		return BY_CONFIG_NAME.get(name);
	}
}
