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
package ghidra.app.plugin.core.debug.event;

import ghidra.debug.api.action.LocationTrackingSpec;
import ghidra.framework.plugintool.PluginEvent;

public class TrackingChangedPluginEvent extends PluginEvent {
	public static final String NAME = "TrackingChanged";

	private final LocationTrackingSpec spec;

	public TrackingChangedPluginEvent(String sourceName, LocationTrackingSpec spec) {
		super(sourceName, NAME);
		this.spec = spec;
	}

	public LocationTrackingSpec getLocationTrackingSpec() {
		return spec;
	}
}
