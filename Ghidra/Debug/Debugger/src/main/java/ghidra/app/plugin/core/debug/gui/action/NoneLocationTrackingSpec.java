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

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.DebuggerResources.TrackLocationAction;
import ghidra.debug.api.action.*;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.stack.TraceStack;

public enum NoneLocationTrackingSpec implements LocationTrackingSpec, LocationTracker {
	INSTANCE;

	public static final String CONFIG_NAME = "TRACK_NONE";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return TrackLocationAction.NAME_NONE;
	}

	@Override
	public Icon getMenuIcon() {
		return TrackLocationAction.ICON_NONE;
	}

	@Override
	public String computeTitle(DebuggerCoordinates coordinates) {
		return null;
	}

	@Override
	public String getLocationLabel() {
		return null;
	}

	@Override
	public LocationTracker getTracker() {
		return this;
	}

	@Override
	public Address computeTraceAddress(ServiceProvider provider, DebuggerCoordinates coordinates) {
		return null;
	}

	@Override
	public GoToInput getDefaultGoToInput(ServiceProvider provider, DebuggerCoordinates coordinates,
			ProgramLocation location) {
		if (location == null) {
			return GoToInput.fromString("00000000");
		}
		return GoToInput.fromAddress(location.getAddress());
	}

	@Override
	public boolean affectedByBytesChange(AddressSpace space, TraceAddressSnapRange range,
			DebuggerCoordinates coordinates) {
		return false;
	}

	@Override
	public boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates) {
		return false;
	}

	@Override
	public boolean shouldDisassemble() {
		return false;
	}
}
