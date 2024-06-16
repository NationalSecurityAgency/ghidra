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
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.util.TraceAddressSpace;

public enum PCLocationTrackingSpec implements LocationTrackingSpec, LocationTracker {
	INSTANCE;

	public static final String CONFIG_NAME = "TRACK_PC";

	private static final PCByRegisterLocationTrackingSpec BY_REG =
		PCByRegisterLocationTrackingSpec.INSTANCE;
	private static final PCByStackLocationTrackingSpec BY_STACK =
		PCByStackLocationTrackingSpec.INSTANCE;

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return TrackLocationAction.NAME_PC;
	}

	@Override
	public Icon getMenuIcon() {
		return TrackLocationAction.ICON_PC;
	}

	@Override
	public String computeTitle(DebuggerCoordinates coordinates) {
		return "Auto PC";
	}

	@Override
	public String getLocationLabel() {
		return "pc";
	}

	@Override
	public LocationTracker getTracker() {
		return this;
	}

	@Override
	public Address computeTraceAddress(ServiceProvider provider, DebuggerCoordinates coordinates) {
		if (coordinates.getTime().isSnapOnly()) {
			Address pc = BY_STACK.computeTraceAddress(provider, coordinates);
			if (pc != null) {
				return pc;
			}
		}
		return BY_REG.computeTraceAddress(provider, coordinates);
	}

	@Override
	public GoToInput getDefaultGoToInput(ServiceProvider provider, DebuggerCoordinates coordinates,
			ProgramLocation location) {
		return BY_REG.getDefaultGoToInput(provider, coordinates, location);
	}

	// Note it does no good to override affectByRegChange. It must do what we'd avoid anyway.
	@Override
	public boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates) {
		return BY_STACK.affectedByStackChange(stack, coordinates);
	}

	@Override
	public boolean affectedByBytesChange(TraceAddressSpace space, TraceAddressSnapRange range,
			DebuggerCoordinates coordinates) {
		return BY_REG.affectedByBytesChange(space, range, coordinates);
	}

	@Override
	public boolean shouldDisassemble() {
		return true;
	}
}
