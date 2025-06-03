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
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.guest.TracePlatform;

public enum SPLocationTrackingSpec implements RegisterLocationTrackingSpec {
	INSTANCE;

	public static final String CONFIG_NAME = "TRACK_SP";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return TrackLocationAction.NAME_SP;
	}

	@Override
	public Icon getMenuIcon() {
		return TrackLocationAction.ICON_SP;
	}

	@Override
	public String getLocationLabel() {
		return "sp";
	}

	@Override
	public Register computeRegister(DebuggerCoordinates coordinates) {
		TracePlatform platform = coordinates.getPlatform();
		if (platform == null) {
			return null;
		}
		return platform.getCompilerSpec().getStackPointer();
	}

	@Override
	public AddressSpace computeDefaultAddressSpace(DebuggerCoordinates coordinates) {
		return coordinates.getPlatform().getCompilerSpec().getStackBaseSpace();
	}

	@Override
	public boolean shouldDisassemble() {
		return false;
	}
}
