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

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.TrackLocationAction;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;

public class SPLocationTrackingSpec implements RegisterLocationTrackingSpec {
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
	public Register computeRegister(DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		if (trace == null) {
			return null;
		}
		return trace.getBaseCompilerSpec().getStackPointer();
	}

	@Override
	public AddressSpace computeDefaultAddressSpace(DebuggerCoordinates coordinates) {
		return coordinates.getTrace().getBaseLanguage().getDefaultDataSpace();
	}
}
