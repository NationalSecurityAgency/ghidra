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
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.util.TraceAddressSpace;

public class PCLocationTrackingSpec implements LocationTrackingSpec {
	public static final String CONFIG_NAME = "TRACK_PC";

	private static final PCByRegisterLocationTrackingSpec BY_REG =
		new PCByRegisterLocationTrackingSpec();
	private static final PCByStackLocationTrackingSpec BY_STACK =
		new PCByStackLocationTrackingSpec();

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
	public Address computeTraceAddress(PluginTool tool, DebuggerCoordinates coordinates) {
		if (coordinates.getTime().isSnapOnly()) {
			Address pc = BY_STACK.computeTraceAddress(tool, coordinates);
			if (pc != null) {
				return pc;
			}
		}
		return BY_REG.computeTraceAddress(tool, coordinates);
	}

	// Note it does no good to override affectByRegChange. It must do what we'd avoid anyway.
	@Override
	public boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates) {
		return BY_STACK.affectedByStackChange(stack, coordinates);
	}

	@Override
	public boolean affectedByRegisterChange(TraceAddressSpace space, TraceAddressSnapRange range,
			DebuggerCoordinates coordinates) {
		return BY_REG.affectedByRegisterChange(space, range, coordinates);
	}
}
