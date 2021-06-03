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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;

public class PCLocationTrackingSpec implements RegisterLocationTrackingSpec {
	public static final String CONFIG_NAME = "TRACK_PC";

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
	public Register computeRegister(DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		if (trace == null) {
			return null;
		}
		return trace.getBaseLanguage().getProgramCounter();
	}

	@Override
	public AddressSpace computeDefaultAddressSpace(DebuggerCoordinates coordinates) {
		return coordinates.getTrace().getBaseLanguage().getDefaultSpace();
	}

	public Address computePCViaStack(DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		TraceThread thread = coordinates.getThread();
		long snap = coordinates.getSnap();
		TraceStack stack = trace.getStackManager().getLatestStack(thread, snap);
		if (stack == null) {
			return null;
		}
		int level = coordinates.getFrame();
		TraceStackFrame frame = stack.getFrame(level, false);
		if (frame == null) {
			return null;
		}
		return frame.getProgramCounter();
	}

	@Override
	public Address computeTraceAddress(PluginTool tool, DebuggerCoordinates coordinates,
			long emuSnap) {
		if (coordinates.getTime().isSnapOnly()) {
			Address pc = computePCViaStack(coordinates);
			if (pc != null) {
				return pc;
			}
		}
		return RegisterLocationTrackingSpec.super.computeTraceAddress(tool, coordinates, emuSnap);
	}

	// Note it does no good to override affectByRegChange. It must do what we'd avoid anyway.
	@Override
	public boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates) {
		if (stack.getThread() != coordinates.getThread()) {
			return false;
		}
		if (!coordinates.getTime().isSnapOnly()) {
			return false;
		}
		// TODO: Would be nice to have stack lifespan...
		TraceStack curStack = coordinates.getTrace()
				.getStackManager()
				.getLatestStack(stack.getThread(), coordinates.getSnap());
		if (stack != curStack) {
			return false;
		}
		return true;
	}
}
