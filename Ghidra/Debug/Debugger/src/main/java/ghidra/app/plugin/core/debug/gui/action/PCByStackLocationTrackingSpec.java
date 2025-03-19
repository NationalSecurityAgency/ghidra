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
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;

public enum PCByStackLocationTrackingSpec implements LocationTrackingSpec, LocationTracker {
	INSTANCE;

	public static final String CONFIG_NAME = "TRACK_PC_BY_STACK";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return TrackLocationAction.NAME_PC_BY_STACK;
	}

	@Override
	public Icon getMenuIcon() {
		return TrackLocationAction.ICON_PC_BY_STACK;
	}

	@Override
	public String computeTitle(DebuggerCoordinates coordinates) {
		return "Stack's PC";
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
		Trace trace = coordinates.getTrace();
		TraceThread thread = coordinates.getThread();
		if (thread == null) {
			return null;
		}
		long snap = coordinates.getSnap();
		TraceStack stack;
		try {
			stack = trace.getStackManager().getLatestStack(thread, snap);
		}
		catch (IllegalStateException e) {
			// Schema does not specify a stack
			return null;
		}
		if (stack == null) {
			return null;
		}
		int level = coordinates.getFrame();
		TraceStackFrame frame = stack.getFrame(snap, level, false);
		if (frame == null) {
			return null;
		}
		return frame.getProgramCounter(snap);
	}

	@Override
	public GoToInput getDefaultGoToInput(ServiceProvider provider, DebuggerCoordinates coordinates,
			ProgramLocation location) {
		Address address = computeTraceAddress(provider, coordinates);
		if (address == null) {
			return NoneLocationTrackingSpec.INSTANCE.getDefaultGoToInput(provider, coordinates,
				location);
		}
		return GoToInput.fromAddress(address);
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
		// TODO: It does in objects mode. Leave until old code is removed.
		TraceStack curStack = coordinates.getTrace()
				.getStackManager()
				.getLatestStack(stack.getThread(), coordinates.getSnap());
		if (stack != curStack) {
			return false;
		}
		return true;
	}

	@Override
	public boolean affectedByBytesChange(TraceAddressSpace space, TraceAddressSnapRange range,
			DebuggerCoordinates coordinates) {
		return false;
	}

	@Override
	public boolean shouldDisassemble() {
		return true;
	}
}
