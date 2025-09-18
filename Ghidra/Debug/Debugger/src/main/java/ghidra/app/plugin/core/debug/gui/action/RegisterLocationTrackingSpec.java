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

import ghidra.debug.api.action.*;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;

public interface RegisterLocationTrackingSpec extends LocationTrackingSpec, LocationTracker {
	Register computeRegister(DebuggerCoordinates coordinates);

	AddressSpace computeDefaultAddressSpace(DebuggerCoordinates coordinates);

	@Override
	default String computeTitle(DebuggerCoordinates coordinates) {
		Register register = computeRegister(coordinates);
		if (register == null) {
			return null;
		}
		return register.getName();
	}

	@Override
	default LocationTracker getTracker() {
		return this;
	}

	@Override
	default Address computeTraceAddress(ServiceProvider provider, DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		TracePlatform platform = coordinates.getPlatform();
		TraceThread thread = coordinates.getThread();
		if (thread == null) {
			return null;
		}
		long viewSnap = coordinates.getViewSnap();
		long snap = coordinates.getSnap();
		int frame = coordinates.getFrame();
		Register reg = computeRegister(coordinates);
		if (reg == null) {
			return null;
		}
		if (!thread.isValid(snap)) {
			return null;
		}
		TraceMemorySpace regs = reg.getAddressSpace().isRegisterSpace()
				? trace.getMemoryManager().getMemoryRegisterSpace(thread, frame, false)
				: trace.getMemoryManager().getMemorySpace(reg.getAddressSpace(), false);
		if (regs == null) {
			return null;
		}
		RegisterValue value;
		if (regs.getState(platform, viewSnap, reg) == TraceMemoryState.KNOWN) {
			value = regs.getValue(platform, viewSnap, reg);
		}
		else {
			value = regs.getValue(platform, snap, reg);
		}
		if (value == null) {
			return null;
		}
		/**
		 * NOTE: I don't think the user needs a way to select the address space. For PC and SP, the
		 * tracker provides the best default, i.e., the default (code) space and the compiler's
		 * physical stack space. For watches, I believe the sleigh syntax allows the user to pick,
		 * but I can't recall testing that.
		 */
		return platform.mapGuestToHost(computeDefaultAddressSpace(coordinates)
				.getAddress(value.getUnsignedValue().longValue(), true));
	}

	@Override
	default GoToInput getDefaultGoToInput(ServiceProvider provider, DebuggerCoordinates coordinates,
			ProgramLocation location) {
		Register register = computeRegister(coordinates);
		return GoToInput.offsetOnly(register.getName());
	}

	@Override
	default boolean affectedByBytesChange(AddressSpace space, TraceAddressSnapRange range,
			DebuggerCoordinates coordinates) {
		if (!LocationTrackingSpec.changeIsCurrent(space, range, coordinates)) {
			return false;
		}
		Register register = computeRegister(coordinates);
		if (register == null) {
			return false;
		}
		AddressRange regRng = coordinates.getPlatform()
				.getConventionalRegisterRange(space.isRegisterSpace() ? space : null, register);
		return range.getRange().intersects(regRng);
	}

	@Override
	default boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates) {
		return false;
	}
}
