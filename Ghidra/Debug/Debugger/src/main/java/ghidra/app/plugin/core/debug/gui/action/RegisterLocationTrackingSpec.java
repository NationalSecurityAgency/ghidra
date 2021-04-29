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

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceRegisterUtils;

// TODO: Use this, or allow arbitrary expressions
public interface RegisterLocationTrackingSpec extends LocationTrackingSpec {
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
	default Address computeTraceAddress(PluginTool tool, DebuggerCoordinates coordinates,
			long emuSnap) {
		Trace trace = coordinates.getTrace();
		TraceThread thread = coordinates.getThread();
		long snap = coordinates.getSnap();
		int frame = coordinates.getFrame();
		Register reg = computeRegister(coordinates);
		if (reg == null) {
			return null;
		}
		if (!thread.getLifespan().contains(snap)) {
			return null;
		}
		TraceMemoryRegisterSpace regs =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, frame, false);
		if (regs == null) {
			return null;
		}
		RegisterValue value;
		if (regs.getState(emuSnap, reg) == TraceMemoryState.KNOWN) {
			value = regs.getValue(emuSnap, reg);
		}
		else {
			value = regs.getValue(snap, reg);
		}
		if (value == null) {
			return null;
		}
		// TODO: Action to select the address space
		// Could use code unit, but that can't specify space, yet, either....
		return computeDefaultAddressSpace(coordinates)
				.getAddress(value.getUnsignedValue().longValue());
	}

	@Override
	default boolean affectedByRegisterChange(TraceAddressSpace space,
			TraceAddressSnapRange range, DebuggerCoordinates coordinates) {
		if (!LocationTrackingSpec.changeIsCurrent(space, range, coordinates)) {
			return false;
		}
		Register register = computeRegister(coordinates);
		AddressRange regRng = TraceRegisterUtils.rangeForRegister(register);
		return range.getRange().intersects(regRng);
	}

	@Override
	default boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates) {
		return false;
	}
}
