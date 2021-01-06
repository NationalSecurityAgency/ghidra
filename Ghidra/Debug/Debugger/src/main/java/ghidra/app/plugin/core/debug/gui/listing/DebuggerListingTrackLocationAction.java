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
package ghidra.app.plugin.core.debug.gui.listing;

import docking.action.builder.MultiStateActionBuilder;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.TrackLocationAction;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceRegisterUtils;

public interface DebuggerListingTrackLocationAction extends TrackLocationAction {
	public interface LocationTrackingSpec {
		LocationTrackingSpec TRACK_PC = new PCLocationTrackingSpec();
		LocationTrackingSpec TRACK_SP = new SPLocationTrackingSpec();
		LocationTrackingSpec TRACK_NONE = new NoneLocationTrackingSpec();

		public static class TrackingSpecConfigFieldCodec
				implements ConfigFieldCodec<LocationTrackingSpec> {
			@Override
			public LocationTrackingSpec read(SaveState state, String name,
					LocationTrackingSpec current) {
				String specName = state.getString(name, null);
				return fromConfigName(specName);
			}

			@Override
			public void write(SaveState state, String name, LocationTrackingSpec value) {
				state.putString(name, value.getConfigName());
			}
		}

		static boolean changeIsCurrent(TraceAddressSpace space, TraceAddressSnapRange range,
				DebuggerCoordinates current) {
			if (space == null || space.getThread() != current.getThread()) {
				return false;
			}
			if (space.getFrameLevel() != current.getFrame()) {
				return false;
			}
			if (!range.getLifespan().contains(current.getSnap())) {
				return false;
			}
			return true;
		}

		static LocationTrackingSpec fromConfigName(String spec) {
			switch (spec) {
				default:
				case PCLocationTrackingSpec.CONFIG_NAME:
					return TRACK_PC;
				case SPLocationTrackingSpec.CONFIG_NAME:
					return TRACK_SP;
				case NoneLocationTrackingSpec.CONFIG_NAME:
					return TRACK_NONE;
			}
		}

		String getConfigName();

		/**
		 * Compute a title prefix to indicate this tracking specification
		 * 
		 * @param thread the provider's current thread
		 * @return a prefix, or {@code null} to use a default
		 */
		String computeTitle(DebuggerCoordinates coordinates);

		Address computeTraceAddress(DebuggerCoordinates coordinates, long emuSnap);

		// TODO: Is there a way to generalize these so that other dependencies need not
		// have their own bespoke methods?

		boolean affectedByRegisterChange(TraceAddressSpace space,
				TraceAddressSnapRange range, DebuggerCoordinates coordinates);

		boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates);
	}

	class NoneLocationTrackingSpec implements LocationTrackingSpec {
		static final String CONFIG_NAME = "TRACK_NONE";

		@Override
		public String getConfigName() {
			return CONFIG_NAME;
		}

		@Override
		public String computeTitle(DebuggerCoordinates coordinates) {
			return null;
		}

		@Override
		public Address computeTraceAddress(DebuggerCoordinates coordinates, long emuSnap) {
			return null;
		}

		@Override
		public boolean affectedByRegisterChange(TraceAddressSpace space,
				TraceAddressSnapRange range, DebuggerCoordinates coordinates) {
			return false;
		}

		@Override
		public boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates) {
			return false;
		}
	}

	// TODO: Use this, or allow arbitrary expressions
	interface RegisterLocationTrackingSpec extends LocationTrackingSpec {
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
		default Address computeTraceAddress(DebuggerCoordinates coordinates, long emuSnap) {
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

	class PCLocationTrackingSpec implements RegisterLocationTrackingSpec {
		static final String CONFIG_NAME = "TRACK_PC";

		@Override
		public String getConfigName() {
			return CONFIG_NAME;
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
		public Address computeTraceAddress(DebuggerCoordinates coordinates, long emuSnap) {
			if (coordinates.getTime().isSnapOnly()) {
				Address pc = computePCViaStack(coordinates);
				if (pc != null) {
					return pc;
				}
			}
			return RegisterLocationTrackingSpec.super.computeTraceAddress(coordinates, emuSnap);
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

	class SPLocationTrackingSpec implements RegisterLocationTrackingSpec {
		static final String CONFIG_NAME = "TRACK_SP";

		@Override
		public String getConfigName() {
			return CONFIG_NAME;
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

	static MultiStateActionBuilder<LocationTrackingSpec> builder(Plugin owner) {
		MultiStateActionBuilder<LocationTrackingSpec> builder = TrackLocationAction.builder(owner);
		return builder
				.toolBarGroup(owner.getName())
				.performActionOnButtonClick(true)
				.addState(NAME_NONE, ICON_NONE, LocationTrackingSpec.TRACK_NONE)
				.addState(NAME_PC, ICON_PC, LocationTrackingSpec.TRACK_PC)
				.addState(NAME_SP, ICON_SP, LocationTrackingSpec.TRACK_SP);
	}
}
