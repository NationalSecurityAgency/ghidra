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
package ghidra.pcode.exec.trace.data;

import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;

/**
 * The default data-access shim for trace registers
 */
public class DefaultPcodeTraceRegistersAccess extends AbstractPcodeTraceDataAccess
		implements PcodeTraceRegistersAccess {

	protected final TraceThread thread;
	protected final int frame;

	protected TraceMemorySpace ms;

	/**
	 * Construct a shim
	 * 
	 * @param platform the associated platform
	 * @param snap the associated snap
	 * @param thread the associated thread whose registers to access
	 * @param frame the associated frame, or 0 if not applicable
	 * @param viewport the viewport, set to the same snapshot
	 */
	protected DefaultPcodeTraceRegistersAccess(TracePlatform platform, long snap,
			TraceThread thread, int frame, TraceTimeViewport viewport) {
		super(platform, snap, viewport);
		this.thread = thread;
		this.frame = frame;

		this.ms = mm.getMemoryRegisterSpace(thread, frame, false);
	}

	@Override
	protected TraceMemorySpace getMemoryOps(boolean createIfAbsent) {
		if (ms == null) {
			return ms = mm.getMemoryRegisterSpace(thread, frame, createIfAbsent);
		}
		return ms;
	}

	@Override
	public <T> TracePropertyMapSpace<T> getPropertyOps(String name, Class<T> type,
			boolean createIfAbsent) {
		if (createIfAbsent) {
			return platform.getTrace()
					.getAddressPropertyManager()
					.getOrCreatePropertyMap(name, type)
					.getPropertyMapRegisterSpace(thread, frame, createIfAbsent);
		}
		TracePropertyMap<T> map = platform.getTrace()
				.getAddressPropertyManager()
				.getPropertyMap(name, type);
		return map == null ? null : map.getPropertyMapRegisterSpace(thread, frame, createIfAbsent);
	}

	/**
	 * Check if a register has a {@link TraceMemoryState#KNOWN} value for the given thread
	 * 
	 * @param thread the thread
	 * @param register the register
	 * @return true if known
	 */
	protected boolean isRegisterKnown(PcodeThread<?> thread, Register register) {
		Trace trace = platform.getTrace();
		TraceThread traceThread =
			trace.getThreadManager().getLiveThreadByPath(snap, thread.getName());
		TraceMemorySpace space =
			trace.getMemoryManager().getMemoryRegisterSpace(traceThread, false);
		if (space == null) {
			return false;
		}
		return space.getState(platform, snap, register) == TraceMemoryState.KNOWN;
	}

	@Override
	public void initializeThreadContext(PcodeThread<?> thread) {
		Trace trace = platform.getTrace();
		Language language = platform.getLanguage();
		Register contextreg = language.getContextBaseRegister();
		if (contextreg != Register.NO_CONTEXT && !isRegisterKnown(thread, contextreg)) {
			RegisterValue context = trace.getRegisterContextManager()
					.getValueWithDefault(platform, contextreg, snap, thread.getCounter());
			if (context != null) { // TODO: Why does this happen?
				thread.overrideContext(context);
			}
		}
	}

	@Override
	protected Address toOverlay(Address address) {
		TraceMemorySpace ops = getMemoryOps(false);
		if (ops == null) {
			return null; // client should bail anyway
		}
		return ops.getAddressSpace().getOverlayAddress(address);
	}

	@Override
	protected AddressRange toOverlay(AddressRange range) {
		TraceMemorySpace ops = getMemoryOps(false);
		if (ops == null) {
			return null; // client should bail anyway
		}
		AddressSpace space = ops.getAddressSpace();
		return TraceRegisterUtils.getOverlayRange(space, range);
	}

	@Override
	protected AddressSetView toOverlay(AddressSetView set) {
		TraceMemorySpace ops = getMemoryOps(false);
		if (ops == null) {
			return null; // client should bail anyway
		}
		AddressSpace space = ops.getAddressSpace();
		return TraceRegisterUtils.getOverlaySet(space, set);
	}
}
