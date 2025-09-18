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
package ghidra.app.plugin.core.debug.gui.time;

import java.util.Date;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class SnapshotRow {
	private final TraceSnapshot snapshot;
	private final ServiceProvider serviceProvider;

	private final Trace trace;

	public SnapshotRow(TraceSnapshot snapshot, ServiceProvider serviceProvider) {
		this.snapshot = snapshot;
		this.serviceProvider = serviceProvider;
		this.trace = snapshot.getTrace();
	}

	public TraceSnapshot getSnapshot() {
		return snapshot;
	}

	public TraceSchedule getTime() {
		long snap = snapshot.getKey();
		if (snap < 0) {
			return snapshot.getSchedule();
		}
		return TraceSchedule.snap(snap);
	}

	public long getSnap() {
		return snapshot.getKey();
	}

	public Date getTimeStamp() {
		return new Date(snapshot.getRealTime());
	}

	private Address getProgramCounterByStack() {
		TraceThread thread = snapshot.getEventThread();
		if (thread == null) {
			return null;
		}
		long snap = getTime().getSnap();
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
		TraceStackFrame frame = stack.getFrame(snap, 0, false);
		if (frame == null) {
			return null;
		}
		return frame.getProgramCounter(snap);
	}

	private Address getProgramCounterByRegister() {
		TraceThread thread = getEventThread();
		if (thread == null) {
			return null;
		}
		long viewSnap = snapshot.getKey();
		long snap = getTime().getSnap();
		/**
		 * LATER: Some notion of an event platform? Or perhaps the thread has some attribute to
		 * indicate which platform is active?
		 * 
		 * I could use the tool's "current" platform, but that may produce odd behavior when
		 * changing platforms. Each would have the most recent PC for the selected platform, which
		 * is totally irrelevant. For now, seek out the platform with the most recent update to its
		 * PC for the event thread. While this should be perfectly accurate, it's a bit expensive.
		 */
		record MostRecentValue(TracePlatform platform, long snap, RegisterValue value) {
			static MostRecentValue choose(MostRecentValue a, MostRecentValue b) {
				if (a == null) {
					return b;
				}
				if (b == null) {
					return a;
				}
				// Prefer negative ("view") snaps to positive. Of that, pick most recent.
				if (Long.compareUnsigned(a.snap, b.snap) > 0) {
					return a;
				}
				return b;
			}

			static MostRecentValue get(TracePlatform platform, TraceThread thread, long viewSnap,
					long snap) {
				Register reg = platform.getLanguage().getProgramCounter();
				TraceMemoryManager mm = thread.getTrace().getMemoryManager();
				TraceMemorySpace regs = reg.getAddressSpace().isRegisterSpace()
						? mm.getMemoryRegisterSpace(thread, false)
						: mm.getMemorySpace(reg.getAddressSpace(), false);
				if (regs == null) {
					return null;
				}
				if (regs.getState(platform, viewSnap, reg) == TraceMemoryState.KNOWN) {
					RegisterValue value = regs.getValue(platform, viewSnap, reg);
					return value == null ? null : new MostRecentValue(platform, viewSnap, value);
				}
				RegisterValue value = regs.getValue(platform, snap, reg);
				return value == null ? null : new MostRecentValue(platform, snap, value);
			}

			Address mapToHost() {
				AddressSpace codeSpace = platform.getAddressFactory().getDefaultAddressSpace();
				return platform.mapGuestToHost(
					codeSpace.getAddress(value.getUnsignedValue().longValue(), true));
			}
		}
		MostRecentValue choice = MostRecentValue.get(trace.getPlatformManager().getHostPlatform(),
			thread, viewSnap, snap);
		for (TraceGuestPlatform guest : trace.getPlatformManager().getGuestPlatforms()) {
			choice =
				MostRecentValue.choose(choice, MostRecentValue.get(guest, thread, viewSnap, snap));
		}
		return choice == null ? null : choice.mapToHost();
	}

	public Address getProgramCounter() {
		Address byStack = getProgramCounterByStack();
		return byStack != null ? byStack : getProgramCounterByRegister();
	}

	public Function getFunction() {
		Address pc = getProgramCounter();
		if (pc == null) {
			return null;
		}
		return DebuggerStaticMappingUtils.getFunction(pc, trace, getTime().getSnap(),
			serviceProvider);
	}

	public String getModuleName() {
		Address pc = getProgramCounter();
		if (pc == null) {
			return null;
		}
		return DebuggerStaticMappingUtils.getModuleName(pc, trace, getTime().getSnap());
	}

	private TraceThread getEventThread() {
		TraceThread thread = snapshot.getEventThread();
		if (thread != null) {
			return thread;
		}
		return getTime().getLastThread(trace);
	}

	public String getEventThreadName() {
		TraceThread thread = getEventThread();
		return thread == null ? "" : thread.getName(getTime().getSnap());
	}

	public TraceSchedule getSchedule() {
		return snapshot.getSchedule();
	}

	public String getDescription() {
		return snapshot.getDescription();
	}

	public void setDescription(String description) {
		try (Transaction tx = trace.openTransaction("Modify snapshot description")) {
			snapshot.setDescription(description);
		}
	}
}
