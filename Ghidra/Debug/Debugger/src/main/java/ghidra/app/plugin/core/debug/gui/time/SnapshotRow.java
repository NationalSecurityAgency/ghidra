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
import ghidra.app.util.PseudoInstruction;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.util.ProgramContextImpl;
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
	private final SnapshotTableModel model;
	private final ServiceProvider serviceProvider;

	private final Trace trace;

	record Cached<T>(int version, T value) {
		boolean invalid(int version) {
			return this.version != version;
		}
	}

	private Cached<Address> pc;
	private Cached<Function> function;
	private Cached<String> moduleName;
	private Cached<String> eventThreadName;
	private Cached<Instruction> instruction;

	public SnapshotRow(TraceSnapshot snapshot, SnapshotTableModel model,
			ServiceProvider serviceProvider) {
		this.snapshot = snapshot;
		this.model = model;
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
		// Use snap only for the object structure. Actual value must be in view snapshot
		long snap = getTime().getSnap();
		long viewSnap = snapshot.getKey();
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
		return frame.getProgramCounter(viewSnap);
	}

	record ProgramCounterInfo(TracePlatform platform, long snap, RegisterValue value) {
		static ProgramCounterInfo choose(ProgramCounterInfo a, ProgramCounterInfo b) {
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

		static ProgramCounterInfo get(TracePlatform platform, TraceThread thread, long viewSnap,
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
				return value == null ? null : new ProgramCounterInfo(platform, viewSnap, value);
			}
			RegisterValue value = regs.getValue(platform, snap, reg);
			return value == null ? null : new ProgramCounterInfo(platform, snap, value);
		}

		Address mapToHost() {
			AddressSpace codeSpace = platform.getAddressFactory().getDefaultAddressSpace();
			return platform.mapGuestToHost(
				codeSpace.getAddress(value.getUnsignedValue().longValue(), true));
		}
	}

	private ProgramCounterInfo getProgramCounterByRegister() {
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

		ProgramCounterInfo choice = ProgramCounterInfo
				.get(trace.getPlatformManager().getHostPlatform(), thread, viewSnap, snap);
		for (TraceGuestPlatform guest : trace.getPlatformManager().getGuestPlatforms()) {
			choice = ProgramCounterInfo.choose(choice,
				ProgramCounterInfo.get(guest, thread, viewSnap, snap));
		}
		return choice;
	}

	private Address computeProgramCounter() {
		Address byStack = getProgramCounterByStack();
		if (byStack != null) {
			return byStack;
		}
		ProgramCounterInfo info = getProgramCounterByRegister();
		return info == null ? null : info.mapToHost();
	}

	public Address getProgramCounter() {
		if (pc == null || pc.invalid(model.cacheVersion)) {
			pc = new Cached<>(model.cacheVersion, computeProgramCounter());
		}
		return pc.value();
	}

	private Function computeFunction() {
		Address pc = getProgramCounter();
		if (pc == null) {
			return null;
		}
		return DebuggerStaticMappingUtils.getFunction(pc, trace, getTime().getSnap(),
			serviceProvider);
	}

	public Function getFunction() {
		if (function == null || function.invalid(model.cacheVersion)) {
			function = new Cached<>(model.cacheVersion, computeFunction());
		}
		return function.value();
	}

	private String computeModuleName() {
		Address pc = getProgramCounter();
		if (pc == null) {
			return null;
		}
		return DebuggerStaticMappingUtils.getModuleName(pc, trace, getTime().getSnap());
	}

	public String getModuleName() {
		if (moduleName == null || moduleName.invalid(model.cacheVersion)) {
			moduleName = new Cached<>(model.cacheVersion, computeModuleName());
		}
		return moduleName.value();
	}

	private TraceThread getEventThread() {
		TraceThread thread = snapshot.getEventThread();
		if (thread != null) {
			return thread;
		}
		return getTime().getLastThread(trace);
	}

	private String computeEventThreadName() {
		TraceThread thread = getEventThread();
		return thread == null ? "" : thread.getName(getTime().getSnap());
	}

	public String getEventThreadName() {
		if (eventThreadName == null || eventThreadName.invalid(model.cacheVersion)) {
			eventThreadName = new Cached<>(model.cacheVersion, computeEventThreadName());
		}
		return eventThreadName.value();
	}

	public TraceSchedule getSchedule() {
		return snapshot.getSchedule();
	}

	public String getDescription() {
		return snapshot.getDescription();
	}

	public void setDescription(String description) {
		try (Transaction _ = trace.openTransaction("Modify snapshot description")) {
			snapshot.setDescription(description);
		}
	}

	private Instruction computeInstruction() {
		// I need the platform, no matter where the counter comes from
		ProgramCounterInfo info = getProgramCounterByRegister();
		if (info == null) {
			return null;
		}
		Address pc = getProgramCounterByStack();
		if (pc == null) {
			pc = info.mapToHost();
		}

		TracePlatform platform = info.platform();
		Language language = platform.getLanguage();
		Register ctxreg = language.getContextBaseRegister();
		long snap = getSnap();
		MemBuffer buf = trace.getMemoryManager().getBufferAt(snap, pc);
		ProcessorContext context = new ProcessorContextImpl(language);
		if (ctxreg != null && ctxreg != Register.NO_CONTEXT) {
			TraceMemorySpace regs =
				trace.getMemoryManager().getMemoryRegisterSpace(getEventThread(), false);
			RegisterValue ctxval;
			if (regs == null) {
				ProgramContextImpl defaultContext = new ProgramContextImpl(language);
				language.applyContextSettings(defaultContext);
				ctxval = defaultContext.getDefaultDisassemblyContext();
			}
			else {
				ctxval = regs.getValue(platform, snap, ctxreg);
			}
			try {
				context.setRegisterValue(ctxval);
			}
			catch (ContextChangeException e) {
				throw new AssertionError(e);
			}
		}
		InstructionPrototype prototype;
		try {
			prototype = language.parse(buf, context, false);
		}
		catch (InsufficientBytesException | UnknownInstructionException e) {
			return null;
		}
		try {
			return new PseudoInstruction(pc, prototype, buf, context);
		}
		catch (AddressOverflowException e) {
			return null;
		}
	}

	public Instruction getInstruction() {
		if (instruction == null || instruction.invalid(model.cacheVersion)) {
			instruction = new Cached<>(model.cacheVersion, computeInstruction());
		}
		return instruction.value();
	}
}
