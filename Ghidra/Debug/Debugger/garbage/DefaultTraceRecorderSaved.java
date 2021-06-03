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
package ghidra.app.plugin.core.debug.service.model;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.google.common.collect.*;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.services.TraceRecorder;
import ghidra.app.services.TraceRecorderListener;
import ghidra.async.*;
import ghidra.async.AsyncLazyMap.KeyedFuture;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AllRequiredAccess;
import ghidra.dbg.DebugModelConventions.SubTreeListenerAdapter;
import ghidra.dbg.attributes.*;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibility;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointSpecListener;
import ghidra.dbg.target.TargetEventScope.TargetEventScopeListener;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionStateListener;
import ghidra.dbg.target.TargetFocusScope.TargetFocusScopeListener;
import ghidra.dbg.target.TargetMemory.TargetMemoryListener;
import ghidra.dbg.target.TargetRegisterBank.TargetRegisterBankListener;
import ghidra.dbg.util.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.listing.TraceCodeManager;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.*;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DefaultTraceRecorderSaved implements TraceRecorder {

	private static final boolean LOG_STACK_TRACE = false;
	// For large memory captures
	private static final int BLOCK_SIZE = 4096;
	private static final long BLOCK_MASK = -1L << 12;

	static final PathMatcher HARDCODED_MATCHER = new PathMatcher() {
		{
			// Paths for GDB
			addPattern(PathUtils.parse("Breakpoints[]."));
			addPattern(PathUtils.parse("Inferiors[].Memory[]"));
			addPattern(PathUtils.parse("Inferiors[].Modules[].Sections[]"));
			addPattern(PathUtils.parse("Inferiors[].Registers[]"));
			addPattern(PathUtils.parse("Inferiors[].Threads[]"));
			addPattern(PathUtils.parse("Inferiors[].Threads[].Stack[]"));

			// Paths for dbgeng
			addPattern(PathUtils.parse("Sessions[].Processes[].Memory[]"));
			addPattern(PathUtils.parse("Sessions[].Processes[].Modules[]"));
			addPattern(PathUtils.parse("Sessions[].Processes[].Threads[].Registers[]"));
			addPattern(PathUtils.parse("Sessions[].Processes[].Threads[].Stack[]"));
			addPattern(PathUtils.parse("Sessions[].Processes[].Debug.Breakpoints[]"));

			// (Additional) paths for dbgmodel
			addPattern(PathUtils.parse("Sessions[].Attributes"));
			addPattern(PathUtils.parse("Sessions[].Processes[].Threads[].Stack.Frames[]"));
			addPattern(PathUtils.parse("Sessions[].Processes[].Threads[].TTD.Position"));
			addPattern(PathUtils.parse("Sessions[].Processes[].Threads[].Registers.User."));

			// Paths for JDI
			addPattern(PathUtils.parse("VirtualMachines[]"));
			addPattern(PathUtils.parse("VirtualMachines[].Breakpoints"));
			addPattern(PathUtils.parse("VirtualMachines[].Classes[]"));
			addPattern(PathUtils.parse("VirtualMachines[].Classes[].Sections[]"));
			addPattern(PathUtils.parse("VirtualMachines[].Threads[]"));
			addPattern(PathUtils.parse("VirtualMachines[].Threads[].Registers[]"));
			addPattern(PathUtils.parse("VirtualMachines[].Threads[].Stack[]"));

		}
	};

	protected static class PermanentTransaction implements AutoCloseable {
		static PermanentTransaction start(Trace trace, String description) {
			UndoableTransaction tid = null;
			try {
				tid = UndoableTransaction.start(trace, description, true);
			}
			catch (Throwable t) {
				tid.close();
				return ExceptionUtils.rethrow(t);
			}
			return new PermanentTransaction(trace, tid);
		}

		private final Trace trace;
		private final UndoableTransaction tid;

		public PermanentTransaction(Trace trace, UndoableTransaction tid) {
			this.trace = trace;
			this.tid = tid;
		}

		@Override
		public void close() {
			tid.close();
			trace.clearUndo();
		}
	}

	protected final AsyncLazyMap<TargetRegisterBank<?>, AllRequiredAccess> accessibilityByRegBank =
		new AsyncLazyMap<>(new HashMap<>(), this::fetchRegAccessibility) {
			public AllRequiredAccess remove(TargetRegisterBank<?> key) {
				AllRequiredAccess acc = super.remove(key);
				if (acc != null) {
					acc.removeChangeListener(listenerRegAccChanged);
				}
				return acc;
			}
		};
	protected final Map<TargetMemoryRegion<?>, TargetMemory<?>> byRegion = new HashMap<>();
	protected final AsyncLazyMap<TargetMemory<?>, AllRequiredAccess> accessibilityByMemory =
		new AsyncLazyMap<>(new HashMap<>(), this::fetchMemAccessibility) {
			public AllRequiredAccess remove(TargetMemory<?> key) {
				AllRequiredAccess acc = super.remove(key);
				if (acc != null) {
					acc.removeChangeListener(processMemory.memAccListeners.fire);
				}
				return acc;
			}
		};

	protected CompletableFuture<AllRequiredAccess> fetchRegAccessibility(
			TargetRegisterBank<?> bank) {
		return DebugModelConventions.trackAccessibility(bank).thenApply(acc -> {
			acc.addChangeListener(listenerRegAccChanged);
			return acc;
		});
	}

	protected CompletableFuture<AllRequiredAccess> fetchMemAccessibility(TargetMemory<?> mem) {
		return DebugModelConventions.trackAccessibility(mem).thenApply(acc -> {
			acc.addChangeListener(processMemory.memAccListeners.fire);
			return acc;
		});
	}

	/**
	 * Get accessible memory, as viewed in the trace
	 * 
	 * @param pred an additional predicate applied via "AND" with accessibility
	 * @return the computed set
	 */
	protected AddressSet getAccessibleMemory(Predicate<TargetMemory<?>> pred) {
		synchronized (accessibilityByMemory) {
			// TODO: Might accomplish by using listeners and tracking the accessible set
			AddressSet accessible = new AddressSet();
			for (Entry<TargetMemoryRegion<?>, TargetMemory<?>> ent : byRegion.entrySet()) {
				TargetMemory<?> mem = ent.getValue();
				if (!pred.test(mem)) {
					continue;
				}
				AllRequiredAccess acc = accessibilityByMemory.getCompletedMap().get(mem);
				if (acc == null || acc.getAllAccessibility() != TargetAccessibility.ACCESSIBLE) {
					continue;
				}
				accessible.add(memMapper.targetToTrace(ent.getKey().getRange()));
			}
			return accessible;
		}
	}

	protected class ComposedMemory {
		protected final ComposedMemory chain;

		protected final NavigableMap<Address, TargetMemoryRegion<?>> byMin = new TreeMap<>();

		@SuppressWarnings({ "rawtypes", "unchecked" })
		protected final ListenerSet<TriConsumer<TargetAccessibility, TargetAccessibility, Void>> memAccListeners =
			new ListenerSet(TriConsumer.class);

		public ComposedMemory() {
			this.chain = null;
		}

		public ComposedMemory(ComposedMemory chain) {
			this.chain = chain;
		}

		protected void addRegion(TargetMemoryRegion<?> region, TargetMemory<?> memory) {
			synchronized (accessibilityByMemory) {
				TargetMemory<?> old = byRegion.put(region, memory);
				assert old == null;
				byMin.put(region.getRange().getMinAddress(), region);
				accessibilityByMemory.get(memory).exceptionally(e -> {
					e = AsyncUtils.unwrapThrowable(e);
					Msg.error(this, "Could not track memory accessibility: " + e.getMessage());
					return null;
				});
			}
		}

		protected boolean removeRegion(TargetObject invalid) {
			if (!(invalid instanceof TargetMemoryRegion<?>)) {
				return false;
			}
			synchronized (accessibilityByMemory) {
				TargetMemoryRegion<?> invRegion = (TargetMemoryRegion<?>) invalid;
				TargetMemory<?> old = byRegion.remove(invRegion);
				assert old != null;
				byMin.remove(invRegion.getRange().getMinAddress());
				if (!old.isValid() || !byRegion.containsValue(old)) {
					accessibilityByMemory.remove(old);
				}
				return true;
			}
		}

		protected AllRequiredAccess findChainedMemoryAccess(TargetMemoryRegion<?> region) {
			synchronized (accessibilityByMemory) {
				TargetMemory<?> mem = byRegion.get(region);
				if (mem != null) {
					return accessibilityByMemory.getCompletedMap().get(mem);
				}
				return chain == null ? null : chain.findChainedMemoryAccess(region);
			}
		}

		protected Entry<Address, TargetMemoryRegion<?>> findChainedFloor(Address address) {
			synchronized (accessibilityByMemory) {
				Entry<Address, TargetMemoryRegion<?>> myFloor = byMin.floorEntry(address);
				Entry<Address, TargetMemoryRegion<?>> byChain =
					chain == null ? null : chain.findChainedFloor(address);
				if (byChain == null) {
					return myFloor;
				}
				if (myFloor == null) {
					return byChain;
				}
				int c = myFloor.getKey().compareTo(byChain.getKey());
				if (c < 0) {
					return byChain;
				}
				return myFloor;
			}
		}

		protected AddressRange align(Address address, int length) {
			AddressSpace space = address.getAddressSpace();
			long offset = address.getOffset();
			Address start = space.getAddress(offset & BLOCK_MASK);
			Address end = space.getAddress(((offset + length - 1) & BLOCK_MASK) + BLOCK_SIZE - 1);
			return new AddressRangeImpl(start, end);
		}

		protected AddressRange alignWithLimit(Address address, int length,
				TargetMemoryRegion<?> limit) {
			return align(address, length).intersect(limit.getRange());
		}

		protected AddressRange alignAndLimitToFloor(Address address, int length) {
			Entry<Address, TargetMemoryRegion<?>> floor = findChainedFloor(address);
			if (floor == null) {
				return null;
			}
			return alignWithLimit(address, length, floor.getValue());
		}

		protected AddressRange alignWithOptionalLimit(Address address, int length,
				TargetMemoryRegion<?> limit) {
			if (limit == null) {
				return alignAndLimitToFloor(address, length);
			}
			return alignWithLimit(address, length, limit);
		}

		protected CompletableFuture<byte[]> readMemory(Address address, int length) {
			synchronized (accessibilityByMemory) {
				Entry<Address, TargetMemoryRegion<?>> floor = findChainedFloor(address);
				if (floor == null) {
					throw new IllegalArgumentException(
						"address " + address + " is not in any known region");
				}
				Address max;
				try {
					max = address.addNoWrap(length - 1);
				}
				catch (AddressOverflowException e) {
					throw new IllegalArgumentException("read extends beyond the address space");
				}
				if (!floor.getValue().getRange().contains(max)) {
					throw new IllegalArgumentException("read extends beyond a single region");
				}
				TargetMemory<?> mem = byRegion.get(floor.getValue());
				if (mem != null) {
					return mem.readMemory(address, length);
				}
				return CompletableFuture.completedFuture(new byte[0]);
			}
		}

		protected CompletableFuture<Void> writeMemory(Address address, byte[] data) {
			synchronized (accessibilityByMemory) {
				Entry<Address, TargetMemoryRegion<?>> floor = findChainedFloor(address);
				if (floor == null) {
					throw new IllegalArgumentException(
						"address " + address + " is not in any known region");
				}
				Address max;
				try {
					max = address.addNoWrap(data.length - 1);
				}
				catch (AddressOverflowException e) {
					throw new IllegalArgumentException("read extends beyond the address space");
				}
				if (!floor.getValue().getRange().contains(max)) {
					throw new IllegalArgumentException("read extends beyond a single region");
				}
				TargetMemory<?> mem = byRegion.get(floor.getValue());
				if (mem != null) {
					return mem.writeMemory(address, data);
				}
				throw new IllegalArgumentException("read starts outside any address space");
			}
		}
	}

	protected static class ThreadMap {
		protected final NavigableSet<Integer> observedThreadPathLengths = new TreeSet<>();
		protected final Map<TargetThread<?>, ThreadRecorder> byTargetThread = new HashMap<>();
		protected final Map<TraceThread, ThreadRecorder> byTraceThread = new HashMap<>();

		public void put(ThreadRecorder rec) {
			observedThreadPathLengths.add(rec.targetThread.getPath().size());
			byTargetThread.put(rec.targetThread, rec);
			byTraceThread.put(rec.traceThread, rec);
		}

		public ThreadRecorder getForSuccessor(TargetObjectRef successor) {
			List<String> path = successor.getPath();
			for (int l : observedThreadPathLengths.descendingSet()) {
				if (l > path.size()) {
					continue;
				}
				path = List.copyOf(path.subList(0, l));
				TargetObjectRef maybeThread = successor.getModel().createRef(path);
				ThreadRecorder rec = byTargetThread.get(maybeThread);
				if (rec != null) {
					return rec;
				}
			}
			return null;
		}

		public ThreadRecorder get(TargetThread<?> thread) {
			return byTargetThread.get(thread);
		}

		public ThreadRecorder get(TargetObjectRef maybeThread) {
			return byTargetThread.get(maybeThread);
		}

		public ThreadRecorder get(TraceThread thread) {
			return byTraceThread.get(thread);
		}

		public void remove(ThreadRecorder rec) {
			ThreadRecorder rByTarget = byTargetThread.remove(rec.targetThread);
			ThreadRecorder rByTrace = byTraceThread.remove(rec.traceThread);
			assert rec == rByTarget;
			assert rec == rByTrace;
		}

		public Collection<ThreadRecorder> recorders() {
			return byTargetThread.values();
		}
	}

	protected static AddressSetView expandToBlocks(AddressSetView asv) {
		AddressSet result = new AddressSet();
		// Not terribly efficient, but this is one range most of the time
		for (AddressRange range : asv) {
			AddressSpace space = range.getAddressSpace();
			Address min = space.getAddress(range.getMinAddress().getOffset() & BLOCK_MASK);
			Address max = space.getAddress(range.getMaxAddress().getOffset() | ~BLOCK_MASK);
			result.add(new AddressRangeImpl(min, max));
		}
		return result;
	}

	protected static AddressRange range(Address min, Integer length) {
		if (length == null) {
			length = 1;
		}
		try {
			return new AddressRangeImpl(min, length);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	protected static String nameBreakpoint(TargetBreakpointLocation<?> bpt) {
		if (bpt instanceof TargetBreakpointSpec) {
			return bpt.getIndex();
		}
		return bpt.getSpecification().getIndex() + "." + bpt.getIndex();
	}

	protected static int getFrameLevel(TargetStackFrame<?> frame) {
		// TODO: A fair assumption? frames are elements with numeric base-10 indices
		return Integer.decode(frame.getIndex());
	}

	protected class ThreadRecorder {
		protected final TargetThread<?> targetThread;
		protected final TraceThread traceThread;
		protected DebuggerRegisterMapper regMapper;
		protected TargetRegister<?> pcReg;
		protected TargetRegister<?> spReg;
		protected Map<Integer, TargetRegisterBank<?>> regs = new HashMap<>();
		protected NavigableMap<Integer, TargetStackFrame<?>> stack =
			Collections.synchronizedNavigableMap(new TreeMap<>());
		protected final ComposedMemory threadMemory = new ComposedMemory(processMemory);
		protected TargetBreakpointContainer<?> threadBreakpointContainer;
		protected TargetExecutionState state = TargetExecutionState.ALIVE;

		protected ThreadRecorder(TargetThread<?> targetThread, TraceThread traceThread) {
			this.targetThread = targetThread;
			this.traceThread = traceThread;

			if (targetThread instanceof TargetExecutionStateful<?>) {
				TargetExecutionStateful<?> stateful = (TargetExecutionStateful<?>) targetThread;
				state = stateful.getExecutionState();
			}
		}

		protected synchronized CompletableFuture<Void> initRegMapper(
				TargetRegisterContainer<?> registers) {
			/**
			 * TODO: At the moment, this assumes the recorded thread has one register container, or
			 * at least that all register banks in the thread use the same register container
			 * (descriptors). If this becomes a problem, then we'll need to keep a separate register
			 * mapper per register container. This would likely also require some notion of multiple
			 * languages in the mapper (seems an unlikely design choice). NOTE: In cases where a
			 * single process may (at least appear to) execute multiple languages, the model should
			 * strive to present the registers of the physical machine, as they are most likely
			 * uniform across the process, not those being emulated in the moment. In cases where an
			 * abstract machine is involved, it is probably more fitting to present separate
			 * containers (likely provided by separate models) than to present both the physical and
			 * abstract machine in the same target.
			 * 
			 * <p>
			 * TODO: Should I formalize that only one register container is present in a recorded
			 * thread? This seems counter to the model's flexibility. Traces allow polyglot
			 * disassembly, but not polyglot register spaces.
			 */
			/*if (regMapper != null) {
				return AsyncUtils.NIL;
			}*/
			return regMappers.get(registers).thenAccept(rm -> {
				synchronized (this) {
					regMapper = rm;
					Language language = trace.getBaseLanguage();
					pcReg = regMapper.traceToTarget(language.getProgramCounter());
					spReg = regMapper.traceToTarget(trace.getBaseCompilerSpec().getStackPointer());
					extraRegs = new LinkedHashSet<>();
					for (String rn : mapper.getExtraRegNames()) {
						Register traceReg = language.getRegister(rn);
						if (traceReg == null) {
							Msg.error(this,
								"Mapper's extra register '" + rn + "' is not in the language!");
							continue;
						}
						TargetRegister<?> targetReg = regMapper.traceToTarget(traceReg);
						if (targetReg == null) {
							Msg.error(this,
								"Mapper's extra register '" + traceReg + "' is not mappable!");
							continue;
						}
						extraRegs.add(targetReg);
					}
				}
				listenerForRecord.retroOfferRegMapperDependents();
			}).exceptionally(ex -> {
				Msg.error(this, "Could not intialize register mapper", ex);
				return null;
			});
		}

		protected void regMapperAmended(DebuggerRegisterMapper rm, TargetRegister<?> reg,
				boolean removed) {
			boolean doUpdateRegs = false;
			String name = reg.getIndex();
			synchronized (this) {
				if (regMapper != rm) {
					return;
				}
				TargetRegister<?> newPcReg =
					regMapper.traceToTarget(trace.getBaseLanguage().getProgramCounter());
				if (pcReg != newPcReg) {
					pcReg = newPcReg;
					doUpdateRegs |= pcReg != null;
				}
				TargetRegister<?> newSpReg =
					regMapper.traceToTarget(trace.getBaseCompilerSpec().getStackPointer());
				if (spReg != newSpReg) {
					spReg = newSpReg;
					doUpdateRegs |= spReg != null;
				}
				if (mapper.getExtraRegNames().contains(name)) {
					if (removed) {
						extraRegs.remove(reg);
					}
					else {
						extraRegs.add(reg);
					}
					doUpdateRegs = true;
				}
			}
			if (removed) {
				return;
			}
			TargetRegisterBank<?> bank = regs.get(0);
			if (bank != null) {
				byte[] cachedVal = bank.getCachedRegisters().get(name);
				if (cachedVal != null) {
					recordRegisterValues(bank, Map.of(name, cachedVal));
				}
				if (doUpdateRegs) {
					updateRegsMem(null);
				}
			}
			// TODO: This may be too heavy-handed
			// listenerForRecord.retroOfferRegMapperDependents();
		}

		protected int getSuccessorFrameLevel(TargetObjectRef successor) {
			NavigableSet<Integer> observedPathLengths = new TreeSet<>();
			for (TargetStackFrame<?> frame : stack.values()) {
				observedPathLengths.add(frame.getPath().size());
			}
			List<String> path = successor.getPath();
			for (int l : observedPathLengths.descendingSet()) {
				if (l > path.size()) {
					continue;
				}
				List<String> sub = path.subList(0, l);
				if (!PathUtils.isIndex(sub)) {
					continue;
				}
				int index = Integer.decode(PathUtils.getIndex(sub));
				TargetStackFrame<?> frame = stack.get(index);
				if (frame == null || !Objects.equals(sub, frame.getPath())) {
					continue;
				}
				return index;
			}
			return 0;
		}

		CompletableFuture<Void> doFetchAndInitRegMapper(TargetRegisterBank<?> bank) {
			int frameLevel = getSuccessorFrameLevel(bank);
			TypedTargetObjectRef<? extends TargetRegisterContainer<?>> descsRef =
				bank.getDescriptions();
			if (descsRef == null) {
				Msg.error(this, "Cannot create mapper, yet: Descriptions is null.");
				return AsyncUtils.NIL;
			}
			return descsRef.fetch().thenCompose(descs -> {
				return initRegMapper(descs);
			}).thenAccept(__ -> {
				if (frameLevel == 0) {
					recordRegisterValues(bank, bank.getCachedRegisters());
					updateRegsMem(null);
				}
				listeners.fire.registerBankMapped(DefaultTraceRecorderSaved.this);
			}).exceptionally(ex -> {
				Msg.error(this, "Could not intialize register mapper", ex);
				return null;
			});
		}

		protected void offerRegisters(TargetRegisterBank<?> newRegs) {
			int frameLevel = getSuccessorFrameLevel(newRegs);
			if (regs.isEmpty()) {
				// TODO: Technically, each frame may need its own mapper....
				doFetchAndInitRegMapper(newRegs);
			}

			TargetRegisterBank<?> oldRegs = regs.put(frameLevel, newRegs);
			if (oldRegs == newRegs) {
				return;
			}

			synchronized (accessibilityByRegBank) {
				if (oldRegs != null) {
					accessibilityByRegBank.remove(oldRegs);
				}
				accessibilityByRegBank.get(newRegs).exceptionally(e -> {
					e = AsyncUtils.unwrapThrowable(e);
					Msg.error(this, "Could not track register accessibility: " + e.getMessage());
					return null;
				});
			}
		}

		protected void offerStackFrame(TargetStackFrame<?> frame) {
			stack.put(getFrameLevel(frame), frame);
			recordFrame(frame);
		}

		protected void offerThreadRegion(TargetMemoryRegion<?> region) {
			region.getMemory().fetch().thenCompose(mem -> {
				threadMemory.addRegion(region, mem);
				initMemMapper(mem);
				// TODO: Add region to trace memory manager (when allowed for threads)
				return updateRegsMem(region);
			}).exceptionally(ex -> {
				Msg.error(this, "Could not add thread memory region", ex);
				return null;
			});
		}

		protected void offerThreadBreakpointContainer(TargetBreakpointContainer<?> bc) {
			if (threadBreakpointContainer != null) {
				Msg.warn(this, "Thread already has a breakpoint container");
			}
			threadBreakpointContainer = bc;
		}

		/**
		 * Inform the recorder the given object is no longer valid
		 * 
		 * @param invalid the invalidated object
		 * @return true if this recorder should be invalidated, too
		 */
		protected synchronized boolean objectRemoved(TargetObject invalid) {
			if (checkThreadRemoved(invalid)) {
				return true;
			}
			if (checkRegistersRemoved(invalid)) {
				//return false;
				// Regs could also be a stack frame
			}
			if (checkStackFrameRemoved(invalid)) {
				return false;
			}
			if (threadMemory.removeRegion(invalid)) {
				return false;
			}
			Msg.trace(this, "Ignored removed object: " + invalid);
			return false;
		}

		protected boolean checkThreadRemoved(TargetObject invalid) {
			if (targetThread == invalid) {
				threadDestroyed();
				return true;
			}
			return false;
		}

		protected boolean checkRegistersRemoved(TargetObject invalid) {
			synchronized (accessibilityByRegBank) {
				if (regs.values().remove(invalid)) {
					accessibilityByRegBank.remove((TargetRegisterBank<?>) invalid);
					return true;
				}
				return false;
			}
		}

		protected boolean checkStackFrameRemoved(TargetObject invalid) {
			if (stack.values().remove(invalid)) {
				popStack();
				return true;
			}
			return false;
		}

		protected Address pcFromStack() {
			TargetStackFrame<?> frame = stack.get(0);
			if (frame == null) {
				return null;
			}
			return frame.getProgramCounter();
		}

		protected boolean checkReadCondition(Address traceAddress) {
			/**
			 * TODO: This heuristic doesn't really belong here, but I have to implement it here so
			 * that it doesn't "override" the listing's implementation. Once watches are
			 * implemented, we should be able to drop this garbage.
			 */
			TraceMemoryRegion region =
				memoryManager.getRegionContaining(snapshot.getKey(), traceAddress);
			if (region == null) {
				return false;
			}
			if (region.isWrite()) {
				return true;
			}
			Entry<TraceAddressSnapRange, TraceMemoryState> ent =
				memoryManager.getMostRecentStateEntry(snapshot.getKey(), traceAddress);
			if (ent == null) {
				return true;
			}
			if (ent.getValue() == TraceMemoryState.KNOWN) {
				return false;
			}
			return true;
		}

		protected CompletableFuture<?> readAlignedConditionally(String name, Address targetAddress,
				TargetMemoryRegion<?> limit) {
			if (targetAddress == null) {
				return AsyncUtils.NIL;
			}
			Address traceAddress = memMapper.targetToTrace(targetAddress);
			if (traceAddress == null) {
				return AsyncUtils.NIL;
			}
			if (!checkReadCondition(traceAddress)) {
				return AsyncUtils.NIL;
			}
			AddressRange targetRange = threadMemory.alignWithOptionalLimit(targetAddress, 1, limit);
			if (targetRange == null) {
				return AsyncUtils.NIL;
			}
			TimedMsg.info(this,
				"  Reading memory at " + name + " (" + targetAddress + " -> " + targetRange + ")");
			// NOTE: Recorder takes data via memoryUpdated callback
			// TODO: In that callback, sort out process memory from thread memory?
			return threadMemory
					.readMemory(targetRange.getMinAddress(), (int) targetRange.getLength())
					.exceptionally(ex -> {
						Msg.error(this, "Could not read memory at " + name, ex);
						return null;
					});
		}

		Address registerValueToTargetAddress(TargetRegister<?> reg, byte[] value) {
			/**
			 * TODO: This goes around the horn and back just to select a default address space. We
			 * should really just go directly to target address space.
			 */
			RegisterValue rv = regMapper.targetToTrace(reg, value);
			if (rv == null) {
				return null;
			}
			Address traceAddress = trace.getBaseLanguage()
					.getDefaultSpace()
					.getAddress(rv.getUnsignedValue().longValue());
			return memMapper.traceToTarget(traceAddress);
		}

		protected CompletableFuture<Void> updateRegsMem(TargetMemoryRegion<?> limit) {
			TargetRegisterBank<?> bank;
			TargetRegister<?> pc;
			TargetRegister<?> sp;
			Set<TargetRegister<?>> toRead = new LinkedHashSet<>();
			synchronized (DefaultTraceRecorderSaved.this) {
				if (regMapper == null) {
					return AsyncUtils.NIL;
				}
				bank = regs.get(0);
				pc = pcReg;
				sp = spReg;
				toRead.addAll(extraRegs);
				toRead.add(sp);
				toRead.add(pc);
			}
			if (bank == null || pc == null || sp == null) {
				return AsyncUtils.NIL;
			}
			TimedMsg.info(this, "Reading " + toRead + " of " + targetThread);
			return bank.readRegisters(toRead).thenCompose(vals -> {
				synchronized (DefaultTraceRecorderSaved.this) {
					if (memMapper == null) {
						return AsyncUtils.NIL;
					}
				}
				if (threadMemory == null) {
					return AsyncUtils.NIL;
				}
				AsyncFence fence = new AsyncFence();

				Address pcTargetAddr = pcFromStack();
				if (pcTargetAddr == null) {
					pcTargetAddr = registerValueToTargetAddress(pcReg, vals.get(pcReg.getIndex()));
				}
				fence.include(readAlignedConditionally("PC", pcTargetAddr, limit));

				Address spTargetAddr =
					registerValueToTargetAddress(spReg, vals.get(spReg.getIndex()));
				fence.include(readAlignedConditionally("SP", spTargetAddr, limit));

				return fence.ready();
			}).exceptionally(ex -> {
				if (LOG_STACK_TRACE) {
					Msg.error(this, "Could not read registers", ex);
				}
				else {
					Msg.error(this, "Could not read registers");
				}
				return null;
			});
		}

		public void stateChanged(final TargetExecutionState newState) {
			if (newState == TargetExecutionState.STOPPED) {
				updateRegsMem(null);
			}
			state = newState;
		}

		public void threadDestroyed() {
			String path = PathUtils.toString(targetThread.getPath());
			try (PermanentTransaction tid =
				PermanentTransaction.start(trace, path + " destroyed")) {
				// TODO: Should it be key - 1
				// Perhaps, since the thread should not exist
				// But it could imply earlier destruction than actually observed
				traceThread.setDestructionSnap(snapshot.getKey());
			}
			catch (DuplicateNameException e) {
				throw new AssertionError(e); // Should be shrinking
			}
		}

		public void recordRegisterValues(TargetRegisterBank<?> bank, Map<String, byte[]> updates) {
			synchronized (DefaultTraceRecorderSaved.this) {
				if (regMapper == null) {
					return;
				}
			}
			int frameLevel = getSuccessorFrameLevel(bank);
			TimedMsg.info(this, "Reg values changed: " + updates.keySet());
			try (PermanentTransaction tid = PermanentTransaction.start(trace,
				"Registers changed in " + PathUtils.toString(bank.getPath()))) {
				TraceMemoryRegisterSpace regSpace =
					memoryManager.getMemoryRegisterSpace(traceThread, frameLevel, true);
				for (Entry<String, byte[]> ent : updates.entrySet()) {
					RegisterValue rv = regMapper.targetToTrace(ent.getKey(), ent.getValue());
					if (rv == null) {
						continue; // mapper does not know this register....
					}
					regSpace.setValue(snapshot.getKey(), rv);
					if (rv.getRegister() == trace.getBaseLanguage().getProgramCounter() &&
						pcFromStack() == null) {
						Address pcTargetAddr = registerValueToTargetAddress(pcReg, ent.getValue());
						readAlignedConditionally("PC", pcTargetAddr, null); // NB: Reports errors
					}
					if (rv.getRegister() == trace.getBaseCompilerSpec().getStackPointer()) {
						Address spTargetAddr = registerValueToTargetAddress(spReg, ent.getValue());
						readAlignedConditionally("SP", spTargetAddr, null); // NB: Reports errors
					}
				}
			}
		}

		public void recordFrame(TargetStackFrame<?> frame) {
			recordFrame(frame, frame.getProgramCounter());
		}

		public void doRecordFrame(TraceStack traceStack, int frameLevel, Address pc) {
			TraceStackFrame traceFrame = traceStack.getFrame(frameLevel, true);
			traceFrame.setProgramCounter(pc);
		}

		public void recordFrame(TargetStackFrame<?> frame, Address pc) {
			synchronized (DefaultTraceRecorderSaved.this) {
				if (memMapper == null) {
					return;
				}
				Address tracePc = pc == null ? null : memMapper.targetToTrace(pc);
				try (PermanentTransaction tid =
					PermanentTransaction.start(trace, "Stack frame added")) {
					TraceStack traceStack =
						stackManager.getStack(traceThread, snapshot.getKey(), true);
					doRecordFrame(traceStack, getFrameLevel(frame), tracePc);
				}
			}
		}

		protected int stackDepth() {
			return stack.isEmpty() ? 0 : stack.lastKey() + 1;
		}

		public void recordStack() {
			synchronized (DefaultTraceRecorderSaved.this) {
				if (memMapper == null) {
					return;
				}
				try (PermanentTransaction tid =
					PermanentTransaction.start(trace, "Stack changed")) {
					TraceStack traceStack =
						stackManager.getStack(traceThread, snapshot.getKey(), true);
					traceStack.setDepth(stackDepth(), false);
					for (Map.Entry<Integer, TargetStackFrame<?>> ent : stack.entrySet()) {
						Address tracePc =
							memMapper.targetToTrace(ent.getValue().getProgramCounter());
						doRecordFrame(traceStack, ent.getKey(), tracePc);
					}
				}
			}
		}

		public void popStack() {
			synchronized (DefaultTraceRecorderSaved.this) {
				try (PermanentTransaction tid = PermanentTransaction.start(trace, "Stack popped")) {
					TraceStack traceStack =
						stackManager.getStack(traceThread, snapshot.getKey(), true);
					traceStack.setDepth(stackDepth(), false);
				}
			}
		}

		public void onThreadBreakpointContainers(
				Consumer<? super TargetBreakpointContainer<?>> action) {
			if (threadBreakpointContainer == null) {
				return;
			}
			action.accept(threadBreakpointContainer);
		}
	}

	protected class EffectiveBreakpointResolver {
		private final TargetBreakpointLocation<?> bpt;
		private TargetBreakpointSpec<?> spec;
		private boolean affectsProcess = false;
		private final Set<TraceThread> threadsAffected = new LinkedHashSet<>();

		public EffectiveBreakpointResolver(TargetBreakpointLocation<?> bpt) {
			this.bpt = bpt;
		}

		public CompletableFuture<Void> resolve() {
			AsyncFence fence = new AsyncFence();
			fence.include(bpt.getSpecification().fetch().thenAccept(s -> this.spec = s));

			for (TargetObjectRef ref : bpt.getAffects()) {
				if (ref.equals(target)) {
					affectsProcess = true;
				}
				else {
					fence.include(resolveThread(ref));
				}
			}
			return fence.ready();
		}

		// TODO: If affects is empty/null, also try to default to the containing process
		private CompletableFuture<Void> resolveThread(TargetObjectRef ref) {
			return DebugModelConventions.findThread(ref).thenAccept(thread -> {
				if (thread == null) {
					Msg.error(this,
						"Could not find process or thread from breakpoint-affected object: " + ref);
					return;
				}
				if (!ref.equals(thread)) {
					Msg.warn(this, "Effective breakpoint should apply to process or threads. Got " +
						ref + ". Resolved to " + thread);
					return;
				}
				if (!PathUtils.isAncestor(target.getPath(), thread.getPath())) {
					/**
					 * Perfectly normal if the breakpoint container is outside the process
					 * container. Don't record such in this trace, though.
					 */
					return;
				}
				ThreadRecorder rec = listenerForRecord.getOrCreateThreadRecorder(thread);
				synchronized (threadsAffected) {
					threadsAffected.add(rec.traceThread);
				}
			}).exceptionally(ex -> {
				Msg.error(this, "Error resolving thread from breakpoint-affected object: " + ref);
				return null;
			});
		}

		public void applyChecksAndConventions() {
			if (affectsProcess && !threadsAffected.isEmpty()) {
				Msg.warn(this, "Breakpoint affects process and individual threads?: " + bpt);
				threadsAffected.clear();
			}
			// Check ancestry for "affects"
			if (!affectsProcess && threadsAffected.isEmpty()) {
				if (PathUtils.isAncestor(target.getPath(), bpt.getPath())) {
					for (ThreadRecorder rec : threadMap.byTargetThread.values()) {
						if (PathUtils.isAncestor(rec.targetThread.getPath(), bpt.getPath())) {
							threadsAffected.add(rec.traceThread);
							break; // Only one thread could be its ancestor
						}
					}
					if (threadsAffected.isEmpty()) {
						affectsProcess = true;
					}
				}
			}
		}
	}

	public class ListenerForRecord extends SubTreeListenerAdapter implements
			TargetBreakpointSpecListener, TargetEventScopeListener, TargetExecutionStateListener,
			TargetFocusScopeListener, TargetRegisterBankListener, TargetMemoryListener {

		//protected final Map<String, TargetModule<?>> modulesByName = new HashMap<>();
		protected final Set<TargetBreakpointLocation<?>> breakpoints = new HashSet<>();

		@Override
		protected boolean checkDescend(TargetObjectRef ref) {
			// NOTE, cannot return false on match, since it could be a prefix of another
			if (HARDCODED_MATCHER.successorCouldMatch(ref.getPath())) {
				return true;
			}
			return false;
		}

		// TODO: Move this into conventions?
		protected CompletableFuture<TargetObject> findThreadOrProcess(TargetObject successor) {
			return new DebugModelConventions.AncestorTraversal<TargetObject>(successor) {
				@Override
				protected Result check(TargetObject obj) {
					if (obj.isRoot()) {
						return Result.FOUND;
					}
					if (obj instanceof TargetThread<?>) {
						return Result.FOUND;
					}
					if (obj instanceof TargetProcess<?>) {
						return Result.FOUND;
					}
					return Result.CONTINUE;
				}

				@Override
				protected TargetObject finish(TargetObject obj) {
					return obj;
				}
			}.start();
		}

		@Override
		protected void objectAdded(TargetObject added) {
			if (!valid) {
				return;
			}
			if (added instanceof TargetThread<?>) {
				getOrCreateThreadRecorder((TargetThread<?>) added);
			}
			if (added instanceof TargetStack<?>) {
				// Actually, this may not matter
			}
			// Do stack frame first, since bank would be it or child.
			// Need frames indexed first to determine level of bank
			if (added instanceof TargetStackFrame<?>) {
				ThreadRecorder rec = threadMap.getForSuccessor(added);
				if (rec == null) {
					Msg.error(this, "Frame without thread?: " + added);
				}
				else {
					rec.offerStackFrame((TargetStackFrame<?>) added);
				}
			}
			if (added instanceof TargetRegisterBank<?>) {
				ThreadRecorder rec = threadMap.getForSuccessor(added);
				if (rec == null) {
					Msg.error(this, "Bank without thread?: " + added);
				}
				else {
					rec.offerRegisters((TargetRegisterBank<?>) added);
				}
			}
			if (added instanceof TargetRegisterContainer<?>) {
				// These are picked up when a bank is added with these descriptions
			}
			if (added instanceof TargetRegister<?>) {
				TargetRegister<?> reg = (TargetRegister<?>) added;
				regMappers.get(reg.getContainer()).thenAccept(rm -> {
					rm.targetRegisterAdded(reg);
					for (ThreadRecorder rec : threadMap.byTargetThread.values()) {
						rec.regMapperAmended(rm, reg, false);
					}
				});
			}
			if (added instanceof TargetMemory<?>) {
				initMemMapper((TargetMemory<?>) added);
			}
			if (added instanceof TargetMemoryRegion<?>) {
				TargetMemoryRegion<?> region = (TargetMemoryRegion<?>) added;
				findThreadOrProcess(added).thenAccept(obj -> {
					if (obj == target) {
						offerProcessRegion(region);
						return;
					}
					if (obj instanceof TargetThread) {
						ThreadRecorder rec = getOrCreateThreadRecorder((TargetThread<?>) obj);
						rec.offerThreadRegion(region);
					}
				}).exceptionally(ex -> {
					Msg.error(this, "Error recording memory region", ex);
					return null;
				});
			}
			if (added instanceof TargetModule<?>) {
				TargetModule<?> module = (TargetModule<?>) added;
				offerProcessModule(module);
			}
			if (added instanceof TargetSection<?>) {
				TargetSection<?> section = (TargetSection<?>) added;
				section.getModule().fetch().thenAccept(module -> {
					offerProcessModuleSection(module, section);
					// I hope this should never be a per-thread thing
				}).exceptionally(ex -> {
					Msg.error(this, "Error recording module section", ex);
					return null;
				});
			}
			if (added instanceof TargetBreakpointContainer<?>) {
				TargetBreakpointContainer<?> breaks = (TargetBreakpointContainer<?>) added;
				findThreadOrProcess(added).thenAccept(obj -> {
					if (obj == target) {
						offerProcessBreakpointContainer(breaks);
						return;
					}
					if (obj.isRoot()) {
						return;
					}
					ThreadRecorder rec = getOrCreateThreadRecorder((TargetThread<?>) obj);
					rec.offerThreadBreakpointContainer(breaks);
				}).exceptionally(ex -> {
					Msg.error(this, "Error recording breakpoint container", ex);
					return null;
				});
			}
			if (added instanceof TargetBreakpointSpec<?>) {
				// I don't think this matters. UI for live recording only.
			}
			if (added instanceof TargetBreakpointLocation<?>) {
				TargetBreakpointLocation<?> bpt = (TargetBreakpointLocation<?>) added;
				breakpoints.add(bpt);
				offerEffectiveBreakpoint(bpt);
			}
		}

		@Override
		protected void objectRemoved(TargetObject removed) {
			if (!valid) {
				return;
			}
			if (target == removed) {
				stopRecording();
				return;
			}
			if (removed instanceof TargetRegisterContainer<?>) {
				regMappers.remove((TargetRegisterContainer<?>) removed);
			}
			if (removed instanceof TargetRegister<?>) {
				TargetRegister<?> reg = (TargetRegister<?>) removed;
				reg.getContainer().fetch().thenAccept(cont -> {
					DebuggerRegisterMapper rm = regMappers.getCompletedMap().get(cont);
					if (rm == null) {
						return;
					}
					rm.targetRegisterRemoved(reg);
					for (ThreadRecorder rec : threadMap.byTargetThread.values()) {
						rec.regMapperAmended(rm, reg, true);
					}
				});
			}
			if (removed instanceof TargetMemoryRegion<?>) {
				TargetMemoryRegion<?> region = (TargetMemoryRegion<?>) removed;
				if (processMemory.removeRegion(region)) {
					removeProcessRegion(region);
					return;
				}
				// Allow removal notice to fall through to thread recorders
			}
			if (removed instanceof TargetModule<?>) {
				TargetModule<?> module = (TargetModule<?>) removed;
				removeProcessModule(module);
				return;
			}
			if (removed instanceof TargetBreakpointLocation<?>) {
				TargetBreakpointLocation<?> bpt = (TargetBreakpointLocation<?>) removed;
				breakpoints.remove(bpt);
				removeEffectiveBreakpoint(bpt);
				return;
			}
			synchronized (threadMap) {
				for (Iterator<ThreadRecorder> it = threadMap.recorders().iterator(); it
						.hasNext();) {
					ThreadRecorder rec = it.next();
					if (rec.objectRemoved(removed)) {
						it.remove();
					}
				}
			}
		}

		protected boolean successor(TargetObjectRef ref) {
			return PathUtils.isAncestor(target.getPath(), ref.getPath());
		}

		protected boolean anyRef(Collection<Object> parameters) {
			for (Object p : parameters) {
				if (!(p instanceof TargetObjectRef)) {
					continue;
				}
				return true;
			}
			return false;
		}

		protected boolean anySuccessor(Collection<Object> parameters) {
			for (Object p : parameters) {
				if (!(p instanceof TargetObjectRef)) {
					continue;
				}
				TargetObjectRef ref = (TargetObjectRef) p;
				if (!successor(ref)) {
					continue;
				}
				return true;
			}
			return false;
		}

		protected boolean eventApplies(TargetObjectRef eventThread, TargetEventType type,
				List<Object> parameters) {
			if (type == TargetEventType.RUNNING) {
				return false;
				/**
				 * TODO: Perhaps some configuration for this later. It's kind of interesting to
				 * record the RUNNING event time, but it gets pedantic when these exist between
				 * steps.
				 */
			}
			if (eventThread != null) {
				return successor(eventThread);
			}
			if (anyRef(parameters)) {
				return anySuccessor(parameters);
			}
			return true; // Some session-wide event, I suppose
		}

		@Override
		public void event(TargetEventScope<?> object,
				TypedTargetObjectRef<? extends TargetThread<?>> eventThread, TargetEventType type,
				String description, List<Object> parameters) {
			if (!valid) {
				return;
			}
			TimedMsg.info(this, "Event: " + type + " thread=" + eventThread + " description=" +
				description + " params=" + parameters);
			// Just use this to step the snaps. Creation/destruction still handled in add/remove
			if (!eventApplies(eventThread, type, parameters)) {
				return;
			}
			ThreadRecorder rec = threadMap.get(eventThread);
			createSnapshot(description, rec == null ? null : rec.traceThread, null);

			if (type == TargetEventType.THREAD_CREATED) {
				if (rec == null) {
					return;
				}
				try (UndoableTransaction tid =
					UndoableTransaction.start(trace, "Adjust thread creation", true)) {
					rec.traceThread.setCreationSnap(snapshot.getKey());
				}
				catch (DuplicateNameException e) {
					throw new AssertionError(e); // Should be shrinking
				}
			}
			else if (type == TargetEventType.MODULE_LOADED) {
				Object p0 = parameters.get(0);
				if (!(p0 instanceof TargetObjectRef)) {
					return;
				}
				TargetObjectRef ref = (TargetObjectRef) p0;
				ref.fetch().thenAccept(obj -> {
					if (!(obj instanceof TargetModule<?>)) {
						return;
					}
					TargetModule<?> mod = (TargetModule<?>) obj;
					TraceModule traceModule = getTraceModule(mod);
					if (traceModule == null) {
						return;
					}
					try (UndoableTransaction tid =
						UndoableTransaction.start(trace, "Adjust module load", true)) {
						traceModule.setLoadedSnap(snapshot.getKey());
					}
					catch (DuplicateNameException e) {
						Msg.error(this, "Could not set module loaded snap", e);
					}
				});
			}
		}

		@Override
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			super.attributesChanged(parent, removed, added);
			if (!valid) {
				return;
			}
			// Dispatch attribute changes which don't have "built-in" events.
			if (parent instanceof TargetBreakpointLocation<?>) {
				if (added.containsKey(TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME)) {
					breakpointLengthChanged((TargetBreakpointLocation<?>) parent,
						(Integer) added.get(TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME));
				}
			}
			if (parent instanceof TargetStackFrame<?>) {
				if (added.containsKey(TargetStackFrame.PC_ATTRIBUTE_NAME)) {
					framePcUpdated((TargetStackFrame<?>) parent);
				}
			}
			if (parent instanceof TargetRegisterBank<?>) {
				if (added.containsKey(TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME)) {
					ThreadRecorder rec = threadMap.getForSuccessor(parent);
					if (rec != null) {
						rec.doFetchAndInitRegMapper((TargetRegisterBank<?>) parent);
					}
				}
			}
			// This should be fixed at construction.
			/*if (parent instanceof TargetModule<?>) {
				if (added.containsKey(TargetModule.BASE_ATTRIBUTE_NAME)) {
					moduleBaseUpdated((TargetModule<?>) parent,
						(Address) added.get(TargetModule.BASE_ATTRIBUTE_NAME));
				}
			}*/
		}

		@Override
		public void executionStateChanged(TargetExecutionStateful<?> stateful,
				TargetExecutionState state) {
			if (!valid) {
				return;
			}
			TimedMsg.info(this, "State " + state + " for " + stateful);
			findThreadOrProcess(stateful).thenAccept(threadOrProcess -> {
				if (threadOrProcess == target && state == TargetExecutionState.TERMINATED) {
					stopRecording();
					return;
				}
				ThreadRecorder rec = null;
				synchronized (threadMap) {
					if (threadOrProcess instanceof TargetThread) {
						rec = threadMap.get((TargetThread<?>) threadOrProcess);
					}
				}
				if (rec != null) {
					rec.stateChanged(state);
				}
				// Else we'll discover it and sync state later
			});
		}

		protected ThreadRecorder getOrCreateThreadRecorder(TargetThread<?> thread) {
			synchronized (threadMap) {
				ThreadRecorder rec = threadMap.get(thread);
				if (rec != null) {
					return rec;
				}
				TraceThread traceThread;
				String path = PathUtils.toString(thread.getPath());
				try (PermanentTransaction tid =
					PermanentTransaction.start(trace, path + " created")) {
					// Note, if THREAD_CREATED is emitted, it will adjust the creation snap
					traceThread = threadManager.createThread(path, thread.getShortDisplay(),
						snapshot.getKey());
				}
				catch (DuplicateNameException e) {
					throw new AssertionError(e); // Should be a new thread in model
				}
				rec = new ThreadRecorder(thread, traceThread);
				threadMap.put(rec);
				return rec;
			}
		}

		@Override
		public void registersUpdated(TargetRegisterBank<?> bank, Map<String, byte[]> updates) {
			if (!valid) {
				return;
			}
			ThreadRecorder rec = threadMap.getForSuccessor(bank);
			if (rec == null) {
				return;
			}
			rec.recordRegisterValues(bank, updates);
		}

		@Override
		public void memoryUpdated(TargetMemory<?> memory, Address address, byte[] data) {
			if (!valid) {
				return;
			}
			synchronized (DefaultTraceRecorderSaved.this) {
				if (memMapper == null) {
					Msg.warn(this, "Received memory write before a region has been added");
					return;
				}
			}
			Address traceAddr = memMapper.targetToTrace(address);
			long snap = snapshot.getKey();
			TimedMsg.info(this, "Memory updated: " + address + " (" + data.length + ")");
			try (PermanentTransaction tid = PermanentTransaction.start(trace, "Memory observed")) {
				ByteBuffer newBytes = ByteBuffer.wrap(data);
				memoryManager.putBytes(snap, traceAddr, newBytes);
			}
		}

		@Override
		public void memoryReadError(TargetMemory<?> memory, AddressRange range,
				DebuggerMemoryAccessException e) {
			if (!valid) {
				return;
			}
			Msg.error(this, "Error reading range " + range, e);
			Address traceMin = memMapper.targetToTrace(range.getMinAddress());
			try (PermanentTransaction tid =
				PermanentTransaction.start(trace, "Memory read error")) {
				memoryManager.setState(snapshot.getKey(), traceMin, TraceMemoryState.ERROR);
				// TODO: Bookmark to describe error?
			}
		}

		@Override
		public void breakpointToggled(TargetBreakpointSpec<?> spec, boolean enabled) {
			if (!valid) {
				return;
			}
			spec.getLocations().thenAccept(bpts -> {
				try (PermanentTransaction tid =
					PermanentTransaction.start(trace, "Breakpoint toggled")) {
					for (TargetBreakpointLocation<?> eb : bpts) {
						TraceBreakpoint traceBpt = getTraceBreakpoint(eb);
						if (traceBpt == null) {
							String path = PathUtils.toString(eb.getPath());
							Msg.warn(this, "Cannot find toggled trace breakpoint for " + path);
							continue;
						}
						// Verify attributes match? Eh. If they don't, someone has fiddled with it.
						traceBpt.splitWithEnabled(snapshot.getKey(), enabled);
					}
				}
			}).exceptionally(ex -> {
				Msg.error(this, "Error recording toggled breakpoint spec: " + spec, ex);
				return null;
			});
		}

		protected void breakpointLengthChanged(TargetBreakpointLocation<?> bpt, int length) {
			Address traceAddr = memMapper.targetToTrace(bpt.getAddress());
			String path = PathUtils.toString(bpt.getPath());
			for (TraceBreakpoint traceBpt : breakpointManager.getBreakpointsByPath(path)) {
				if (traceBpt.getLength() == length) {
					continue; // Nothing to change
				}
				// TODO: Verify all other attributes match?
				// TODO: Should this be allowed to happen?
				try (PermanentTransaction tid =
					PermanentTransaction.start(trace, "Breakpoint length changed")) {
					long snap = snapshot.getKey();
					if (traceBpt.getPlacedSnap() == snap) {
						traceBpt.delete();
					}
					else {
						traceBpt.setClearedSnap(snap - 1);
					}
					breakpointManager.placeBreakpoint(path, snap, range(traceAddr, length),
						traceBpt.getThreads(), traceBpt.getKinds(), traceBpt.isEnabled(),
						traceBpt.getComment());
				}
				catch (DuplicateNameException e) {
					throw new AssertionError(e); // Split, and length matters not
				}
			}
		}

		protected void framePcUpdated(TargetStackFrame<?> frame) {
			ThreadRecorder rec = threadMap.getForSuccessor(frame);
			// Yes, entire stack, otherwise, the stack seems to be just one deep.
			rec.recordStack();
		}

		protected void stackUpdated(TargetStack<?> stack) {
			ThreadRecorder rec = threadMap.getForSuccessor(stack);
			rec.recordStack();
		}

		@Override
		public void focusChanged(TargetFocusScope<?> object, TargetObjectRef focused) {
			if (!valid) {
				return;
			}
			if (PathUtils.isAncestor(target.getPath(), focused.getPath())) {
				curFocus = focused;
			}
		}

		protected void retroOfferRegMapperDependents() {
			List<ThreadRecorder> copy;
			synchronized (objects) {
				copy = List.copyOf(threadMap.byTargetThread.values());
			}
			for (ThreadRecorder rec : copy) {
				TargetRegisterBank<?> bank = rec.regs.get(0);
				if (bank != null) {
					rec.recordRegisterValues(bank, bank.getCachedRegisters());
					rec.updateRegsMem(null);
				}
			}
		}

		protected void retroOfferMemMapperDependents() {
			List<TargetObject> copy;
			synchronized (objects) {
				copy = List.copyOf(objects.values());
			}
			synchronized (DefaultTraceRecorderSaved.this) {
				for (TargetObject obj : copy) {
					if (obj instanceof TargetModule<?>) {
						offerProcessModule((TargetModule<?>) obj);
					}
					if (obj instanceof TargetSection<?>) {
						TargetSection<?> section = (TargetSection<?>) obj;
						section.getModule().fetch().thenAccept(module -> {
							offerProcessModuleSection(module, section);
						});
					}
					if (obj instanceof TargetBreakpointLocation<?>) {
						offerEffectiveBreakpoint((TargetBreakpointLocation<?>) obj);
					}
					if (obj instanceof TargetStack<?>) {
						stackUpdated((TargetStack<?>) obj);
					}
				}
			}
		}

		public TargetMemoryRegion<?> getTargetMemoryRegion(TraceMemoryRegion region) {
			synchronized (objects) {
				return (TargetMemoryRegion<?>) objects.get(PathUtils.parse(region.getPath()));
			}
		}

		public TargetModule<?> getTargetModule(TraceModule module) {
			synchronized (objects) {
				return (TargetModule<?>) objects.get(PathUtils.parse(module.getPath()));
			}
		}

		public TargetSection<?> getTargetSection(TraceSection section) {
			synchronized (objects) {
				return (TargetSection<?>) objects.get(PathUtils.parse(section.getPath()));
			}
		}

		public TargetBreakpointLocation<?> getTargetBreakpoint(TraceBreakpoint bpt) {
			synchronized (objects) {
				return (TargetBreakpointLocation<?>) objects.get(PathUtils.parse(bpt.getPath()));
			}
		}

		public List<TargetBreakpointLocation<?>> collectBreakpoints(TargetThread<?> thread) {
			synchronized (objects) {
				return breakpoints.stream().filter(bpt -> {
					TargetObjectRefList<?> affects = bpt.getAffects();
					// N.B. in case thread is null (process), affects.contains(thread) is always false
					return affects.isEmpty() || affects.contains(thread) ||
						affects.contains(target);
				}).collect(Collectors.toList());
			}
		}

		protected void onProcessBreakpointContainers(
				Consumer<? super TargetBreakpointContainer<?>> action) {
			synchronized (objects) {
				if (processBreakpointContainer == null) {
					for (TargetThread<?> thread : threadsView) {
						onThreadBreakpointContainers(thread, action);
					}
				}
				else {
					action.accept(processBreakpointContainer);
				}
			}
		}

		protected void onThreadBreakpointContainers(TargetThread<?> thread,
				Consumer<? super TargetBreakpointContainer<?>> action) {
			synchronized (objects) {
				getOrCreateThreadRecorder(thread).onThreadBreakpointContainers(action);
			}
		}

		protected void onBreakpointContainers(TargetThread<?> thread,
				Consumer<? super TargetBreakpointContainer<?>> action) {
			if (thread == null) {
				onProcessBreakpointContainers(action);
			}
			else {
				onThreadBreakpointContainers(thread, action);
			}
		}
	}

	protected final DebuggerModelServicePlugin plugin;
	protected final PluginTool tool;
	protected final Trace trace;
	protected final TargetObject target;
	protected final ComposedMemory processMemory = new ComposedMemory();
	protected TargetBreakpointContainer<?> processBreakpointContainer;

	protected final TraceBreakpointManager breakpointManager;
	protected final TraceCodeManager codeManager;
	protected final TraceBasedDataTypeManager dataTypeManager;
	protected final TraceEquateManager equateManager;
	protected final TraceMemoryManager memoryManager;
	protected final TraceModuleManager moduleManager;
	protected final TraceStackManager stackManager;
	protected final TraceSymbolManager symbolManager;
	protected final TraceThreadManager threadManager;
	protected final TraceTimeManager timeManager;

	protected final AbstractDebuggerTargetTraceMapper mapper;
	protected DebuggerMemoryMapper memMapper;
	protected AsyncLazyMap<TypedTargetObjectRef<? extends TargetRegisterContainer<?>>, DebuggerRegisterMapper> regMappers;
	protected final TargetDataTypeConverter typeConverter;
	protected Collection<TargetRegister<?>> extraRegs;
	// TODO: Support automatic recording of user-specified extra registers...
	// NOTE: Probably via watches, once we have those
	// TODO: Probably move all the auto-reads into watches

	protected final ListenerSet<TraceRecorderListener> listeners =
		new ListenerSet<>(TraceRecorderListener.class);
	protected final TriConsumer<TargetAccessibility, TargetAccessibility, Void> listenerRegAccChanged =
		this::registerAccessibilityChanged;
	protected final TriConsumer<TargetAccessibility, TargetAccessibility, Void> listenerProcMemAccChanged =
		this::processMemoryAccessibilityChanged;

	private final ListenerForRecord listenerForRecord;

	protected final ThreadMap threadMap = new ThreadMap();
	protected final Set<TargetThread<?>> threadsView =
		Collections.unmodifiableSet(threadMap.byTargetThread.keySet());
	protected final BiMap<TargetBreakpointLocation<?>, TraceBreakpoint> processBreakpointsMap =
		HashBiMap.create();

	protected final AsyncLazyValue<Void> lazyInit = new AsyncLazyValue<>(this::doInit);

	protected TraceSnapshot snapshot = null;
	private boolean valid = true;

	protected TargetFocusScope<?> focusScope;
	protected TargetObjectRef curFocus;

	public DefaultTraceRecorderSaved(DebuggerModelServicePlugin plugin, Trace trace,
			TargetObject target, AbstractDebuggerTargetTraceMapper mapper) {
		this.plugin = plugin;
		this.tool = plugin.getTool();
		this.trace = trace;
		this.target = target;

		this.breakpointManager = trace.getBreakpointManager();
		this.codeManager = trace.getCodeManager();
		this.dataTypeManager = trace.getDataTypeManager();
		this.equateManager = trace.getEquateManager();
		this.memoryManager = trace.getMemoryManager();
		this.moduleManager = trace.getModuleManager();
		this.stackManager = trace.getStackManager();
		this.symbolManager = trace.getSymbolManager();
		this.threadManager = trace.getThreadManager();
		this.timeManager = trace.getTimeManager();

		this.mapper = mapper;
		this.regMappers = new AsyncLazyMap<>(new HashMap<>(),
			ref -> ref.fetch().thenCompose(mapper::offerRegisters));
		this.typeConverter = new TargetDataTypeConverter(trace.getDataTypeManager());

		this.listenerForRecord = new ListenerForRecord();

		processMemory.memAccListeners.add(listenerProcMemAccChanged);

		trace.addConsumer(this);
	}

	protected void registerAccessibilityChanged(TargetAccessibility old, TargetAccessibility acc,
			Void __) {
		listeners.fire.registerAccessibilityChanged(this);
	}

	protected void processMemoryAccessibilityChanged(TargetAccessibility old,
			TargetAccessibility acc, Void __) {
		listeners.fire.processMemoryAccessibilityChanged(this);
	}

	@Override
	public CompletableFuture<Void> init() {
		return lazyInit.request();
	}

	protected CompletableFuture<Void> doInit() {
		createSnapshot("Started recording " + PathUtils.toString(target.getPath()) + " in " +
			target.getModel(), null, null);
		AsyncFence fence = new AsyncFence();
		CompletableFuture<? extends TargetBreakpointContainer<?>> futureBreaks =
			DebugModelConventions.findSuitable(TargetBreakpointContainer.tclass, target);
		fence.include(futureBreaks.thenAccept(breaks -> {
			if (breaks != null && !PathUtils.isAncestor(target.getPath(), breaks.getPath())) {
				offerProcessBreakpointContainer(breaks); // instead of objectAdded
				listenerForRecord.addListenerAndConsiderSuccessors(breaks);
			}
		}).exceptionally(e -> {
			Msg.error(this, "Could not search for breakpoint container", e);
			return null;
		}));

		CompletableFuture<? extends TargetEventScope<?>> futureEvents =
			DebugModelConventions.findSuitable(TargetEventScope.tclass, target);
		fence.include(futureEvents.thenAccept(events -> {
			if (events != null && !PathUtils.isAncestor(target.getPath(), events.getPath())) {
				// Don't descend. Scope may be the entire session.
				listenerForRecord.addListener(events);
			}
		}).exceptionally(e -> {
			Msg.warn(this, "Could not search for event scope", e);
			return null;
		}));

		CompletableFuture<? extends TargetFocusScope<?>> futureFocus =
			DebugModelConventions.findSuitable(TargetFocusScope.tclass, target);
		fence.include(futureFocus.thenAccept(focus -> {
			if (focus != null && !PathUtils.isAncestor(target.getPath(), focus.getPath())) {
				// Don't descend. Scope may be the entire session.
				offerFocusScope(focus);
				listenerForRecord.addListener(focus);
			}
		}).exceptionally(e -> {
			Msg.error(this, "Could not search for focus scope", e);
			return null;
		}));
		return fence.ready().thenAccept(__ -> {
			listenerForRecord.objectAdded(target); // TODO: This seems wrong
			listenerForRecord.addListenerAndConsiderSuccessors(target);
		});
	}

	protected synchronized void doAdvanceSnap(String description, TraceThread eventThread) {
		snapshot = timeManager.createSnapshot(description);
		snapshot.setEventThread(eventThread);
	}

	@Override
	public TraceSnapshot forceSnapshot() {
		createSnapshot("User-forced snapshot", null, null);
		return snapshot;
	}

	protected void createSnapshot(String description, TraceThread eventThread,
			PermanentTransaction tid) {
		if (tid != null) {
			doAdvanceSnap(description, eventThread);
			listeners.fire.snapAdvanced(this, snapshot.getKey());
			return;
		}
		try (PermanentTransaction tid2 = PermanentTransaction.start(trace, description)) {
			doAdvanceSnap(description, eventThread);
		}
		listeners.fire.snapAdvanced(this, snapshot.getKey());
	}

	// TODO: This could probably be discovered by the offer and passed in at construction
	protected synchronized CompletableFuture<Void> initMemMapper(TargetMemory<?> memory) {
		/**
		 * TODO: At the moment, there's no real dependency on the memory. When there is, see that
		 * additional memories can be incorporated into the mapper, and stale ones removed.
		 * Alternatively, formalize that there is no possible dependency on memory.
		 */
		if (memMapper != null) {
			return AsyncUtils.NIL;
		}
		return mapper.offerMemory(memory).thenAccept(mm -> {
			synchronized (this) {
				memMapper = mm;
			}
			listenerForRecord.retroOfferMemMapperDependents();
		}).exceptionally(ex -> {
			Msg.error(this, "Could not intialize memory mapper", ex);
			return null;
		});
	}

	protected Collection<TraceMemoryFlag> getTraceFlags(TargetMemoryRegion<?> region) {
		Collection<TraceMemoryFlag> flags = new HashSet<>();
		if (region.isReadable()) {
			flags.add(TraceMemoryFlag.READ);
		}
		if (region.isWritable()) {
			flags.add(TraceMemoryFlag.WRITE);
		}
		if (region.isExecutable()) {
			flags.add(TraceMemoryFlag.EXECUTE);
		}
		// TODO: Volatile? Can any debugger report that?
		return flags;
	}

	protected void offerProcessRegion(TargetMemoryRegion<?> region) {
		region.getMemory().fetch().thenCompose(mem -> {
			processMemory.addRegion(region, mem);
			initMemMapper(mem);
			synchronized (this) {
				try (PermanentTransaction tid =
					PermanentTransaction.start(trace, "Memory region added")) {
					String path = PathUtils.toString(region.getPath());
					TraceMemoryRegion traceRegion =
						memoryManager.getLiveRegionByPath(snapshot.getKey(), path);
					if (traceRegion != null) {
						Msg.warn(this, "Region " + path + " already recorded");
						return AsyncUtils.NIL;
					}
					traceRegion = memoryManager.addRegion(path, Range.atLeast(snapshot.getKey()),
						memMapper.targetToTrace(region.getRange()), getTraceFlags(region));
					traceRegion.setName(region.getName());
				}
				catch (TraceOverlappedRegionException e) {
					Msg.error(this, "Failed to create region due to overlap", e);
				}
				catch (DuplicateNameException e) {
					throw new AssertionError(e); // Just checked for existing
				}
			}
			return updateAllThreadsRegsMem(region);
		}).exceptionally(ex -> {
			Msg.error(this, "Could not add process memory region", ex);
			return null;
		});
	}

	protected synchronized void removeProcessRegion(TargetMemoryRegion<?> region) {
		// Already removed from processMemory. That's how we knew to go here.
		try (PermanentTransaction tid =
			PermanentTransaction.start(trace, "Memory region removed")) {
			String path = PathUtils.toString(region.getPath());
			long snap = snapshot.getKey();
			TraceMemoryRegion traceRegion = memoryManager.getLiveRegionByPath(snap, path);
			if (traceRegion == null) {
				Msg.warn(this, "Could not find region " + path + " in trace to remove");
				return;
			}
			traceRegion.setDestructionSnap(snap - 1);
		}
		catch (DuplicateNameException | TraceOverlappedRegionException e) {
			throw new AssertionError(e); // Region is shrinking in time
		}
	}

	protected void recordBreakpoint(TargetBreakpointSpec<?> spec, TargetBreakpointLocation<?> bpt,
			Set<TraceThread> traceThreads) {
		synchronized (this) {
			if (memMapper == null) {
				throw new IllegalStateException(
					"No memory mapper! Have not recorded a region, yet.");
			}
		}
		String path = PathUtils.toString(bpt.getPath());
		String name = nameBreakpoint(bpt);
		Address traceAddr = memMapper.targetToTrace(bpt.getAddress());
		AddressRange traceRange = range(traceAddr, bpt.getLength());
		try (PermanentTransaction tid = PermanentTransaction.start(trace, "Breakpoint placed")) {
			boolean enabled = spec.isEnabled();
			Set<TraceBreakpointKind> traceKinds =
				TraceRecorder.targetToTraceBreakpointKinds(spec.getKinds());
			TraceBreakpoint traceBpt = breakpointManager.placeBreakpoint(path, snapshot.getKey(),
				traceRange, traceThreads, traceKinds, enabled, spec.getExpression());
			traceBpt.setName(name);
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e); // Should be new to model, or already cleared
		}
	}

	protected void offerProcessBreakpointContainer(TargetBreakpointContainer<?> bc) {
		if (processBreakpointContainer != null) {
			Msg.warn(this, "Already have a breakpoint container for this process");
		}
		processBreakpointContainer = bc;
	}

	protected void offerFocusScope(TargetFocusScope<?> scope) {
		if (this.focusScope != null) {
			Msg.warn(this, "Already have a focus scope: " + this.focusScope);
		}
		this.focusScope = scope;
	}

	protected synchronized TraceModule offerProcessModule(TargetModule<?> module) {
		if (memMapper == null) {
			return null;
		}

		String path = PathUtils.toString(module.getPath());
		TraceModule traceModule = moduleManager.getLoadedModuleByPath(snapshot.getKey(), path);
		if (traceModule != null) {
			return traceModule;
		}
		try (PermanentTransaction tid =
			PermanentTransaction.start(trace, "Module " + path + " loaded")) {
			AddressRange targetRange = module.getRange();
			AddressRange traceRange =
				targetRange == null ? null : memMapper.targetToTrace(targetRange);
			traceModule = moduleManager.addLoadedModule(path, module.getModuleName(), traceRange,
				snapshot.getKey());
			return traceModule;
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e); // We checked for existing by path
		}
	}

	protected synchronized TraceSection offerProcessModuleSection(TargetModule<?> module,
			TargetSection<?> section) {
		if (memMapper == null) {
			return null;
		}
		String path = PathUtils.toString(section.getPath());
		TraceModule traceModule = offerProcessModule(module);
		TraceSection traceSection = moduleManager.getLoadedSectionByPath(snapshot.getKey(), path);
		if (traceSection != null) {
			Msg.warn(this, path + " already recorded");
			return traceSection;
		}
		try (PermanentTransaction tid =
			PermanentTransaction.start(trace, "Section " + path + " added")) {
			AddressRange targetRange = section.getRange();
			AddressRange traceRange = memMapper.targetToTrace(targetRange);
			traceSection = traceModule.addSection(path, section.getIndex(), traceRange);
			return traceSection;
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e); // We checked for existing by name
		}
	}

	protected synchronized void removeProcessModule(TargetModule<?> module) {
		String path = PathUtils.toString(module.getPath());
		long snap = snapshot.getKey();
		TraceThread eventThread = snapshot.getEventThread();
		TraceModule traceModule = moduleManager.getLoadedModuleByPath(snap, path);
		if (traceModule == null) {
			Msg.warn(this, "unloaded " + path + " is not in the trace");
			return;
		}
		try (PermanentTransaction tid =
			PermanentTransaction.start(trace, "Module " + path + " unloaded")) {
			if (traceModule.getLoadedSnap() == snap) {
				Msg.warn(this, "Observed module unload in the same snap as its load");
				createSnapshot("WARN: Module removed", eventThread, tid);
				snap = snapshot.getKey();
			}
			traceModule.setUnloadedSnap(snap - 1);
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e); // Module lifespan should be shrinking
		}
	}

	// NB: No removeProcessModuleSection, because sections should be immutable
	// They are removed when the module is removed

	protected void offerEffectiveBreakpoint(TargetBreakpointLocation<?> bpt) {
		synchronized (this) {
			if (memMapper == null) {
				return;
			}
		}
		EffectiveBreakpointResolver resolver = new EffectiveBreakpointResolver(bpt);
		resolver.resolve().thenAccept(__ -> {
			if (resolver.affectsProcess || !resolver.threadsAffected.isEmpty()) {
				recordBreakpoint(resolver.spec, bpt, resolver.threadsAffected);
			}
		}).exceptionally(ex -> {
			Msg.error(this, "Could record target breakpoint: " + bpt, ex);
			return null;
		});
	}

	protected void removeEffectiveBreakpoint(TargetBreakpointLocation<?> bpt) {
		String path = PathUtils.toString(bpt.getPath());
		long snap = snapshot.getKey();
		try (PermanentTransaction tid = PermanentTransaction.start(trace, "Breakpoint deleted")) {
			for (TraceBreakpoint traceBpt : breakpointManager.getBreakpointsByPath(path)) {
				if (traceBpt.getPlacedSnap() > snap) {
					Msg.error(this,
						"Tracked, now removed breakpoint was placed in the future? " + bpt);
				}
				else if (traceBpt.getPlacedSnap() == snap) {
					// TODO: I forget if this is allowed for DBTrace iteration
					traceBpt.delete();
				}
				else {
					traceBpt.setClearedSnap(snap - 1);
				}
			}
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e); // Lifespan in shrinking
		}
	}

	protected CompletableFuture<Void> updateAllThreadsRegsMem(TargetMemoryRegion<?> limit) {
		AsyncFence fence = new AsyncFence();
		for (ThreadRecorder rec : threadMap.recorders()) {
			fence.include(rec.updateRegsMem(limit));
		}
		return fence.ready();
	}

	@Override
	public TargetObject getTarget() {
		return target;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public long getSnap() {
		return snapshot.getKey();
	}

	@Override
	public boolean isRecording() {
		return valid;
	}

	@Override
	public void stopRecording() {
		invalidate();
		listeners.fire.recordingStopped(this);
	}

	@Override
	public void addListener(TraceRecorderListener l) {
		listeners.add(l);
	}

	@Override
	public void removeListener(TraceRecorderListener l) {
		listeners.remove(l);
	}

	@Override
	public boolean isViewAtPresent(TraceProgramView view) {
		if (!valid) {
			return false;
		}
		if (!Objects.equals(trace, view.getTrace())) {
			return false;
		}
		if (snapshot.getKey() != view.getSnap()) {
			return false;
		}
		return true;
	}

	@Override
	public TargetBreakpointLocation<?> getTargetBreakpoint(TraceBreakpoint bpt) {
		return listenerForRecord.getTargetBreakpoint(bpt);
	}

	@Override
	public TraceBreakpoint getTraceBreakpoint(TargetBreakpointLocation<?> bpt) {
		String path = PathUtils.toString(bpt.getPath());
		return breakpointManager.getPlacedBreakpointByPath(snapshot.getKey(), path);
	}

	@Override
	public List<TargetBreakpointContainer<?>> collectBreakpointContainers(TargetThread<?> thread) {
		List<TargetBreakpointContainer<?>> result = new ArrayList<>();
		listenerForRecord.onBreakpointContainers(thread, result::add);
		return result;
	}

	@Override
	public List<TargetBreakpointLocation<?>> collectBreakpoints(TargetThread<?> thread) {
		return listenerForRecord.collectBreakpoints(thread);
	}

	@Override
	public Set<TraceBreakpointKind> getSupportedBreakpointKinds() {
		Set<TargetBreakpointKind> tKinds = new HashSet<>();
		listenerForRecord.onBreakpointContainers(null, cont -> {
			tKinds.addAll(cont.getSupportedBreakpointKinds());
		});
		return TraceRecorder.targetToTraceBreakpointKinds(tKinds);
	}

	@Override
	public TargetMemoryRegion<?> getTargetMemoryRegion(TraceMemoryRegion region) {
		return listenerForRecord.getTargetMemoryRegion(region);
	}

	@Override
	public TraceMemoryRegion getTraceMemoryRegion(TargetMemoryRegion<?> region) {
		String path = PathUtils.toString(region.getPath());
		return memoryManager.getLiveRegionByPath(snapshot.getKey(), path);
	}

	@Override
	public TargetModule<?> getTargetModule(TraceModule module) {
		return listenerForRecord.getTargetModule(module);
	}

	@Override
	public TraceModule getTraceModule(TargetModule<?> module) {
		String path = PathUtils.toString(module.getPath());
		return moduleManager.getLoadedModuleByPath(snapshot.getKey(), path);
	}

	@Override
	public TargetSection<?> getTargetSection(TraceSection section) {
		return listenerForRecord.getTargetSection(section);
	}

	@Override
	public TraceSection getTraceSection(TargetSection<?> section) {
		String path = PathUtils.toString(section.getPath());
		return moduleManager.getLoadedSectionByPath(snapshot.getKey(), path);
	}

	@Override
	public TargetThread<?> getTargetThread(TraceThread thread) {
		ThreadRecorder rec = threadMap.get(thread);
		return rec == null ? null : rec.targetThread;
	}

	@Override
	public TargetExecutionState getTargetThreadState(TargetThread<?> thread) {
		ThreadRecorder rec = threadMap.get(thread);
		return rec == null ? null : rec.state;
	}

	@Override
	public TargetExecutionState getTargetThreadState(TraceThread thread) {
		ThreadRecorder rec = threadMap.get(thread);
		return rec == null ? null : rec.state;
	}

	@Override
	public boolean isRegisterBankAccessible(TargetRegisterBank<?> bank) {
		if (bank == null) {
			return false;
		}
		synchronized (accessibilityByRegBank) {
			KeyedFuture<?, AllRequiredAccess> future = accessibilityByRegBank.get(bank);
			if (future == null) {
				return false;
			}
			AllRequiredAccess acc = future.getNow(null);
			if (acc == null) {
				return false;
			}
			return acc.get() == TargetAccessibility.ACCESSIBLE;
		}
	}

	@Override
	public boolean isRegisterBankAccessible(TraceThread thread, int frameLevel) {
		return isRegisterBankAccessible(getTargetRegisterBank(thread, frameLevel));
	}

	@Override
	public TargetRegisterBank<?> getTargetRegisterBank(TraceThread thread, int frameLevel) {
		ThreadRecorder rec = threadMap.get(thread);
		return rec == null ? null : rec.regs.get(frameLevel);
	}

	@Override
	public Set<TargetThread<?>> getLiveTargetThreads() {
		return threadsView;
	}

	@Override
	public TraceThread getTraceThread(TargetThread<?> thread) {
		ThreadRecorder rec = threadMap.byTargetThread.get(thread);
		return rec == null ? null : rec.traceThread;
	}

	@Override
	public TraceThread getTraceThreadForSuccessor(TargetObjectRef successor) {
		ThreadRecorder rec = threadMap.getForSuccessor(successor);
		return rec == null ? null : rec.traceThread;
	}

	protected TraceStackFrame getTraceStackFrame(TraceThread thread, int level) {
		TraceStack stack = trace.getStackManager().getLatestStack(thread, snapshot.getKey());
		if (stack == null) {
			return null;
		}
		return stack.getFrame(level, false);
	}

	@Override
	public TraceStackFrame getTraceStackFrame(TargetStackFrame<?> frame) {
		ThreadRecorder rec = threadMap.getForSuccessor(frame);
		if (rec == null) {
			return null;
		}
		int level = getFrameLevel(frame);
		if (rec.stack.get(level) != frame) {
			return null;
		}
		return getTraceStackFrame(rec.traceThread, level);
	}

	@Override
	public TraceStackFrame getTraceStackFrameForSuccessor(TargetObjectRef successor) {
		ThreadRecorder rec = threadMap.getForSuccessor(successor);
		if (rec == null) {
			return null;
		}
		int level = rec.getSuccessorFrameLevel(successor);
		return getTraceStackFrame(rec.traceThread, level);
	}

	@Override
	public TargetStackFrame<?> getTargetStackFrame(TraceThread thread, int frameLevel) {
		ThreadRecorder rec = threadMap.get(thread);
		if (rec == null) {
			return null;
		}
		return rec.stack.get(frameLevel);
	}

	@Override
	public DebuggerMemoryMapper getMemoryMapper() {
		return memMapper;
	}

	@Override
	public DebuggerRegisterMapper getRegisterMapper(TraceThread thread) {
		ThreadRecorder rec = threadMap.get(thread);
		if (rec == null) {
			return null;
		}
		return rec.regMapper;
	}

	@Override
	public AddressSetView getAccessibleProcessMemory() {
		// TODO: Efficiently distinguish which memory is process vs. thread
		return getAccessibleMemory(mem -> true);
	}

	protected void invalidate() {
		valid = false;
		listenerForRecord.dispose();
		trace.release(this);
	}

	protected TraceThread findLiveThreadByName(String name) {
		for (TraceThread traceThread : threadManager.getThreadsByPath(name)) {
			if (traceThread != null && traceThread.isAlive()) {
				return traceThread;
			}
		}
		return null;
	}

	@Override
	public CompletableFuture<Void> captureThreadRegisters(TraceThread thread, int frameLevel,
			Set<Register> registers) {
		DebuggerRegisterMapper regMapper = getRegisterMapper(thread);
		if (regMapper == null) {
			throw new IllegalStateException("Have not found register descriptions for " + thread);
		}
		if (!regMapper.getRegistersOnTarget().containsAll(registers)) {
			throw new IllegalArgumentException(
				"All given registers must be recognized by the target");
		}
		if (registers.isEmpty()) {
			return AsyncUtils.NIL;
		}
		List<TargetRegister<?>> tRegs =
			registers.stream().map(regMapper::traceToTarget).collect(Collectors.toList());

		TargetRegisterBank<?> bank = getTargetRegisterBank(thread, frameLevel);
		if (bank == null) {
			throw new IllegalArgumentException(
				"Given thread and frame level does not have a live register bank");
		}
		// NOTE: Cache update, if applicable, will cause recorder to write values to trace
		return bank.readRegisters(tRegs).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> writeThreadRegisters(TraceThread thread, int frameLevel,
			Map<Register, RegisterValue> values) {
		DebuggerRegisterMapper regMapper = getRegisterMapper(thread);
		if (regMapper == null) {
			throw new IllegalStateException("Have not found register descriptions for " + thread);
		}
		if (!regMapper.getRegistersOnTarget().containsAll(values.keySet())) {
			throw new IllegalArgumentException(
				"All given registers must be recognized by the target");
		}
		if (values.isEmpty()) {
			return AsyncUtils.NIL;
		}
		Map<String, byte[]> tVals = values.entrySet().stream().map(ent -> {
			if (ent.getKey() != ent.getValue().getRegister()) {
				throw new IllegalArgumentException("register name mismatch in value");
			}
			return regMapper.traceToTarget(ent.getValue());
		}).collect(Collectors.toMap(Entry::getKey, Entry::getValue));

		TargetRegisterBank<?> bank = getTargetRegisterBank(thread, frameLevel);
		if (bank == null) {
			throw new IllegalArgumentException(
				"Given thread and frame level does not have a live register bank");
		}
		// NOTE: Model + recorder will cause applicable trace updates
		return bank.writeRegistersNamed(tVals).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<byte[]> readProcessMemory(Address start, int length) {
		Address tStart = memMapper.traceToTarget(start);
		return processMemory.readMemory(tStart, length);
	}

	@Override
	public CompletableFuture<Void> writeProcessMemory(Address start, byte[] data) {
		Address tStart = memMapper.traceToTarget(start);
		return processMemory.writeMemory(tStart, data);
	}

	@Override
	public CompletableFuture<Void> captureProcessMemory(AddressSetView set, TaskMonitor monitor) {
		if (set.isEmpty()) {
			return AsyncUtils.NIL;
		}
		// TODO: Figure out how to display/select per-thread memory.
		//   Probably need a thread parameter passed in then?
		//   NOTE: That thread memory will already be chained to process memory. Good.

		int total = 0;
		AddressSetView expSet =
			expandToBlocks(set).intersect(memoryManager.getRegionsAddressSet(snapshot.getKey()));
		for (AddressRange r : expSet) {
			total += Long.divideUnsigned(r.getLength() + BLOCK_SIZE - 1, BLOCK_SIZE);
		}
		monitor.initialize(total);
		monitor.setMessage("Capturing memory");
		// TODO: Read blocks in parallel? Probably NO. Tends to overload the agent.
		return AsyncUtils.each(TypeSpec.VOID, expSet.iterator(), (r, loop) -> {
			AddressRangeChunker it = new AddressRangeChunker(r, BLOCK_SIZE);
			AsyncUtils.each(TypeSpec.VOID, it.iterator(), (vRng, inner) -> {
				// The listener in the recorder will copy to the Trace.
				monitor.incrementProgress(1);
				AddressRange tRng = memMapper.traceToTarget(vRng);
				processMemory.readMemory(tRng.getMinAddress(), (int) tRng.getLength())
						.thenApply(b -> !monitor.isCancelled())
						.handle(inner::repeatWhile);
			}).exceptionally(e -> {
				Msg.error(this, "Error reading range " + r + ": " + e);
				// NOTE: Above may double log, since recorder listens for errors, too
				return null; // Continue looping on errors
			}).thenApply(v -> !monitor.isCancelled()).handle(loop::repeatWhile);
		});
	}

	@Override
	public CompletableFuture<Void> captureDataTypes(TargetDataTypeNamespace<?> namespace,
			TaskMonitor monitor) {
		if (!valid) {
			return AsyncUtils.NIL;
		}
		String path = PathUtils.toString(namespace.getPath());
		monitor.setMessage("Capturing data types for " + path);
		return namespace.getTypes().thenCompose(types -> {
			monitor.initialize(types.size());
			AsyncFence fence = new AsyncFence();
			List<DataType> converted = new ArrayList<>();
			for (TargetNamedDataType<?> type : types) {
				if (monitor.isCancelled()) {
					fence.ready().cancel(false);
					return AsyncUtils.nil();
				}
				monitor.incrementProgress(1);
				fence.include(typeConverter.convertTargetDataType(type).thenAccept(converted::add));
			}
			return fence.ready().thenApply(__ -> converted);
		}).thenAccept(converted -> {
			if (converted == null) {
				return;
			}
			try (PermanentTransaction tid =
				PermanentTransaction.start(trace, "Capture data types for " + path)) {
				// NOTE: createCategory is actually getOrCreate
				Category category = dataTypeManager.createCategory(new CategoryPath("/" + path));
				for (DataType dataType : converted) {
					category.addDataType(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
			}
		});
	}

	@Override
	public CompletableFuture<Void> captureDataTypes(TraceModule module, TaskMonitor monitor) {
		TargetModule<?> targetModule = getTargetModule(module);
		if (targetModule == null) {
			Msg.error(this, "Module " + module + " is not loaded");
			return AsyncUtils.NIL;
		}
		CompletableFuture<? extends Map<String, ? extends TargetDataTypeNamespace<?>>> future =
			targetModule.fetchChildrenSupporting(TargetDataTypeNamespace.tclass);
		// NOTE: I should expect exactly one namespace...
		return future.thenCompose(namespaces -> {
			AsyncFence fence = new AsyncFence();
			for (TargetDataTypeNamespace<?> ns : namespaces.values()) {
				fence.include(captureDataTypes(ns, monitor));
			}
			return fence.ready();
		});
	}

	private TraceNamespaceSymbol createNamespaceIfAbsent(String path) {
		try {
			return symbolManager.namespaces()
					.add(path, symbolManager.getGlobalNamespace(), SourceType.IMPORTED);
		}
		catch (DuplicateNameException e) {
			Msg.info(this, "Namespace for module " + path +
				" already exists or another exists with a conflicting name. Using the existing one: " +
				e);
			TraceNamespaceSymbol ns = symbolManager.namespaces().getGlobalNamed(path);
			if (ns != null) {
				return ns;
			}
			Msg.error(this, "Existing namespace for " + path +
				" is not a plain namespace. Using global namespace.");
			return symbolManager.getGlobalNamespace();
		}
		catch (InvalidInputException | IllegalArgumentException e) {
			Msg.error(this,
				"Could not create namespace for new module: " + path + ". Using global namespace.",
				e);
			return symbolManager.getGlobalNamespace();
		}
	}

	@Override
	public CompletableFuture<Void> captureSymbols(TargetSymbolNamespace<?> namespace,
			TaskMonitor monitor) {
		if (!valid) {
			return AsyncUtils.NIL;
		}
		String path = PathUtils.toString(namespace.getPath());
		monitor.setMessage("Capturing symbols for " + path);
		return namespace.getSymbols().thenAccept(symbols -> {
			try (PermanentTransaction tid =
				PermanentTransaction.start(trace, "Capture types and symbols for " + path)) {
				TraceNamespaceSymbol ns = createNamespaceIfAbsent(path);
				monitor.setMessage("Capturing symbols for " + path);
				monitor.initialize(symbols.size());
				for (TargetSymbol<?> sym : symbols) {
					if (monitor.isCancelled()) {
						return;
					}
					monitor.incrementProgress(1);
					String symName = sym.getIndex();
					if (sym.isConstant()) {
						// TODO: Equate namespaces?
						TraceEquate equate = equateManager.getByName(symName);
						long symVal = sym.getValue().getOffset();
						if (equate != null && equate.getValue() == symVal) {
							continue;
						}
						try {
							equateManager.create(symName, symVal);
						}
						catch (DuplicateNameException | IllegalArgumentException e) {
							Msg.error(this, "Could not create equate: " + symName, e);
						}
						continue;
					}
					Address addr = memMapper.targetToTrace(sym.getValue());
					try {
						symbolManager.labels()
								.create(snapshot.getKey(), null, addr, symName, ns,
									SourceType.IMPORTED);
					}
					catch (InvalidInputException e) {
						Msg.error(this, "Could not add module symbol " + sym + ": " + e);
					}
					/**
					 * TODO: Lay down data type, if present
					 *
					 * TODO: Interpret "address" type correctly. A symbol with this type is itself
					 * the pointer. In other words, it is not specifying the type to lay down in
					 * memory.
					 */
				}
			}
		});
	}

	@Override
	public CompletableFuture<Void> captureSymbols(TraceModule module, TaskMonitor monitor) {
		TargetModule<?> targetModule = getTargetModule(module);
		if (targetModule == null) {
			Msg.error(this, "Module " + module + " is not loaded");
			return AsyncUtils.NIL;
		}
		CompletableFuture<? extends Map<String, ? extends TargetSymbolNamespace<?>>> future =
			targetModule.fetchChildrenSupporting(TargetSymbolNamespace.tclass);
		// NOTE: I should expect exactly one namespace...
		return future.thenCompose(namespaces -> {
			AsyncFence fence = new AsyncFence();
			for (TargetSymbolNamespace<?> ns : namespaces.values()) {
				fence.include(captureSymbols(ns, monitor));
			}
			return fence.ready();
		});
	}

	@Override
	public boolean isSupportsFocus() {
		return focusScope != null;
	}

	@Override
	public TargetObjectRef getFocus() {
		if (curFocus == null) {
			if (focusScope == null) {
				return null;
			}
			TargetObjectRef focus = focusScope.getFocus();
			if (focus == null || !PathUtils.isAncestor(target.getPath(), focus.getPath())) {
				return null;
			}
			curFocus = focus;
		}
		return curFocus;
	}

	@Override
	public CompletableFuture<Boolean> requestFocus(TargetObjectRef focus) {
		if (!isSupportsFocus()) {
			return CompletableFuture
					.failedFuture(new IllegalArgumentException("Target does not support focus"));
		}
		if (!PathUtils.isAncestor(target.getPath(), focus.getPath())) {
			return CompletableFuture.failedFuture(new IllegalArgumentException(
				"Requested focus path is not a successor of the target"));
		}
		if (!PathUtils.isAncestor(focusScope.getPath(), focus.getPath())) {
			return CompletableFuture.failedFuture(new IllegalArgumentException(
				"Requested focus path is not a successor of the focus scope"));
		}
		return focusScope.requestFocus(focus).thenApply(__ -> true).exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			if (ex instanceof DebuggerModelAccessException) {
				String msg = "Could not focus " + focus + ": " + ex.getMessage();
				Msg.info(this, msg);
				plugin.getTool().setStatusInfo(msg);
			}
			Msg.showError(this, null, "Focus Sync", "Could not focus " + focus, ex);
			return false;
		});
	}

	@Override
	public TraceEventListener getListenerForRecord() {
		return null;
	}

	@Override
	public ListenerSet<TraceRecorderListener> getListeners() {
		return null;
	}

	/*
	@Override
	public ListenerForRecord getListenerForRecord() {
		return listenerForRecord;
	}
	*/
}
