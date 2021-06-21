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

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.plugin.core.debug.service.model.interfaces.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.TimedMsg;
import ghidra.util.exception.DuplicateNameException;

public class DefaultThreadRecorder implements ManagedThreadRecorder {
	//private static final boolean LOG_STACK_TRACE = false;

	private final TargetThread targetThread;
	private final TraceThread traceThread;

	protected final AbstractRecorderMemory threadMemory;
	//private AbstractRecorderRegisterSet threadRegisters;
	protected TargetBreakpointSpecContainer threadBreakpointContainer;

	protected Map<Integer, TargetRegisterBank> regs = new HashMap<>();
	protected Collection<TargetRegister> extraRegs;

	protected TargetExecutionState state = TargetExecutionState.ALIVE;

	private final DefaultTraceRecorder recorder;
	private final Trace trace;
	private final TraceObjectManager objectManager;

	private final TraceMemoryManager memoryManager;

	private DebuggerRegisterMapper regMapper;
	private final AbstractDebuggerTargetTraceMapper mapper;

	private final DefaultStackRecorder stackRecorder;
	private final DefaultBreakpointRecorder breakpointRecorder;

	protected static int getFrameLevel(TargetStackFrame frame) {
		// TODO: A fair assumption? frames are elements with numeric base-10 indices
		return Integer.decode(frame.getIndex());
	}

	public DefaultThreadRecorder(DefaultTraceRecorder recorder,
			AbstractDebuggerTargetTraceMapper mapper, TargetThread targetThread,
			TraceThread traceThread) {
		this.recorder = recorder;
		this.mapper = mapper;
		this.trace = recorder.getTrace();
		this.objectManager = recorder.objectManager;

		this.targetThread = targetThread;
		this.traceThread = traceThread;

		this.memoryManager = trace.getMemoryManager();

		//this.threadMemory = new RecorderComposedMemory(recorder.getProcessMemory());
		this.threadMemory = recorder.getProcessMemory();
		//this.threadRegisters = recorder.getThreadRegisters();

		if (targetThread instanceof TargetExecutionStateful) {
			TargetExecutionStateful stateful = (TargetExecutionStateful) targetThread;
			state = stateful.getExecutionState();
		}

		this.stackRecorder = new DefaultStackRecorder(traceThread, recorder);
		this.breakpointRecorder = new DefaultBreakpointRecorder(recorder);
	}

	protected synchronized CompletableFuture<Void> initRegMapper(
			TargetRegisterContainer registers) {
		/**
		 * TODO: At the moment, this assumes the recorded thread has one register container, or at
		 * least that all register banks in the thread use the same register container
		 * (descriptors). If this becomes a problem, then we'll need to keep a separate register
		 * mapper per register container. This would likely also require some notion of multiple
		 * languages in the mapper (seems an unlikely design choice). NOTE: In cases where a single
		 * process may (at least appear to) execute multiple languages, the model should strive to
		 * present the registers of the physical machine, as they are most likely uniform across the
		 * process, not those being emulated in the moment. In cases where an abstract machine is
		 * involved, it is probably more fitting to present separate containers (likely provided by
		 * separate models) than to present both the physical and abstract machine in the same
		 * target.
		 * 
		 * <p>
		 * TODO: Should I formalize that only one register container is present in a recorded
		 * thread? This seems counter to the model's flexibility. Traces allow polyglot disassembly,
		 * but not polyglot register spaces.
		 */
		return objectManager.getRegMappers().get(registers).thenAccept(rm -> {
			synchronized (this) {
				regMapper = rm;
				Language language = trace.getBaseLanguage();
				extraRegs = new LinkedHashSet<>();
				for (String rn : mapper.getExtraRegNames()) {
					Register traceReg = language.getRegister(rn);
					if (traceReg == null) {
						Msg.error(this,
							"Mapper's extra register '" + rn + "' is not in the language!");
						continue;
					}
					TargetRegister targetReg = regMapper.traceToTarget(traceReg);
					if (targetReg == null) {
						Msg.error(this,
							"Mapper's extra register '" + traceReg + "' is not mappable!");
						continue;
					}
					extraRegs.add(targetReg);
				}
			}
		}).exceptionally(ex -> {
			Msg.error(this, "Could not intialize register mapper", ex);
			return null;
		});
	}

	@Override
	public CompletableFuture<Void> doFetchAndInitRegMapper(TargetRegisterBank bank) {
		TargetRegisterContainer descs = bank.getDescriptions();
		if (descs == null) {
			Msg.error(this, "Cannot create mapper, yet: Descriptions is null.");
			return AsyncUtils.NIL;
		}
		return initRegMapper(descs).thenAccept(__ -> {
			recorder.getListeners().fire.registerBankMapped(recorder);
		}).exceptionally(ex -> {
			Msg.error(this, "Could not intialize register mapper", ex);
			return null;
		});
	}

	public CompletableFuture<Map<Register, RegisterValue>> captureThreadRegisters(
			TraceThread thread, int frameLevel, Set<Register> registers) {
		if (regMapper == null) {
			throw new IllegalStateException("Have not found register descriptions for " + thread);
		}
		if (!regMapper.getRegistersOnTarget().containsAll(registers)) {
			throw new IllegalArgumentException(
				"All given registers must be recognized by the target");
		}
		if (registers.isEmpty()) {
			return CompletableFuture.completedFuture(Map.of());
		}
		List<TargetRegister> tRegs =
			registers.stream().map(regMapper::traceToTarget).collect(Collectors.toList());

		TargetRegisterBank bank = getTargetRegisterBank(thread, frameLevel);
		if (bank == null) {
			throw new IllegalArgumentException(
				"Given thread and frame level does not have a live register bank");
		}
		// NOTE: Cache update, if applicable, will cause recorder to write values to trace
		return bank.readRegisters(tRegs).thenApply(regMapper::targetToTrace);
	}

	public TargetRegisterBank getTargetRegisterBank(TraceThread thread, int frameLevel) {
		return regs.get(frameLevel);
	}

	@Override
	public void regMapperAmended(DebuggerRegisterMapper rm, TargetRegister reg, boolean removed) {
		String name = reg.getIndex();
		synchronized (this) {
			if (regMapper != rm) {
				return;
			}
			if (mapper.getExtraRegNames().contains(name)) {
				if (removed) {
					extraRegs.remove(reg);
				}
				else {
					extraRegs.add(reg);
				}
			}
		}
	}

	@Override
	public void offerRegisters(TargetRegisterBank bank) {
		if (regMapper == null) {
			doFetchAndInitRegMapper(bank);
		}
		int frameLevel = stackRecorder.getSuccessorFrameLevel(bank);
		//System.err.println("offerRegisters " + this.targetThread.getDisplay() + ":" + frameLevel);
		TargetRegisterBank old = regs.put(frameLevel, bank);
		if (null != old) {
			Msg.warn(this, "Unexpected register bank replacement");
		}
	}

	@Override
	public void removeRegisters(TargetRegisterBank bank) {
		int frameLevel = stackRecorder.getSuccessorFrameLevel(bank);
		TargetRegisterBank old = regs.remove(frameLevel);
		if (bank != old) {
			Msg.warn(this, "Unexpected register bank upon removal");
		}
	}

	@Override
	public void offerThreadRegion(TargetMemoryRegion region) {
		TargetMemory mem = region.getMemory();
		threadMemory.addRegion(region, mem);
	}

	@Override
	public void stateChanged(final TargetExecutionState newState) {
		state = newState;
	}

	public void threadDestroyed() {
		String path = getTargetThread().getJoinedPath(".");
		long snap = recorder.getSnap();
		recorder.parTx.execute("Thread " + path + " destroyed", () -> {
			// TODO: Should it be key - 1
			// Perhaps, since the thread should not exist
			// But it could imply earlier destruction than actually observed
			try {
				getTraceThread().setDestructionSnap(snap);
			}
			catch (DuplicateNameException e) {
				throw new AssertionError(e); // Should be shrinking
			}
		}, path);
	}

	@Override
	public void recordRegisterValues(TargetRegisterBank bank, Map<String, byte[]> updates) {
		synchronized (recorder) {
			if (regMapper == null) {
				doFetchAndInitRegMapper(bank);
			}
		}
		int frameLevel = stackRecorder.getSuccessorFrameLevel(bank);
		long snap = recorder.getSnap();
		String path = bank.getJoinedPath(".");
		TimedMsg.debug(this, "Reg values changed: " + updates.keySet());
		recorder.parTx.execute("Registers " + path + " changed", () -> {
			TraceCodeManager codeManager = trace.getCodeManager();
			TraceCodeRegisterSpace codeRegisterSpace =
				codeManager.getCodeRegisterSpace(traceThread, false);
			TraceDefinedDataRegisterView definedData =
				codeRegisterSpace == null ? null : codeRegisterSpace.definedData();
			TraceMemoryRegisterSpace regSpace =
				memoryManager.getMemoryRegisterSpace(traceThread, frameLevel, true);
			for (Entry<String, byte[]> ent : updates.entrySet()) {
				RegisterValue rv = regMapper.targetToTrace(ent.getKey(), ent.getValue());
				if (rv == null) {
					continue; // mapper does not know this register....
				}
				regSpace.setValue(snap, rv);
				Register register = rv.getRegister();
				if (definedData != null) {
					TraceData td = definedData.getForRegister(snap, register);
					if (td != null && td.getDataType() instanceof Pointer) {
						Address addr = registerValueToTargetAddress(rv, ent.getValue());
						readAlignedConditionally(ent.getKey(), addr); // NB: Reports errors
					}
				}
			}
		}, getTargetThread().getJoinedPath("."));
	}

	@Override
	public void recordRegisterValue(TargetRegister targetRegister, byte[] value) {
		TargetRegisterBank bank = (TargetRegisterBank) targetRegister.getParent();
		synchronized (recorder) {
			if (regMapper == null) {
				doFetchAndInitRegMapper(bank);
			}
		}
		int frameLevel = stackRecorder.getSuccessorFrameLevel(bank);
		long snap = recorder.getSnap();
		String path = targetRegister.getJoinedPath(".");
		//TimedMsg.info(this, "Register value changed: " + targetRegister);
		recorder.parTx.execute("Register " + path + " changed", () -> {
			TraceCodeManager codeManager = trace.getCodeManager();
			TraceCodeRegisterSpace codeRegisterSpace =
				codeManager.getCodeRegisterSpace(traceThread, false);
			TraceDefinedDataRegisterView definedData =
				codeRegisterSpace == null ? null : codeRegisterSpace.definedData();
			TraceMemoryRegisterSpace regSpace =
				memoryManager.getMemoryRegisterSpace(traceThread, frameLevel, true);
			String key = targetRegister.getName();
			if (PathUtils.isIndex(key)) {
				key = key.substring(1, key.length() - 1);
			}
			RegisterValue rv = regMapper.targetToTrace(key, value);
			if (rv == null) {
				return; // mapper does not know this register....
			}
			regSpace.setValue(snap, rv);
			Register register = rv.getRegister();
			if (definedData != null) {
				TraceData td = definedData.getForRegister(snap, register);
				if (td != null && td.getDataType() instanceof Pointer) {
					Address addr = registerValueToTargetAddress(rv, value);
					readAlignedConditionally(key, addr); // NB: Reports errors
				}
			}
		}, getTargetThread().getJoinedPath("."));
	}

	public CompletableFuture<Void> writeThreadRegisters(int frameLevel,
			Map<Register, RegisterValue> values) {
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

		TargetRegisterBank bank = getTargetRegisterBank(traceThread, frameLevel);
		if (bank == null) {
			throw new IllegalArgumentException(
				"Given thread and frame level does not have a live register bank");
		}
		// NOTE: Model + recorder will cause applicable trace updates
		return bank.writeRegistersNamed(tVals).thenApply(__ -> null);
	}

	Address registerValueToTargetAddress(RegisterValue rv, byte[] value) {
		Address traceAddress =
			trace.getBaseLanguage().getDefaultSpace().getAddress(rv.getUnsignedValue().longValue());
		return objectManager.getMemoryMapper().traceToTarget(traceAddress);
	}

	protected CompletableFuture<?> readAlignedConditionally(String name, Address targetAddress) {
		if (targetAddress == null) {
			return AsyncUtils.NIL;
		}
		Address traceAddress = objectManager.getMemoryMapper().targetToTrace(targetAddress);
		if (traceAddress == null) {
			return AsyncUtils.NIL;
		}
		if (!checkReadCondition(traceAddress)) {
			return AsyncUtils.NIL;
		}
		AddressRange targetRange = threadMemory.alignAndLimitToFloor(targetAddress, 1);
		if (targetRange == null) {
			return AsyncUtils.NIL;
		}
		TimedMsg.debug(this,
			"  Reading memory at " + name + " (" + targetAddress + " -> " + targetRange + ")");
		// NOTE: Recorder takes data via memoryUpdated callback
		// TODO: In that callback, sort out process memory from thread memory?
		return threadMemory.readMemory(targetRange.getMinAddress(), (int) targetRange.getLength())
				.exceptionally(ex -> {
					Msg.error(this, "Could not read memory at " + name, ex);
					return null;
				});
	}

	protected boolean checkReadCondition(Address traceAddress) {
		/**
		 * TODO: This heuristic doesn't really belong here, but I have to implement it here so that
		 * it doesn't "override" the listing's implementation. Once watches are implemented, we
		 * should be able to drop this garbage.
		 */
		TraceMemoryRegion region =
			memoryManager.getRegionContaining(recorder.getSnap(), traceAddress);
		if (region == null) {
			return false;
		}
		if (region.isWrite()) {
			return true;
		}
		Entry<TraceAddressSnapRange, TraceMemoryState> ent =
			memoryManager.getMostRecentStateEntry(recorder.getSnap(), traceAddress);
		if (ent == null) {
			return true;
		}
		if (ent.getValue() == TraceMemoryState.KNOWN) {
			return false;
		}
		return true;
	}

	@Override
	public TargetThread getTargetThread() {
		return targetThread;
	}

	@Override
	public TraceThread getTraceThread() {
		return traceThread;
	}

	@Override
	public long getSnap() {
		return recorder.getSnap();
	}

	@Override
	public Trace getTrace() {
		return recorder.getTrace();
	}

	@Override
	public DebuggerMemoryMapper getMemoryMapper() {
		return recorder.objectManager.getMemoryMapper();
	}

	@Override
	public ManagedStackRecorder getStackRecorder() {
		return stackRecorder;
	}

	@Override
	public ManagedBreakpointRecorder getBreakpointRecorder() {
		return breakpointRecorder;
	}

	/**
	 * Inform the recorder the given object is no longer valid
	 * 
	 * @param invalid the invalidated object
	 * @return true if this recorder should be invalidated, too
	 */
	// UNUSED?
	@Override
	public synchronized boolean objectRemoved(TargetObject invalid) {
		if (checkThreadRemoved(invalid)) {
			return true;
		}
		if (stackRecorder.checkStackFrameRemoved(invalid)) {
			return false;
		}
		if (threadMemory.removeRegion(invalid)) {
			return false;
		}
		Msg.trace(this, "Ignored removed object: " + invalid);
		return false;
	}

	protected boolean checkThreadRemoved(TargetObject invalid) {
		if (getTargetThread() == invalid) {
			threadDestroyed();
			return true;
		}
		return false;
	}

	public DebuggerRegisterMapper getRegisterMapper() {
		return regMapper;
	}

	/*
	public CompletableFuture<Void> updateRegsMem(TargetMemoryRegion limit) {
		TargetRegisterBank bank;
		TargetRegister pc;
		TargetRegister sp;
		Set<TargetRegister> toRead = new LinkedHashSet<>();
		synchronized (recorder) {
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
		System.err.println("URM:" + getTargetThread());
		TimedMsg.info(this, "Reading " + toRead + " of " + getTargetThread());
		return bank.readRegisters(toRead).thenCompose(vals -> {
			synchronized (recorder) {
				if (memoryManager == null) {
					return AsyncUtils.NIL;
				}
			}
			if (threadMemory == null) {
				return AsyncUtils.NIL;
			}
			AsyncFence fence = new AsyncFence();
	
			Address pcTargetAddr = stackRecorder.pcFromStack();
			if (pcTargetAddr == null) {
				pcTargetAddr = registerValueToTargetAddress(pcReg, vals.get(pcReg.getIndex()));
			}
			fence.include(readAlignedConditionally("PC", pcTargetAddr, limit));
	
			Address spTargetAddr = registerValueToTargetAddress(spReg, vals.get(spReg.getIndex()));
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
	*/

}
