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
package ghidra.app.plugin.core.debug.gui.slice;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.*;

import ghidra.app.util.PseudoData;
import ghidra.app.util.PseudoInstruction;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.listing.TraceInstruction;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Shared reference searches used by both forward and backward slicing. */
public enum SliceAnalysis {
	INSTANCE;

	static AddressRange vnRange(Varnode vn) {
		return new AddressRangeImpl(vn.getAddress(), vn.getAddress().add(vn.getSize() - 1));
	}

	static Stream<CodeBlockReference> toStream(CodeBlockReferenceIterator it) {
		return StreamSupport.stream(new Spliterator<>() {
			@Override
			public boolean tryAdvance(Consumer<? super CodeBlockReference> action) {
				try {
					if (!it.hasNext()) {
						return false;
					}
					action.accept(it.next());
					return true;
				}
				catch (CancelledException e) {
					throw new StreamCancelledException(e);
				}
			}

			@Override
			public Spliterator<CodeBlockReference> trySplit() {
				return null;
			}

			@Override
			public long estimateSize() {
				return 0;
			}

			@Override
			public int characteristics() {
				return 0;
			}
		}, false);
	}

	public Instruction getOrDisassemble(Trace trace, long snap, Address start,
			RegisterValue ctx) {
		TraceInstruction instruction = trace.getCodeManager().instructions().getAt(snap, start);
		if (instruction != null) {
			return instruction;
		}
		MemBuffer buffer = trace.getMemoryManager().getBufferAt(snap, start);
		ProcessorContext context = new ProcessorContextImpl(trace.getBaseLanguage());
		try {
			context.setRegisterValue(ctx);
		}
		catch (ContextChangeException e) {
			throw new AssertionError(e);
		}
		InstructionPrototype proto;
		try {
			proto = trace.getBaseLanguage().parse(buffer, context, false);
		}
		catch (InsufficientBytesException | UnknownInstructionException e) {
			return null;
		}
		try {
			return new PseudoInstruction(start, proto, buffer, context);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	public Data getOrPseudoData(Trace trace, long snap, AddressRange range) {
		int len = (int) range.getLength();
		TraceData data = trace.getCodeManager().definedData().getAt(snap, range.getMinAddress());
		if (data != null && data.getLength() == len) {
			return data;
		}
		MemBuffer buffer = trace.getMemoryManager().getBufferAt(snap, range.getMinAddress());
		DataType type = Undefined.getUndefinedDataType(len);
		try {
			return new PseudoData(range.getMinAddress(), type, buffer);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	public TraceMemorySpace getEventThreadRegisters(Trace trace, long snap) {
		TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, false);
		if (snapshot == null || snapshot.getEventThread() == null) {
			return null;
		}
		return trace.getMemoryManager().getMemoryRegisterSpace(snapshot.getEventThread(), false);
	}

	public Address getDynamicPc(Trace trace, long snap) {
		TraceMemorySpace regs = getEventThreadRegisters(trace, snap);
		if (regs == null) {
			return null;
		}
		Register pc = trace.getBaseLanguage().getProgramCounter();
		AddressSpace space = trace.getBaseAddressFactory().getDefaultAddressSpace();
		return space.getAddress(regs.getValue(snap, pc).getUnsignedValue().longValue());
	}

	public ProgramLocation computeStaticPc(Trace trace, long snap,
			DebuggerAddressTranslator translator) {
		Address dyPc = getDynamicPc(trace, snap);
		return dyPc == null || translator == null ? null
				: translator.getOpenMappedLocation(
					new DefaultTraceLocation(trace, null, Lifespan.at(snap), dyPc));
	}

	public Instruction getInstructionAtPc(Trace trace, long snap) {
		TraceMemorySpace regs = getEventThreadRegisters(trace, snap);
		if (regs == null) {
			return null;
		}
		Register pc = trace.getBaseLanguage().getProgramCounter();
		AddressSpace space = trace.getBaseAddressFactory().getDefaultAddressSpace();
		Address counter = space.getAddress(regs.getValue(snap, pc).getUnsignedValue().longValue());
		Register ctxreg = trace.getBaseLanguage().getContextBaseRegister();
		return getOrDisassemble(trace, snap, counter, regs.getValue(snap, ctxreg));
	}

	public OptionalLong computeMostRecentExecution(Trace trace, long snap, Address pc) {
		return trace.getObjectManager()
				.requireRootSchema()
				.getContext()
				.getAllSchemas()
				.stream()
				.filter(s -> s.getInterfaces().contains(TraceStackFrame.class))
				.map(s -> s.checkAliasedAttribute(TraceStackFrame.KEY_PC))
				.flatMapToLong(key -> trace.getObjectManager()
						.getValuesIntersecting(Lifespan.since(snap), new AddressRangeImpl(pc, pc),
							key)
						.stream()
						.mapToLong(value -> -value.getMinSnap()))
				.sorted()
				.map(value -> -value)
				.findFirst();
	}

	public OptionalLong computeNextExecution(Trace trace, long snap, Address pc) {
		return trace.getObjectManager()
				.requireRootSchema()
				.getContext()
				.getAllSchemas()
				.stream()
				.filter(s -> s.getInterfaces().contains(TraceStackFrame.class))
				.map(s -> s.checkAliasedAttribute(TraceStackFrame.KEY_PC))
				.flatMapToLong(key -> trace.getObjectManager()
						.getValuesIntersecting(Lifespan.nowOn(snap), new AddressRangeImpl(pc, pc),
							key)
						.stream()
						.mapToLong(value -> value.getMinSnap()))
				.sorted()
				.findFirst();
	}

	public List<Varnode> getOutputs(Instruction instruction) {
		return Stream.of(instruction.getPcode())
				.map(PcodeOp::getOutput)
				.filter(v -> v != null && (v.isRegister() || v.isAddress()))
				.toList();
	}

	public List<Varnode> getInputs(Instruction instruction) {
		var arithmetic = new PcodeArithmetic<Void>() {
			@Override
			public Class<Void> getDomain() {
				return Void.class;
			}

			@Override
			public Endian getEndian() {
				return null;
			}

			@Override
			public Void unaryOp(int opcode, int sizeout, int sizein1, Void in1) {
				return null;
			}

			@Override
			public Void binaryOp(int opcode, int sizeout, int sizein1, Void in1,
					int sizein2, Void in2) {
				return null;
			}

			@Override
			public Void modBeforeStore(int sizeinOffset, AddressSpace space,
					Void inOffset, int sizeinValue, Void inValue) {
				return null;
			}

			@Override
			public Void modAfterLoad(int sizeinOffset, AddressSpace space,
					Void inOffset, int sizeinValue, Void inValue) {
				return null;
			}

			@Override
			public Void fromConst(byte[] value) {
				return null;
			}

			@Override
			public byte[] toConcrete(Void value, Purpose purpose) {
				throw new ConcretionError("Cannot concretize Void", purpose);
			}

			@Override
			public long sizeOf(Void value) {
				throw new UnsupportedOperationException();
			}
		};
		var state = new PcodeExecutorState<Void>() {
			private final AddressSet written = new AddressSet();
			private final Set<Varnode> inputs = new LinkedHashSet<>();

			@Override
			public Language getLanguage() {
				return instruction.getLanguage();
			}

			@Override
			public PcodeArithmetic<Void> getArithmetic() {
				return arithmetic;
			}

			@Override
			public Stream<PcodeExecutorStatePiece<?, ?>> streamPieces() {
				return Stream.of(this);
			}

			@Override
			public void setVar(AddressSpace space, long offset, int size,
					boolean quantize, Void val) {
				if (space.isRegisterSpace() || space.isMemorySpace()) {
					written.add(space.getAddress(offset), space.getAddress(offset + size - 1));
				}
			}

			@Override
			public void setVar(AddressSpace space, Void offset, int size,
					boolean quantize, Void val) {
			}

			@Override
			public void setVarInternal(AddressSpace space, Void offset, int size, Void val) {
			}

			@Override
			public Void getVar(AddressSpace space, Void offset, int size,
					boolean quantize, Reason reason) {
				return null;
			}

			@Override
			public Void getVar(AddressSpace space, long offset, int size,
					boolean quantize, Reason reason) {
				if (space.isRegisterSpace() || space.isMemorySpace()) {
					Address min = space.getAddress(offset);
					if (!written.contains(min, space.getAddress(offset + size - 1))) {
						inputs.add(new Varnode(min, size));
					}
				}
				return null;
			}

			@Override
			public Void getVarInternal(AddressSpace space, Void offset, int size,
					Reason reason) {
				return null;
			}

			@Override
			public Map<Register, Void> getRegisterValues() {
				return null;
			}

			@Override
			public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
				return null;
			}

			@Override
			public void clear() {
				written.clear();
			}

			@Override
			public PcodeExecutorState<Void> fork(PcodeStateCallbacks cb) {
				throw new AssertionError();
			}
		};
		var exec = new PcodeExecutor<Void>(state, Reason.EXECUTE_READ) {
			@Override
			protected void branchToOffset(PcodeOp op, Void offset, PcodeFrame frame) {
			}

			@Override
			protected void branchInternal(PcodeOp op, PcodeFrame frame, int relative) {
			}

			@Override
			public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
				state.getVar(getConditionalBranchPredicate(op), reason);
			}
		};
		exec.execute(List.of(instruction.getPcode()), PcodeUseropLibrary.nil());
		return List.copyOf(state.inputs);
	}

	public Set<TraceReference> actualDefinitionsOfVariable(Trace trace, AddressRange target,
			long snap) {
		AddressSet remains = new AddressSet(target);
		Set<TraceReference> result = new LinkedHashSet<>();
		for (TraceReference ref : trace.getReferenceManager()
				.getReferencesToRange(Lifespan.since(snap - 1), target,
					Rectangle2DDirection.TOPMOST)) {
			if (!ref.getReferenceType().isWrite()) {
				continue;
			}
			if (remains.intersects(ref.getToRange())) {
				result.add(ref);
				remains.delete(ref.getToRange());
			}
			if (remains.isEmpty()) {
				break;
			}
		}
		return result;
	}

	public Set<TraceReference> actualUsesOfVariable(Trace trace, AddressRange target, long snap) {
		AddressSet remains = new AddressSet(target);
		Set<TraceReference> result = new LinkedHashSet<>();
		for (TraceReference ref : trace.getReferenceManager()
				.getReferencesToRange(Lifespan.nowOn(snap + 1), target,
					Rectangle2DDirection.BOTTOMMOST)) {
			if (ref.getReferenceType().isWrite()) {
				remains.delete(ref.getToRange());
				if (remains.isEmpty()) {
					break;
				}
				continue;
			}
			if (!ref.getReferenceType().isRead()) {
				continue;
			}
			if (remains.intersects(ref.getToRange())) {
				result.add(ref);
			}
		}
		return result;
	}

	public Set<TraceReference> actualInputsToInstruction(Trace trace, Address from, long snap) {
		return trace.getReferenceManager()
				.getReferencesFrom(snap, from)
				.stream()
				.filter(ref -> ref.getReferenceType().isRead())
				.collect(Collectors.toSet());
	}

	public Set<TraceReference> actualOutputsFromInstruction(Trace trace, Address from, long snap) {
		return trace.getReferenceManager()
				.getReferencesFrom(snap, from)
				.stream()
				.filter(ref -> ref.getReferenceType().isWrite())
				.collect(Collectors.toSet());
	}

	public UnitSnap<Instruction> actualConditionalBranchTo(Trace trace, long snap,
			TaskMonitor monitor) throws CancelledException {
		// LATER: Might be nice to have an index on conditional branches?
		// Eh, it's been plenty fast for my uses
		for (long s = snap - 1; s >= 0; s--) {
			monitor.checkCancelled();
			Instruction instruction = getInstructionAtPc(trace, s);
			if (instruction == null) {
				continue;
			}
			if (instruction.getFlowType().isConditional()) {
				return new UnitSnap<>(instruction, s, true);
			}
		}
		return null;
	}

	public UnitSnap<Instruction> actualBranchFrom(Trace trace, long snap, TaskMonitor monitor)
			throws CancelledException {
		Instruction previous = getInstructionAtPc(trace, snap);
		for (long s = snap + 1; s > 0 /* terminate on overflow */; s++) {
			monitor.checkCancelled();
			Instruction instruction = getInstructionAtPc(trace, s);
			FlowType flowType = instruction.getFlowType();
			if (flowType.isConditional() || flowType.isComputed() || flowType.isTerminal()) {
				return new UnitSnap<>(instruction, s, true);
			}
			if (s == snap) {
				continue;
			}
			// Handle exceptional cases
			FlowType prevType = previous.getFlowType();
			Address expectedPc;
			if (prevType.isFallthrough()) {
				expectedPc = previous.getFallThrough();
			}
			else if (prevType.isUnConditional()) {
				expectedPc = previous.getFlows()[0];
			}
			else {
				throw new AssertionError("Unhandled flow type");
			}
			if (!expectedPc.equals(instruction.getAddress())) {
				return new UnitSnap<>(previous, s - 1, true);
			}
		}
		return null;
	}

	public Set<Address> staticDefinitionsOfMemory(Program program, AddressRange target,
			TaskMonitor monitor) throws CancelledException {
		ReferenceManager references = program.getReferenceManager();
		Set<Address> result = new LinkedHashSet<>();
		for (Address addr : target) {
			monitor.checkCancelled();
			for (var ref : references.getReferencesTo(addr)) {
				if (ref.getReferenceType().isWrite()) {
					result.add(ref.getFromAddress());
				}
			}
		}
		return result;
	}

	public Set<Address> staticUsesOfMemory(Program program, AddressRange target,
			TaskMonitor monitor) throws CancelledException {
		ReferenceManager references = program.getReferenceManager();
		Set<Address> result = new LinkedHashSet<>();
		for (Address addr : target) {
			monitor.checkCancelled();
			for (var ref : references.getReferencesTo(addr)) {
				if (ref.getReferenceType().isRead()) {
					result.add(ref.getFromAddress());
				}
			}
		}
		return result;
	}

	public Set<Address> staticDefinitionsOfRegister(Program image, Address pc, AddressRange target,
			TaskMonitor monitor) throws CancelledException {
		var walk = new Object() {
			record Visited(CodeBlock block, Address at, AddressSetView remaining) {}

			final BasicBlockModel blocks = new BasicBlockModel(image, false);
			final Set<Visited> visited = new HashSet<>();

			Stream<Instruction> writesToOperand(Address at, AddressSetView remaining)
					throws CancelledException {
				return Stream.of(blocks.getCodeBlocksContaining(at, monitor))
						.flatMap(b -> StreamCancelledException
								.run(() -> writesToOperand(b, at, remaining)));
			}

			Stream<Instruction> writesToOperand(CodeBlock block, Address at,
					AddressSetView remaining) throws CancelledException {
				if (!visited.add(new Visited(block, at, remaining))) {
					return Stream.empty();
				}
				List<Instruction> definitions = new ArrayList<>();
				AddressSetView before = at.equals(block.getMaxAddress()) ? block
						: block.intersectRange(at.getAddressSpace().getMinAddress(), at.previous());
				for (Instruction instruction : image.getListing().getInstructions(before, false)) {
					// TODO: What if it's a call instruction?
					for (Varnode output : getOutputs(instruction)) {
						if (!output.isRegister()) {
							continue;
						}
						AddressRange range = vnRange(output);
						if (!remaining.intersects(range)) {
							continue;
						}
						definitions.add(instruction);
						AddressSet newRemaining = new AddressSet(remaining);
						newRemaining.delete(range);
						if (newRemaining.isEmpty()) {
							return definitions.stream();
						}
						remaining = newRemaining;
					}
				}
				AddressSetView upRemaining = remaining;
				return Stream.concat(definitions.stream(), toStream(block.getSources(monitor))
						.map(br -> br.getSourceBlock())
						.flatMap(b -> StreamCancelledException
								.run(() -> writesToOperand(b, upRemaining))));
			}

			Stream<Instruction> writesToOperand(CodeBlock block, AddressSetView remaining)
					throws CancelledException {
				return writesToOperand(block, block.getMaxAddress(), remaining);
			}
		};
		try {
			return walk.writesToOperand(pc, new AddressSet(target))
					.map(Instruction::getAddress)
					.collect(Collectors.toSet());
		}
		catch (StreamCancelledException e) {
			throw e.getCause();
		}
	}

	public Set<Address> staticUsesOfRegister(Program image, Address pc, AddressRange target,
			TaskMonitor monitor) throws CancelledException {
		var walk = new Object() {
			record Visited(CodeBlock block, Address at, AddressSetView remaining) {}

			final BasicBlockModel blocks = new BasicBlockModel(image, false);
			final Set<Visited> visited = new HashSet<>();

			Stream<Instruction> readsOperand(Address at, AddressSetView remaining)
					throws CancelledException {
				return Stream.of(blocks.getCodeBlocksContaining(at, monitor))
						.flatMap(b -> StreamCancelledException
								.run(() -> readsOperand(b, at, remaining)));
			}

			Stream<Instruction> readsOperand(CodeBlock block, Address at, AddressSetView remaining)
					throws CancelledException {
				if (!visited.add(new Visited(block, at, remaining))) {
					return Stream.empty();
				}
				List<Instruction> uses = new ArrayList<>();
				AddressSetView after = at.equals(block.getMinAddress()) ? block
						: block.intersectRange(at.next(), at.getAddressSpace().getMaxAddress());
				for (Instruction instruction : image.getListing().getInstructions(after, true)) {
					// TODO: What if it's a call instruction?
					for (Varnode input : getInputs(instruction)) {
						if (!input.isRegister()) {
							continue;
						}
						AddressRange range = vnRange(input);
						if (!remaining.intersects(range)) {
							continue;
						}
						uses.add(instruction);
					}
					AddressSet newRemaining = new AddressSet(remaining);
					for (Varnode output : getOutputs(instruction)) {
						newRemaining.delete(vnRange(output));
					}
					if (newRemaining.isEmpty()) {
						return uses.stream();
					}
					remaining = newRemaining;
				}
				AddressSetView downRemaining = remaining;
				return Stream.concat(uses.stream(), toStream(block.getDestinations(monitor))
						.map(br -> br.getDestinationBlock())
						.flatMap(b -> StreamCancelledException
								.run(() -> readsOperand(b, downRemaining))));
			}

			Stream<Instruction> readsOperand(CodeBlock block, AddressSetView remaining)
					throws CancelledException {
				return readsOperand(block, block.getMinAddress(), remaining);
			}
		};
		try {
			return walk.readsOperand(pc, new AddressSet(target))
					.map(Instruction::getAddress)
					.collect(Collectors.toSet());
		}
		catch (StreamCancelledException e) {
			throw e.getCause();
		}
	}

	public Set<Address> staticDefinitionsOfVariable(Program program, Address pc,
			AddressRange target, TaskMonitor monitor) throws CancelledException {
		return target.getAddressSpace().isMemorySpace()
				? staticDefinitionsOfMemory(program, target, monitor)
				: staticDefinitionsOfRegister(program, pc, target, monitor);
	}

	public Set<Address> staticUsesOfVariable(Program program, Address pc, AddressRange target,
			TaskMonitor monitor) throws CancelledException {
		return target.getAddressSpace().isMemorySpace()
				? staticUsesOfMemory(program, target, monitor)
				: staticUsesOfRegister(program, pc, target, monitor);
	}

	public Set<Instruction> staticConditionalBranchesTo(Program program, Instruction instruction,
			TaskMonitor monitor) throws CancelledException {
		var walk = new Object() {
			final BasicBlockModel blocks = new BasicBlockModel(program, false);
			final Set<CodeBlock> visited = new HashSet<>();

			Stream<Instruction> depsAtAddress(Address address) throws CancelledException {
				return Stream.of(blocks.getCodeBlocksContaining(address, monitor))
						.flatMap(block -> StreamCancelledException.run(() -> depsForBlock(block)));
			}

			boolean isConditional(CodeBlockReference ref) throws CancelledException {
				if (ref.getFlowType().isConditional()) {
					return true;
				}
				if (!ref.getFlowType().isFallthrough()) {
					return false;
				}
				CodeBlockReferenceIterator refs = ref.getSourceBlock().getDestinations(monitor);
				while (refs.hasNext()) {
					if (refs.next().getFlowType().isConditional()) {
						return true;
					}
				}
				return false;
			}

			Stream<Instruction> depsForBlock(CodeBlock block) throws CancelledException {
				if (!visited.add(block)) {
					return Stream.empty();
				}
				List<Instruction> branches = new ArrayList<>();
				List<CodeBlock> predecessors = new ArrayList<>();
				CodeBlockReferenceIterator refs = block.getSources(monitor);
				while (refs.hasNext()) {
					CodeBlockReference ref = refs.next();
					if (!ref.getFlowType().isFlow()) {
						continue;
					}
					if (isConditional(ref)) {
						Instruction branch =
							program.getListing().getInstructionAt(ref.getReferent());
						if (branch != null) {
							branches.add(branch);
						}
					}
					else {
						predecessors.add(ref.getSourceBlock());
					}
				}
				return Stream.concat(branches.stream(), predecessors.stream()
						.flatMap(pred -> StreamCancelledException.run(() -> depsForBlock(pred))));
			}
		};
		try {
			return walk.depsAtAddress(instruction.getAddress()).collect(Collectors.toSet());
		}
		catch (StreamCancelledException e) {
			throw e.getCause();
		}
	}

	public Instruction staticBranchFrom(Program program, Instruction instruction,
			TaskMonitor monitor) throws CancelledException {
		var walk = new Object() {
			final BasicBlockModel blocks = new BasicBlockModel(program, false);
			final Set<CodeBlock> visited = new HashSet<>();

			Instruction branchFrom(CodeBlock block) throws CancelledException {
				if (!visited.add(block)) {
					return null;
				}
				List<CodeBlock> flowDests = toStream(block.getDestinations(monitor))
						.filter(br -> br.getFlowType().isFlow())
						.map(br -> br.getDestinationBlock())
						.toList();
				int size = flowDests.size();
				if (size == 1) {
					return branchFrom(flowDests.get(0));
				}
				return program.getListing().getInstructionContaining(block.getMaxAddress());
			}

			Instruction branchFrom(Address address) throws CancelledException {
				for (CodeBlock block : blocks.getCodeBlocksContaining(address, monitor)) {
					Instruction instruction = branchFrom(block);
					if (instruction != null) {
						return instruction;
					}
				}
				return null;
			}
		};
		return walk.branchFrom(instruction.getAddress());
	}
}
