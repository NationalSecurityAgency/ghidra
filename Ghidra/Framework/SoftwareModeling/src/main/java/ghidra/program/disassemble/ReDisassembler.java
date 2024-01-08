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
package ghidra.program.disassemble;

import java.util.*;

import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ProgramContextImpl;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A class that re-disassembles where necessary
 * 
 * <p>
 * Given a seed address, this will (re-)disassemble the instruction at that address. If it indicates
 * any context changes, whether via {@code globalset} or fall-through, the affected addresses are
 * considered for re-disassembly as well. If no instruction exists at the address, or an off-cut
 * instruction exists at the address, the address is dropped, but the outgoing context is recorded.
 * If one does exist, but its context is already the same, the address is dropped. Otherwise, it is
 * queued up and the process repeats.
 */
public class ReDisassembler {

	protected final Language language;
	protected final AddressFactory addrFactory;
	protected final Register ctxRegister;
	protected final ParallelInstructionLanguageHelper parallelHelper;

	private final Program program;
	private final Listing listing;
	private final ProgramContext programContext;

	public ReDisassembler(Program program) {
		this.program = program;
		this.listing = program.getListing();
		this.programContext = program.getProgramContext();
		this.language = program.getLanguage();
		this.addrFactory = program.getAddressFactory();
		this.ctxRegister = language.getContextBaseRegister();
		this.parallelHelper = language.getParallelInstructionHelper();
	}

	enum FlowType {
		SEED, FALLTHROUGH, BRANCH, GLOBALSET;
	}

	record Flow(Address from, Address to, FlowType type) {
		static Flow seed(Address seed) {
			return new Flow(Address.NO_ADDRESS, seed, FlowType.SEED);
		}

		static Flow fallThrough(Instruction instruction) throws AddressOverflowException {
			return new Flow(instruction.getAddress(),
				instruction.getAddress().add(instruction.getLength()), FlowType.FALLTHROUGH);
		}

		static Flow branch(Instruction instruction, Address to) {
			return new Flow(instruction.getAddress(), to, FlowType.BRANCH);
		}

		Flow globalSet(Address address) {
			return new Flow(to, address, FlowType.GLOBALSET);
		}
	}

	protected class ReDisState {
		protected final TaskMonitor monitor;
		protected final MemBuffer progMemBuffer =
			new DumbMemBufferImpl(program.getMemory(), program.getMemory().getMinAddress());
		protected final ProgramContext tempContext = new ProgramContextImpl(language);
		protected final AddressSet visited = new AddressSet();
		protected final Deque<Flow> queue = new LinkedList<>();
		protected final InstructionSet instructionSet = new InstructionSet(addrFactory);
		// ProgramContext will not remember sets to default context.
		protected final Set<Address> ctxAddrs = new TreeSet<>();

		public ReDisState(TaskMonitor monitor) {
			this.monitor = monitor;
			this.monitor.setMessage("Re-disassembling");
		}

		protected ReDisState addSeed(Address seed) {
			RegisterValue seedCtx = programContext.getRegisterValue(ctxRegister, seed);
			try {
				if (seedCtx == null) {
					tempContext.remove(seed, seed, ctxRegister);
				}
				else {
					tempContext.setRegisterValue(seed, seed, seedCtx);
				}
			}
			catch (ContextChangeException e) {
				throw new AssertionError(e);
			}
			return addFlow(Flow.seed(seed));
		}

		protected ReDisState addFlow(Flow flow) {
			queue.add(flow);
			return this;
		}

		protected MemBuffer createBuffer(Address at) {
			return new WrappedMemBuffer(progMemBuffer, 20,
				(int) at.subtract(progMemBuffer.getAddress()));
		}

		/**
		 * Not necessarily a full block, but certainly no more than a block.
		 *
		 * <p>
		 * It's also not necessarily a <em>basic block</em>, since this doesn't care about jumps
		 * into the block. It simply starts at the next seed and proceeds until either the existing
		 * instruction and context matches what's already there, or it encounters an unconditional
		 * branch.
		 * 
		 * @return true if the queue is non-empty after completing this block, false if we're done.
		 * @throws CancelledException
		 */
		protected boolean nextBlock() throws CancelledException {
			monitor.checkCancelled();
			instructionSet.addBlock(new ReDisBlock(this, queue.pop()).disassembleBlock());
			return !queue.isEmpty();
		}

		protected InstructionSet disassemble() throws CancelledException {
			while (nextBlock()) {
			}
			return instructionSet;
		}

		public void writeContext() {
			for (Address addr : ctxAddrs) {
				RegisterValue curCtxVal = programContext.getRegisterValue(ctxRegister, addr);
				RegisterValue newCtxVal = tempContext.getRegisterValue(ctxRegister, addr);

				if (Objects.equals(curCtxVal, newCtxVal)) {
					continue;
				}
				try {
					if (newCtxVal == null) {
						programContext.remove(addr, addr, ctxRegister);
					}
					else {
						programContext.setRegisterValue(addr, addr, newCtxVal);
					}
				}
				catch (ContextChangeException e) {
					Msg.error(this, "Cannot write context at " + addr + ": " + e);
				}
			}
		}
	}

	protected class ReDisBlock {
		protected final ReDisState state;
		protected final Flow entry;
		protected final InstructionBlock block;
		protected final DisassemblerContextImpl disassemblerContext;
		protected PseudoInstruction lastInstruction;

		public ReDisBlock(ReDisState state, Flow entry) {
			this.state = state;
			this.entry = entry;
			this.block = new InstructionBlock(entry.to);
			this.disassemblerContext = new DisassemblerContextImpl(state.tempContext);
			this.disassemblerContext.flowStart(entry.to);
		}

		protected void recordContext(Address to) {
			RegisterValue ctxValue = disassemblerContext.getRegisterValue(ctxRegister);
			try {
				if (ctxValue == null) {
					state.tempContext.remove(to, to, ctxRegister);
				}
				else {
					state.tempContext.setRegisterValue(to, to, ctxValue);
				}
				state.ctxAddrs.add(to);
			}
			catch (ContextChangeException e) {
				throw new AssertionError(e);
			}
		}

		protected PseudoInstruction createInstruction(Address address,
				InstructionPrototype prototype, MemBuffer memBuffer, ProcessorContext ctx)
				throws AddressOverflowException {
			PseudoInstruction instruction = new PseudoInstruction(program, address, prototype,
				memBuffer, ctx);
			instruction.setInstructionBlock(block);
			return lastInstruction = instruction;
		}

		protected boolean shouldDisassemble(Flow flow) {
			Instruction exists = listing.getInstructionContaining(flow.to);
			if (exists == null) {
				/**
				 * NOTE: New instructions are not placed until we're all done, so there is no need
				 * to worry about differences in instruction length as we progress through a block.
				 */
				return false;
			}
			if (flow.type == FlowType.FALLTHROUGH) {
				return true;
			}
			if (exists.getAddress().equals(flow.to)) {
				return true;
			}
			return false;
		}

		protected Instruction nextInstruction(Flow flow, boolean isInDelaySlot)
				throws CancelledException {
			state.monitor.checkCancelled();
			if (state.visited.contains(flow.to)) {
				// Already disassembled here
				// TODO: Record instruction conflicts?
				return null;
			}
			recordContext(flow.to);
			if (!shouldDisassemble(flow)) {
				return null;
			}
			MemBuffer buffer = state.createBuffer(flow.to);
			RegisterValue newCtxVal = disassemblerContext.getRegisterValue(ctxRegister);
			RegisterValue curCtxVal = programContext.getRegisterValue(ctxRegister, flow.to);
			if (Objects.equals(newCtxVal, curCtxVal) && flow.type != FlowType.SEED) {
				// No need to re-disassemble if context has not changed.
				return null;
			}
			ReDisassemblerContext ctx = new ReDisassemblerContext(state, flow);
			try {
				InstructionPrototype prototype = language.parse(buffer, ctx, false);
				return createInstruction(flow.to, prototype, buffer, ctx);
			}
			catch (UnknownInstructionException e) {
				block.setParseConflict(flow.from, disassemblerContext.getRegisterValue(
					disassemblerContext.getBaseContextRegister()), flow.to, e.getMessage());
				return null;
			}
			catch (InsufficientBytesException e) {
				block.setInstructionMemoryError(flow.to, flow.from, e.getMessage());
				return null;
			}
			catch (AddressOverflowException e) {
				block.setInstructionMemoryError(flow.to, flow.from,
					"Instruction does not fit within address space constraint");
				return null;
			}
		}

		/**
		 * Parse the next instructions, including delay-slotted ones
		 * 
		 * @param address the starting address
		 * @return the if the first instruction has fall-through, the flow out from the last
		 *         instruction parsed. Without delay slots, the first instruction is the last
		 *         instruction.
		 * @throws CancelledException
		 * @throws AddressOverflowException if an instruction would run past the end of the address
		 *             space
		 */
		protected Flow nextInstructionsWithDelays(Flow flow) throws CancelledException {
			Instruction instruction = nextInstruction(flow, false);
			if (instruction == null) {
				return null;
			}
			boolean hasFallthrough = instruction.hasFallthrough();
			try {
				flow = Flow.fallThrough(instruction);
				block.addInstruction(instruction);
				processInstruction(instruction);
				disassemblerContext.flowToAddress(flow.to);
				int remainingBytes = instruction.getPrototype().getDelaySlotByteCount();
				while (remainingBytes > 0) {
					instruction = nextInstruction(flow, true);
					if (instruction == null) {
						return null;
					}
					flow = Flow.fallThrough(instruction);
					block.addInstruction(instruction);
					processInstruction(instruction);
					remainingBytes -= instruction.getLength();
				}
				return hasFallthrough ? flow : null;
			}
			catch (AddressOverflowException e) {
				block.setInstructionMemoryError(flow.to, flow.from,
					"Failed to properly process delay slot at end of address space");
				return null;
			}
		}

		protected void processInstruction(Instruction instruction) {
			state.visited.add(instruction.getMinAddress(), instruction.getMaxAddress());
			for (Address to : instruction.getFlows()) {
				recordContext(to);
				state.addFlow(Flow.branch(instruction, to));
			}
		}

		protected InstructionBlock disassembleBlock() throws CancelledException {
			Flow flow = entry;
			while (flow != null) {
				flow = nextInstructionsWithDelays(flow);
			}
			return block;
		}
	}

	protected class ReDisassemblerContext implements DisassemblerContextAdapter {
		protected final ReDisState state;
		protected final Flow flow;

		public ReDisassemblerContext(ReDisState state, Flow flow) {
			this.state = state;
			this.flow = flow;
		}

		@Override
		public void setFutureRegisterValue(Address address, RegisterValue value) {
			state.addFlow(flow.globalSet(address));
			try {
				state.tempContext.setRegisterValue(address, address, value);
				state.ctxAddrs.add(address);
			}
			catch (ContextChangeException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			return state.tempContext.getRegisterValue(register, flow.to);
		}
	}

	public AddressSetView disasemble(Address seed, TaskMonitor monitor) throws CancelledException {
		ReDisState state = new ReDisState(monitor);
		state.addSeed(seed);
		InstructionSet set = state.disassemble();
		for (AddressRange range : set.getAddressSet()) {
			listing.clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), true, monitor);
		}
		state.writeContext();
		try {
			listing.addInstructions(set, false);
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this, "Could not overwrite with re-disassembly", e);
		}
		return set.getAddressSet();
	}
}
