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
package ghidra.pcode.emu;

import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emulate.InstructionDecodeException;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * The default instruction decoder, based on Sleigh
 * 
 * <p>
 * This simply uses a {@link Disassembler} on the machine's memory state.
 */
public class SleighInstructionDecoder implements InstructionDecoder {
	// TODO: Some sort of instruction decode caching?
	// Not as important for stepping small distances
	// Could become important when dealing with "full system emulation," if we get there.

	private static final String DEFAULT_ERROR = "Unknown disassembly error";

	protected final Language language;
	protected final PcodeExecutorState<?> state;
	protected final AddressFactory addrFactory;
	protected final Disassembler disassembler;

	protected String lastMsg = DEFAULT_ERROR;

	protected InstructionBlock block;
	protected int lengthWithDelays;

	private PseudoInstruction instruction;

	/**
	 * Construct a Sleigh instruction decoder
	 * 
	 * @see {@link DefaultPcodeThread#createInstructionDecoder(PcodeExecutorState)}
	 * @param language the language to decoder
	 * @param state the state containing the target program, probably the shared state of the p-code
	 *            machine. It must be possible to obtain concrete buffers on this state.
	 */
	public SleighInstructionDecoder(Language language, PcodeExecutorState<?> state) {
		this.language = language;
		this.state = state;
		addrFactory = language.getAddressFactory();
		DisassemblerMessageListener listener = msg -> {
			Msg.warn(this, msg);
			lastMsg = msg;
		};
		disassembler =
			Disassembler.getDisassembler(language, addrFactory, TaskMonitor.DUMMY, listener);
	}

	@Override
	public Instruction decodeInstruction(Address address, RegisterValue context) {
		lastMsg = DEFAULT_ERROR;
		if (block != null &&
			(instruction = (PseudoInstruction) block.getInstructionAt(address)) != null) {
			return instruction;
		}
		/*
		 * Parse as few instructions as possible. If more are returned, it's because they form a
		 * parallel instruction group. In that case, I should not have to worry self-modifying code
		 * within that group, so no need to re-disassemble after each is executed.
		 */
		block = disassembler.pseudoDisassembleBlock(
			state.getConcreteBuffer(address, Purpose.DECODE), context, 1);
		if (block == null || block.isEmpty()) {
			throw new DecodePcodeExecutionException(lastMsg, address);
		}
		instruction = (PseudoInstruction) block.getInstructionAt(address);
		lengthWithDelays = computeLength();
		return instruction;
	}

	@Override
	public void branched(Address address) {
		/*
		 * This shouldn't happen in the middle of a parallel instruction group, but in case the
		 * group modifies itself and jumps back to itself, this will ensure it is re-disassembled.
		 */
		block = null;
	}

	/**
	 * Compute the "length" of an instruction, including any delay-slotted instructions that follow
	 * 
	 * @return the length
	 */
	protected int computeLength() {
		int length = instruction.getLength();
		int slots = instruction.getDelaySlotDepth();
		Instruction ins = instruction;
		for (int i = 0; i < slots; i++) {
			try {
				Address next = ins.getAddress().addNoWrap(ins.getLength());
				Instruction ni = block.getInstructionAt(next);
				if (ni == null) {
					throw new InstructionDecodeException("Failed to parse delay slot instruction",
						next);
				}
				ins = ni;
				length += ins.getLength();
			}
			catch (AddressOverflowException e) {
				throw new InstructionDecodeException("Delay slot would exceed address space",
					ins.getAddress());
			}
		}
		return length;
	}

	@Override
	public int getLastLengthWithDelays() {
		return lengthWithDelays;
	}

	@Override
	public Instruction getLastInstruction() {
		return instruction;
	}
}
