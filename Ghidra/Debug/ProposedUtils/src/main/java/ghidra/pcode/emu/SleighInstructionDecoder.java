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

import ghidra.pcode.emulate.InstructionDecodeException;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class SleighInstructionDecoder implements InstructionDecoder {
	// TODO: Some sort of instruction decode caching?
	// Not as imported for stepping small distances
	// Could become important when dealing with "full system emulation," if we get there.

	private static final String DEFAULT_ERROR = "Unknown disassembly error";

	protected final PcodeExecutorState<?> state;
	protected final AddressFactory addrFactory;
	protected final Disassembler disassembler;

	protected String lastMsg = DEFAULT_ERROR;

	protected InstructionBlock block;
	protected int lengthWithDelays;

	private Instruction instruction;

	public SleighInstructionDecoder(Language language, PcodeExecutorState<?> state) {
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
		// Always re-parse block in case bytes change
		block = disassembler.pseudoDisassembleBlock(state.getConcreteBuffer(address), context, 1);
		instruction = block == null ? null : block.getInstructionAt(address);
		if (instruction == null) {
			throw new InstructionDecodeException(lastMsg, address);
		}
		lengthWithDelays = computeLength();
		return instruction;
	}

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
