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
package ghidra.pcode.emu.jit.decode;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The decoder for a single stride.
 * 
 * <p>
 * This starts at a given seed and proceeds linearly until it hits an instruction without fall
 * through. It may also stop if it encounters an existing entry point or an erroneous user inject.
 * 
 * @see JitPassageDecoder
 */
public class DecoderForOneStride {

	/**
	 * The result of decoding an instruction
	 * 
	 * <p>
	 * This may also represent an error encountered while trying to decode an instruction.
	 * 
	 * @param executor the p-code interpreter, which retains some state
	 * @param program the resulting p-code
	 */
	record StepResult(DecoderExecutor executor, PcodeProgram program) {

		/**
		 * Check whether the result falls through, accumulate its instructions and ops, and apply
		 * any control-flow effects.
		 * 
		 * @return true if the result falls through.
		 * @see DecoderExecutor#checkFallthroughAndAccumulate(PcodeProgram)
		 */
		boolean checkFallthroughAndAccumulate() {
			return executor.checkFallthroughAndAccumulate(program);
		}

		/**
		 * Compute the fall-through target
		 * 
		 * <p>
		 * <b>NOTE</b>: This should only be called after checking if the result actually has fall
		 * through; otherwise, this will blindly compute the address and context immediately after
		 * the instruction.
		 * 
		 * @return the next address to decode
		 */
		AddrCtx next() {
			return executor.takeTargetContext(executor.getAdvancedAddress());
		}
	}

	final JitPassageDecoder decoder;
	final DecoderForOnePassage passage;
	private final AddrCtx start;

	final List<Instruction> instructions = new ArrayList<>();
	final List<PcodeOp> opsForStride = new ArrayList<>();;

	/**
	 * Construct a stride decoder
	 * 
	 * @param decoder the thread's passage decoder
	 * @param passage the decoder for this specific passage
	 * @param start the seed to start this stride
	 */
	public DecoderForOneStride(JitPassageDecoder decoder, DecoderForOnePassage passage,
			AddrCtx start) {
		this.decoder = decoder;
		this.passage = passage;
		this.start = start;
	}

	/**
	 * Finish decoding and create the stride
	 * 
	 * @return the stride
	 */
	DecodedStride toStride() {
		return new DecodedStride(start, instructions, opsForStride);
	}

	/**
	 * "Step" the decoder an instruction
	 * 
	 * <p>
	 * This will attempt to decode the instruction at the given address (and contextreg value). If
	 * the given address is already a known entry point (for the entire emulator), then this returns
	 * {@code null} and the stride should be terminated. Otherwise, this checks for a user inject or
	 * then decodes an instruction. The resulting p-code (which may represent a decode error) is
	 * interpreted, and the first op is saved, in case it is targeted by a direct branch. As a
	 * special case, if the inject and/or instruction emits no p-code, we synthesize a
	 * {@link NopPcodeOp nop}, so that we can enter something into our books.
	 * 
	 * @param at the address of the instruction to decode
	 * @return the result
	 */
	private StepResult stepAddrCtx(AddrCtx at) {
		/**
		 * Avoid duplicate translation when we encounter an existing entry point. Just encode an
		 * exit branch.
		 */
		if (decoder.thread.hasEntry(at)) {
			ExitPcodeOp exitOp = new ExitPcodeOp(at);
			opsForStride.add(exitOp);
			passage.otherBranches.put(exitOp, new ExtBranch(exitOp, at));
			return null;
		}

		DecoderExecutor executor = new DecoderExecutor(this, at);
		PcodeProgram program = decoder.thread.getInject(at.address);
		if (program == null) {
			PseudoInstruction instruction = executor.decodeInstruction();
			instructions.add(instruction);
			program = PcodeProgram.fromInstruction(instruction, false);
		}

		executor.execute(program);
		if (executor.opsForThisStep.isEmpty()) {
			NopPcodeOp nop = new NopPcodeOp(at, 0);
			passage.firstOps.put(at, nop);
			opsForStride.add(nop);
		}
		else {
			passage.firstOps.put(at, executor.opsForThisStep.getFirst());
		}
		return new StepResult(executor, program);
	}

	/**
	 * Decode the stride.
	 * 
	 * @return the decoded stride
	 */
	public DecodedStride decode() {
		AddrCtx at = start;
		while (true) {
			if (passage.firstOps.containsKey(at)) {
				return toStride();
			}

			StepResult result = stepAddrCtx(at);

			if (result == null || !result.checkFallthroughAndAccumulate()) {
				return toStride();
			}

			AddrCtx next = result.next();
			if (at.equals(next)) {
				// Would happen because of inject without control flow
				ExitPcodeOp exitOp = new ExitPcodeOp(at);
				opsForStride.add(exitOp);
				passage.otherBranches.put(exitOp, new ExtBranch(exitOp, at));
				return toStride();
			}
			at = next;
		}

		/**
		 * NOTE: If we impose a max instruction count within the stride, be sure to add the
		 * "external branch" that falls-through to the next instruction outside the passage.
		 */
	}
}
