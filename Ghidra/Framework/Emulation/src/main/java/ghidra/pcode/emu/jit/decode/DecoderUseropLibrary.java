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

import java.lang.reflect.Method;
import java.util.List;

import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeEmulationLibrary;
import ghidra.pcode.emu.jit.op.JitNopOp;
import ghidra.pcode.exec.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * The decoder's wrapper around the emulator's userop library
 * 
 * <p>
 * This library serves two purposes: 1) to override {@link PcodeEmulationLibrary#emu_exec_decoded()}
 * and {@link PcodeEmulationLibrary#emu_skip_decoded()}, and 2) to check and inline p-code userops
 * that {@link ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition#canInlinePcode() allow}
 * it.
 * 
 * <p>
 * We accomplish the first purpose simply by adding the two userops using the usual annotations. The
 * two built-in userops regarding the decoded instruction are easily inlinable, so we will mark them
 * as such. Note, however, that they are separate from the wrappers we mention for the second
 * purpose (inlining), and so we must implement that inlining in the actual userop. We still mark
 * them for informational purposes and because the translator needs to know.
 * 
 * <p>
 * We accomplish the second purpose of inlining by accepting the emulator's userop library and
 * individually wrapping each of its userops, excluding the two we override. We allow each userop's
 * attributes to pass through, but when executed, we check if the userop allows inlining. If so,
 * then we feed the userop's p-code into the decoder's interpreter. This effectively inlines the op,
 * control flow ops and all, into the passage. Note we do not actually replace the
 * {@link PcodeOp#CALLOTHER callother} op, for bookkeeping purposes. Instead we will map it to a
 * {@link JitNopOp nop} during translation.
 */
public class DecoderUseropLibrary extends AnnotatedPcodeUseropLibrary<Object> {

	/**
	 * The wrapper around one of the emulator's userops
	 */
	protected class WrappedUseropDefinition implements PcodeUseropDefinition<Object> {
		private final PcodeUseropDefinition<byte[]> rtOp;

		/**
		 * Wrap the given userop
		 * 
		 * @param rtOp the actual userop, as defined by the user or emulator
		 */
		public WrappedUseropDefinition(PcodeUseropDefinition<byte[]> rtOp) {
			this.rtOp = rtOp;
		}

		@Override
		public String getName() {
			return rtOp.getName();
		}

		@Override
		public int getInputCount() {
			return rtOp.getInputCount();
		}

		@Override
		public void execute(PcodeExecutor<Object> executor, PcodeUseropLibrary<Object> library,
				Varnode outVar, List<Varnode> inVars) {
			throw new AssertionError();
		}

		/**
		 * {@inheritDoc}
		 * 
		 * @implNote If the userop can be inlined, we assume the delegate's {@code execute} method
		 *           simply produces p-code and feeds it to the executor. If that is true, then the
		 *           target type {@code <T>} does not matter, so we cast everything to raw types.
		 *           Thus, the user is responsible to apply the {@link #canInlinePcode()} attribute
		 *           correctly.
		 */
		@Override
		@SuppressWarnings("unchecked")
		public void execute(PcodeExecutor<Object> executor, PcodeUseropLibrary<Object> library,
				PcodeOp op) {
			if (rtOp.canInlinePcode()) {
				@SuppressWarnings("rawtypes")
				PcodeExecutor rawExec = executor;
				@SuppressWarnings("rawtypes")
				PcodeUseropLibrary rawLib = library;
				rtOp.execute(rawExec, rawLib, op);
			}
			else {
				// Nothing to do. CALLOTHER is logged and will be compiled later.
			}
		}

		@Override
		public boolean isFunctional() {
			return rtOp.isFunctional();
		}

		@Override
		public boolean hasSideEffects() {
			return rtOp.hasSideEffects();
		}

		@Override
		public boolean canInlinePcode() {
			return rtOp.canInlinePcode();
		}

		@Override
		public Method getJavaMethod() {
			return rtOp.getJavaMethod();
		}

		@Override
		public PcodeUseropLibrary<?> getDefiningLibrary() {
			return rtOp.getDefiningLibrary();
		}
	}

	/**
	 * Wrap the given userop library
	 * 
	 * @param rtLib the actual library provided by the user or emulator
	 */
	public DecoderUseropLibrary(PcodeUseropLibrary<byte[]> rtLib) {
		for (PcodeUseropDefinition<byte[]> opDef : rtLib.getUserops().values()) {
			if (ops.containsKey(opDef.getName())) {
				// Allow our annotations to override stuff in rtLib
				continue;
			}
			ops.put(opDef.getName(), new WrappedUseropDefinition(opDef));
		}
	}

	/**
	 * The replacement for {@link PcodeEmulationLibrary#emu_exec_decoded()}.
	 * 
	 * <p>
	 * The one built into the emulator would have the thread interpret the decoded instruction
	 * directly. While this might "work," it totally missed the purpose of JIT translation. We
	 * instead inline the userop's p-code into the rest of the passage. We accomplish this by having
	 * the decoder interpret the p-code instead. We also need to ensure the decoded instruction is
	 * added into the passage.
	 * 
	 * <p>
	 * Note that the {@link PcodeOp#CALLOTHER callother} op will be mapped to a {@link JitNopOp nop}
	 * during translation because we have set {@code canInline}.
	 * 
	 * @param executor the decoder's executor
	 */
	@PcodeUserop(canInline = true)
	public void emu_exec_decoded(@OpExecutor PcodeExecutor<Object> executor) {
		DecoderExecutor de = (DecoderExecutor) executor;
		PseudoInstruction instruction = de.decodeInstruction();
		de.addInstruction(instruction);
		PcodeProgram program = PcodeProgram.fromInstruction(instruction, false);
		de.execute(program);
	}

	/**
	 * The replacement for {@link PcodeEmulationLibrary#emu_skip_decoded()}.
	 * 
	 * <p>
	 * The one built into the emulator would have the thread drop and skip the decoded instruction
	 * directly. This would not have the intended effect, because the decoder is the thing that
	 * needs to skip and advance to the next address. We instead "inline" nothing, but we must still
	 * decode the instruction. Because the executor provides the decode routine, it can internally
	 * work out fall through. We will <em>not</em> add the instruction to the passage, though,
	 * because we will not have the executor interpret any of the instructon's p-code. As for fall
	 * through, the {@link DecoderExecutor#checkFallthroughAndAccumulate(PcodeProgram)} routine just
	 * does its usual. If the inject falls through, {@link DecoderExecutor#getAdvancedAddress()}
	 * considers the decoded instruction, even though it was never interpreted.
	 * 
	 * <p>
	 * Note that the {@link PcodeOp#CALLOTHER callother} op will still be mapped to a
	 * {@link JitNopOp nop} during translation because we have set {@code canInline}.
	 * 
	 * @param executor the decoder's executor
	 */
	@PcodeUserop(canInline = true)
	public void emu_skip_decoded(@OpExecutor PcodeExecutor<Object> executor) {
		DecoderExecutor de = (DecoderExecutor) executor;
		de.decodeInstruction();
	}
}
