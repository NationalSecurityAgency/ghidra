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
package ghidra.pcode.emu.jit.gen;

import static org.objectweb.asm.Opcodes.ATHROW;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A requested exception handler
 * 
 * <p>
 * When an exception occurs, we must retire all of the variables before we pop the
 * {@link JitCompiledPassage#run(int) run} method's frame. We also write out the program counter and
 * disassembly context so that the emulator can resume appropriately. After that, we re-throw the
 * exception.
 * 
 * <p>
 * When the code generator knows the code it's emitting can cause a user exception, e.g., the Direct
 * invocation of a userop, and there are live variables in scope, then it should request a handler
 * (via {@link JitCodeGenerator#requestExceptionHandler(DecodedPcodeOp, JitBlock)}) and surround the
 * code in a {@code try-catch} on {@link Throwable} directing it to this handler.
 * 
 * @param op the op which may cause an exception
 * @param block the block containing the op
 * @param label the label at the start of the handler
 */
public record ExceptionHandler(PcodeOp op, JitBlock block, Label label) {
	/**
	 * Construct a handler, generating a new label
	 * 
	 * @param op the op which may cause an exception
	 * @param block the block containing the op
	 */
	public ExceptionHandler(PcodeOp op, JitBlock block) {
		this(op, block, new Label());
	}

	/**
	 * Emit the handler's code into the {@link JitCompiledPassage#run(int) run} method.
	 * 
	 * @param gen the code generator
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	public void generateRunCode(JitCodeGenerator gen, MethodVisitor rv) {
		rv.visitLabel(label);
		// [exc]
		gen.generatePassageExit(block, () -> {
			rv.visitLdcInsn(gen.getAddressForOp(op).getOffset());
		}, gen.getExitContext(op), rv);
		// [exc]
		rv.visitInsn(ATHROW);
		// []
	}
}
