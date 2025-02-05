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
package ghidra.pcode.emu.jit.gen.op;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitIntZExtOp;

/**
 * The generator for a {@link JitIntZExtOp int_zext}.
 * 
 * <p>
 * This uses the unary operator generator and emits nothing extra. The unary generator template will
 * emit code to load the input operand, this emits nothing, and then the template emits code to
 * write the output operand, including the necessary type conversion. That type conversion performs
 * the zero extension.
 * 
 * <p>
 * Note that this implementation is equivalent to {@link CopyOpGen}, except that differences in
 * operand sizes are expected.
 */
public enum IntZExtOpGen implements UnOpGen<JitIntZExtOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitIntZExtOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		return uType;
	}
}
