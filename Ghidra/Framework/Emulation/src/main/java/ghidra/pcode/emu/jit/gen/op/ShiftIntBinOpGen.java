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

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.op.JitIntBinOp;

/**
 * An extension for integer shift operators
 * 
 * <p>
 * This is just going to invoke one of the {@link JitCompiledPassage#intLeft(int, int)},
 * {@link JitCompiledPassage#intRight(int, int)}, {@link JitCompiledPassage#intSRight(int, int)},
 * etc. methods, depending on the operand types.
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface ShiftIntBinOpGen<T extends JitIntBinOp> extends BinOpGen<T> {
	/**
	 * The name of the static method in {@link JitCompiledPassage} to invoke
	 * 
	 * @return the name
	 */
	String methodName();

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This reduces the implementation to just the name of the method to invoke. This will select
	 * the JVM signature of the method based on the p-code operand types.
	 */
	@Override
	default JitType generateBinOpRunCode(JitCodeGenerator gen, T op, JitBlock block, JitType lType,
			JitType rType, MethodVisitor rv) {
		String mdesc = switch (lType) {
			case IntJitType lt -> switch (rType) {
				case IntJitType rt -> MDESC_$SHIFT_II;
				case LongJitType rt -> MDESC_$SHIFT_IJ;
				default -> throw new AssertionError();
			};
			case LongJitType lt -> switch (rType) {
				case IntJitType rt -> MDESC_$SHIFT_JI;
				case LongJitType rt -> MDESC_$SHIFT_JJ;
				default -> throw new AssertionError();
			};
			default -> throw new AssertionError();
		};
		rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName(), mdesc, true);
		return lType.ext();
	}
}
