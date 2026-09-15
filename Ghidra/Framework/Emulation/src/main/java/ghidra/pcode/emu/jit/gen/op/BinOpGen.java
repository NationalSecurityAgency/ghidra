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

import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.GenConsts;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.op.JitBinOp;

/**
 * An extension that provides conveniences and common implementations for binary p-code operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface BinOpGen<T extends JitBinOp> extends OpGen<T> {

	/**
	 * A choice of static method parameter to take as operator output
	 */
	enum TakeOut {
		/**
		 * The out (first) parameter
		 */
		OUT,
		/**
		 * The left (second) parameter
		 */
		LEFT;
	}

	/**
	 * Emit bytecode that implements an mp-int binary operator via delegation to a static method on
	 * {@link JitCompiledPassage}. The method must have the signature:
	 * 
	 * <pre>
	 * void method(int[] out, int[] inL, int[] inR);
	 * </pre>
	 * 
	 * <p>
	 * This method presumes that the left operand's legs are at the top of the stack,
	 * least-significant leg on top, followed by the right operand legs, also least-significant leg
	 * on top. This will allocate the output array, move the operands into their respective input
	 * arrays, invoke the method, and then place the result legs on the stack, least-significant leg
	 * on top.
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param em the emitter typed with the empty stack
	 * @param gen the code generator
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param type the type of the operands
	 * @param methodName the name of the method in {@link JitCompiledPassage} to invoke
	 * @param op the p-code op
	 * @param slackLeft the number of extra ints to allocate for the left operand's array. This is
	 *            to facilitate Knuth's division algorithm, which may require an extra leading leg
	 *            in the dividend after normalization.
	 * @param takeOut indicates which operand of the static method to actually take for the output.
	 *            This is to facilitate the remainder operator, because Knuth's algorithm leaves the
	 *            remainder where there dividend was.
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the empty stack
	 */
	default <THIS extends JitCompiledPassage> Emitter<Bot> genMpDelegationToStaticMethod(
			Emitter<Bot> em, JitCodeGenerator<THIS> gen, Local<TRef<THIS>> localThis,
			MpIntJitType type, String methodName, JitBinOp op, int slackLeft, TakeOut takeOut,
			Scope scope) {
		/**
		 * The strategy here will be to allocate an array for each of the operands (output and 2
		 * inputs) and then invoke a static method to do the actual operation. It might be nice to
		 * generate inline code for small multiplications, but we're going to leave that for later.
		 */
		int legCount = type.legsAlloc();

		var emParams = switch (takeOut) {
			case OUT -> em
					.emit(Op::ldc__i, legCount)
					.emit(Op::newarray, Types.T_INT)
					.emit(Op::dup)
					.emit(gen::genReadToArray, localThis, op.l(), type, ext(), scope, slackLeft)
					.emit(gen::genReadToArray, localThis, op.r(), type, rExt(), scope, 0);
			case LEFT -> em
					.emit(Op::aconst_null, Types.T_INT_ARR)
					.emit(gen::genReadToArray, localThis, op.l(), type, ext(), scope, slackLeft)
					.emit(Op::dup_x1)
					.emit(gen::genReadToArray, localThis, op.r(), type, rExt(), scope, 0);
		};
		return emParams
				.emit(Op::invokestatic, GenConsts.T_JIT_COMPILED_PASSAGE, methodName,
					GenConsts.MDESC_JIT_COMPILED_PASSAGE__MP_INT_BINOP, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::retVoid)
				.emit(gen::genWriteFromArray, localThis, op.out(), type, ext(), scope);
	}

	/**
	 * Whether this operator is signed
	 * <p>
	 * In many cases, the operator itself is not affected by the signedness of the operands;
	 * however, if size adjustments to the operands are needed, this can determine how those
	 * operands are extended.
	 * 
	 * @return true for signed, false if not
	 */
	boolean isSigned();

	/**
	 * When loading and storing variables, the kind of extension to apply
	 * 
	 * @return the extension kind
	 */
	default Ext ext() {
		return Ext.forSigned(isSigned());
	}

	/**
	 * When loading the right operand, the kind of extension to apply
	 * 
	 * @return the extension kind
	 */
	default Ext rExt() {
		return ext();
	}
}
