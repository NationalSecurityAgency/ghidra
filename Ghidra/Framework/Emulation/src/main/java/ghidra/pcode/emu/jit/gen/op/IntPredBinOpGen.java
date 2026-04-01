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

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitBinOp;

/**
 * An extension for integer operators whose outputs are boolean
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface IntPredBinOpGen<T extends JitBinOp> extends BinOpGen<T> {

	/**
	 * Emit the JVM bytecode to perform the operator with integer operands on the stack.
	 * 
	 * @param <N2> the tail of the incoming stack
	 * @param <N1> the tail of the incoming stack including the right operand
	 * @param <N0> the incoming stack with the right and left operands on top
	 * @param em the emitter typed with the incoming stack
	 * @param type the p-code type of the operands
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	<N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>> Emitter<Ent<N2, TInt>>
			opForInt(Emitter<N0> em, IntJitType type);

	/**
	 * An implementation for integer operands that delegates to a method on
	 * {@link JitCompiledPassage}
	 * 
	 * @param <N2> the tail of the incoming stack
	 * @param <N1> the tail of the incoming stack including the right operand
	 * @param <N0> the incoming stack with the right and left operands on top
	 * @param em the emitter typed with the incoming stack
	 * @param type the p-code type of the operands
	 * @param methodName the name of the method
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	default <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>>
			delegateIntFlagbit(Emitter<N0> em, IntJitType type, String methodName) {
		return em
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, methodName,
					MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_INT_RAW, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::ldc__i, type.size() * Byte.SIZE - 1)
				.emit(Op::ishr)
				// LATER: This mask may not be needed
				.emit(Op::ldc__i, 1)
				.emit(Op::iand);
	}

	/**
	 * Emit the JVM bytecode to perform the operator with long operands on the stack.
	 * 
	 * @param <N2> the tail of the incoming stack
	 * @param <N1> the tail of the incoming stack including the right operand
	 * @param <N0> the incoming stack with the right and left operands on top
	 * @param em the emitter typed with the incoming stack
	 * @param type the p-code type of the operands
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	<N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>> Emitter<Ent<N2, TInt>>
			opForLong(Emitter<N0> em, LongJitType type);

	/**
	 * An implementation for long operands that delegates to a method on {@link JitCompiledPassage}
	 * 
	 * @param <N2> the tail of the incoming stack
	 * @param <N1> the tail of the incoming stack including the right operand
	 * @param <N0> the incoming stack with the right and left operands on top
	 * @param em the emitter typed with the incoming stack
	 * @param type the p-code type of the operands
	 * @param methodName the name of the method
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	default <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TInt>>
			delegateLongFlagbit(Emitter<N0> em, LongJitType type, String methodName) {
		return em
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, methodName,
					MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_LONG_RAW, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::ldc__i, type.size() * Byte.SIZE - 1)
				.emit(Op::lshr)
				.emit(Op::l2i)
				// LATER: This mask may not be needed
				.emit(Op::ldc__i, 1)
				.emit(Op::iand);
	}

	/**
	 * Emit the JVM bytecode to perform the operator with multi-precision operands.
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param em the emitter typed with the empty stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param op the p-code op
	 * @param type the p-code type of the operands
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the resulting stack, i.e., containing only the result
	 */
	<THIS extends JitCompiledPassage> Emitter<Ent<Bot, TInt>> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, T op, MpIntJitType type,
			Scope scope);

	/**
	 * An implementation for multi-precision integer operands that delegates to a method on
	 * {@link JitCompiledPassage}
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param em the emitter typed with the empty stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param op the p-code op
	 * @param type the p-code type of the operands
	 * @param scope a scope for generating temporary local storage
	 * @param methodName the name of the method
	 * @return the emitter typed with the resulting stack, i.e., containing only the result
	 */
	default <THIS extends JitCompiledPassage> Emitter<Ent<Bot, TInt>> delegateMpIntFlagbit(
			Emitter<Bot> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, T op,
			MpIntJitType type, Scope scope, String methodName) {
		return em
				.emit(gen::genReadToArray, localThis, op.l(), type, ext(), scope, 0)
				.emit(gen::genReadToArray, localThis, op.r(), type, rExt(), scope, 0)
				.emit(Op::ldc__i, type.partialSize() * Byte.SIZE - 1)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, methodName,
					MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_MP_INT, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}

	@Override
	default <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, T op, JitBlock block, Scope scope) {
		JitType lType = gen.resolveType(op.l(), op.lType());
		JitType rType = gen.resolveType(op.r(), op.rType());
		JitType uType = JitType.unify(lType, rType);
		return new LiveOpResult(switch (uType) {
			case IntJitType t -> em
					.emit(gen::genReadToStack, localThis, op.l(), t, ext())
					.emit(gen::genReadToStack, localThis, op.r(), t, rExt())
					.emit(this::opForInt, t)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			case LongJitType t -> em
					.emit(gen::genReadToStack, localThis, op.l(), t, Ext.ZERO)
					.emit(gen::genReadToStack, localThis, op.r(), t, Ext.ZERO)
					.emit(this::opForLong, t)
					.emit(gen::genWriteFromStack, localThis, op.out(), IntJitType.I4, Ext.ZERO,
						scope);
			case MpIntJitType t -> em
					.emit(this::genRunMpInt, localThis, gen, op, t, scope)
					.emit(gen::genWriteFromStack, localThis, op.out(), IntJitType.I4, Ext.ZERO,
						scope);
			default -> throw new AssertionError();
		});
	}
}
