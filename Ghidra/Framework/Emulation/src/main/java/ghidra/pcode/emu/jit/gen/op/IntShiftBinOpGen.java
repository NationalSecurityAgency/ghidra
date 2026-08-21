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
import ghidra.pcode.emu.jit.gen.util.Methods.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitIntBinOp;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.emu.jit.var.JitVar;

/**
 * An extension for integer shift operators
 * 
 * <p>
 * This is just going to invoke one of the {@link JitCompiledPassage#intLeft(int, int)},
 * {@link JitCompiledPassage#intRight(int, int)}, {@link JitCompiledPassage#intSRight(int, int)}, or
 * one of their overloaded methods, depending on the operand types.
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface IntShiftBinOpGen<T extends JitIntBinOp> extends BinOpGen<T> {
	/**
	 * {@inheritDoc}
	 * <p>
	 * The shift amount is always treated unsigned.
	 */
	@Override
	default Ext rExt() {
		return Ext.ZERO;
	}

	/**
	 * The name of the static method in {@link JitCompiledPassage} to invoke
	 * 
	 * @return the name
	 */
	String methodName();

	/**
	 * The implementation when both operands are simple primitives
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <LT> the JVM type of the left operand
	 * @param <LJT> the p-code type of the left operand
	 * @param <RT> the JVM type of the right operand
	 * @param <RJT> the p-code type of the right operand
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param outVar the output operand
	 * @param outType the p-code type of the output value
	 * @param lVal the left operand
	 * @param lType the p-code type of the left operand
	 * @param rVal the right operand
	 * @param rType the p-code type of the right operand
	 * @param scope a scope for generating temporary local storage
	 * @param mdesc the descriptor of the (overloaded) method
	 * @return the emitter typed with the incoming stack
	 */
	default <THIS extends JitCompiledPassage, LT extends BPrim<?>,
		LJT extends SimpleJitType<LT, LJT>, RT extends BPrim<?>, RJT extends SimpleJitType<RT, RJT>,
		N extends Next> Emitter<N> genShiftPrimPrim(Emitter<N> em, Local<TRef<THIS>> localThis,
				JitCodeGenerator<THIS> gen, JitVar outVar, LJT outType, JitVal lVal, LJT lType,
				JitVal rVal, RJT rType, Scope scope, MthDesc<LT, Ent<Ent<Bot, LT>, RT>> mdesc) {
		return em
				.emit(gen::genReadToStack, localThis, lVal, lType, ext())
				.emit(gen::genReadToStack, localThis, rVal, rType, rExt())
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, methodName(), mdesc, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(gen::genWriteFromStack, localThis, outVar, outType, ext(), scope);
	}

	/**
	 * The implementation when the left operand is an mp-int and the right is a primitive
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <RT> the JVM type of the right operand
	 * @param <RJT> the p-code type of the right operand
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param outVar the output operand
	 * @param outType the p-code type of the output value
	 * @param lVal the left operand
	 * @param lType the p-code type of the left operand
	 * @param rVal the right operand
	 * @param rType the p-code type of the right operand
	 * @param scope a scope for generating temporary local storage
	 * @param mdesc the descriptor of the (overloaded) method
	 * @return the emitter typed with the incoming stack
	 */
	default <THIS extends JitCompiledPassage, RT extends BPrim<?>,
		RJT extends SimpleJitType<RT, RJT>, N extends Next> Emitter<N> genShiftMpPrim(Emitter<N> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitVar outVar,
				MpIntJitType outType, JitVal lVal, MpIntJitType lType, JitVal rVal, RJT rType,
				Scope scope,
				MthDesc<TVoid, Ent<Ent<Ent<Ent<Bot, TRef<int[]>>, TInt>, TRef<int[]>>, RT>> mdesc) {
		/**
		 * FIXME: We could avoid this array allocation by shifting in place, but then we'd still
		 * need to communicate the actual out size. Things are easy if the out size is smaller than
		 * the left-in size, but not so easy if larger. Or, maybe over-provision if larger....
		 */
		return em
				.emit(Op::ldc__i, outType.legsAlloc())
				.emit(Op::newarray, Types.T_INT)
				.emit(Op::dup)
				.emit(Op::ldc__i, outType.size())
				.emit(gen::genReadToArray, localThis, lVal, lType, ext(), scope, 0)
				.emit(gen::genReadToStack, localThis, rVal, rType, rExt())
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, methodName(), mdesc, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::retVoid)
				.emit(gen::genWriteFromArray, localThis, outVar, outType, ext(), scope);
	}

	/**
	 * The implementation when the left operand is a primitive and the right operand is an mp-int
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <LT> the JVM type of the left operand
	 * @param <LJT> the p-code type of the left operand
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param outVar the output operand
	 * @param outType the p-code type of the output value
	 * @param lVal the left operand
	 * @param lType the p-code type of the left operand
	 * @param rVal the right operand
	 * @param rType the p-code type of the right operand
	 * @param scope a scope for generating temporary local storage
	 * @param mdesc the descriptor of the (overloaded) method
	 * @return the emitter typed with the incoming stack
	 */
	default <THIS extends JitCompiledPassage, LT extends BPrim<?>,
		LJT extends SimpleJitType<LT, LJT>, N extends Next> Emitter<N> genShiftPrimMp(Emitter<N> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitVar outVar, LJT outType,
				JitVal lVal, LJT lType, JitVal rVal, MpIntJitType rType, Scope scope,
				MthDesc<LT, Ent<Ent<Bot, LT>, TRef<int[]>>> mdesc) {
		return em
				.emit(gen::genReadToStack, localThis, lVal, lType, ext())
				/**
				 * TODO: Generate code to detect shifts > lType size, then just invoke the signature
				 * with int shift amount?
				 */
				.emit(gen::genReadToArray, localThis, rVal, rType, rExt(), scope, 0)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, methodName(), mdesc, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(gen::genWriteFromStack, localThis, outVar, outType, ext(), scope);
	}

	/**
	 * The implementation when both operands are mp-ints
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param outVar the output operand
	 * @param outType the p-code type of the output value
	 * @param lVal the left operand
	 * @param lType the p-code type of the left operand
	 * @param rVal the right operand
	 * @param rType the p-code type of the right operand
	 * @param scope a scope for generating temporary local storage
	 * @param mdesc the descriptor of the (overloaded) method
	 * @return the emitter typed with the incoming stack
	 */
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genShiftMpMp(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitVar outVar,
			MpIntJitType outType, JitVal lVal, MpIntJitType lType, JitVal rVal, MpIntJitType rType,
			Scope scope, MthDesc<TVoid,
				Ent<Ent<Ent<Ent<Bot, TRef<int[]>>, TInt>, TRef<int[]>>, TRef<int[]>>> mdesc) {
		/**
		 * FIXME: We could avoid this array allocation by shifting in place, but then we'd still
		 * need to communicate the actual out size. Things are easy if the out size is smaller than
		 * the left-in size, but not so easy if larger. Or, maybe over-provision if larger....
		 */
		return em
				.emit(Op::ldc__i, outType.legsAlloc())
				.emit(Op::newarray, Types.T_INT)
				.emit(Op::dup)
				.emit(Op::ldc__i, outType.size())
				.emit(gen::genReadToArray, localThis, lVal, lType, ext(), scope, 0)
				/**
				 * TODO: Generate code to detect shifts > lType size, then just invoke the signature
				 * with int shift amount?
				 */
				.emit(gen::genReadToArray, localThis, rVal, rType, rExt(), scope, 0)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, methodName(), mdesc, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::retVoid)
				.emit(gen::genWriteFromArray, localThis, outVar, outType, ext(), scope);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This reduces the implementation to just the name of the method to invoke. This will select
	 * the JVM signature of the method based on the p-code operand types.
	 */
	@Override
	default <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, T op, JitBlock block, Scope scope) {
		JitType lType = gen.resolveType(op.l(), op.lType());
		JitType rType = gen.resolveType(op.r(), op.rType());
		return new LiveOpResult(switch (lType) {
			case IntJitType lt -> switch (rType) {
				case IntJitType rt -> genShiftPrimPrim(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_II);
				case LongJitType rt -> genShiftPrimPrim(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_IJ);
				case MpIntJitType rt -> genShiftPrimMp(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_IA);
				default -> throw new AssertionError();
			};
			case LongJitType lt -> switch (rType) {
				case IntJitType rt -> genShiftPrimPrim(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_JI);
				case LongJitType rt -> genShiftPrimPrim(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_JJ);
				case MpIntJitType rt -> genShiftPrimMp(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_JA);
				default -> throw new AssertionError();
			};
			case MpIntJitType lt -> switch (rType) {
				case IntJitType rt -> genShiftMpPrim(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_AI);
				case LongJitType rt -> genShiftMpPrim(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_AJ);
				case MpIntJitType rt -> genShiftMpMp(em, localThis, gen, op.out(), lt, op.l(),
					lt, op.r(), rt, scope, MDESC_$SHIFT_AA);
				default -> throw new AssertionError();
			};
			default -> throw new AssertionError();
		});
	}
}
