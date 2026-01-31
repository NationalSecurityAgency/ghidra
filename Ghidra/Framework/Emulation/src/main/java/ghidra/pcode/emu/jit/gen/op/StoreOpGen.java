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

import java.util.List;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.FieldForSpaceIndirect;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.access.IntAccessGen;
import ghidra.pcode.emu.jit.gen.access.LongAccessGen;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitStoreOp;
import ghidra.program.model.lang.Endian;

/**
 * The generator for a {@link JitStoreOp store}.
 * 
 * <p>
 * These ops are currently presumed to be indirect memory accesses. <b>TODO</b>: If we fold
 * constants, we could convert some of these to direct.
 * 
 * <p>
 * We request a field to pre-fetch the {@link JitBytesPcodeExecutorStateSpace space} and emit code
 * to load it onto the stack. We then emit code to load the offset onto the stack and convert it to
 * a JVM long, if necessary. The varnode size is loaded by emitting an
 * {@link Op#ldc__i(Emitter, int) ldc}. We must now emit code to load the value and convert it to a
 * byte array. The conversion depends on the type of the value. Finally, we emit an invocation of
 * {@link JitBytesPcodeExecutorStateSpace#write(long, byte[], int, int)}.
 */
public enum StoreOpGen implements OpGen<JitStoreOp> {
	/** The generator singleton */
	GEN;

	/**
	 * Write an integer (often a leg) into a given byte array
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the source value on top
	 * @param em the emitter typed with the incoming stack
	 * @param localArr a handle to the local holding the destination array reference
	 * @param access the access generator for integers (determines the byte order)
	 * @param off the offset in the byte array to write the integer
	 * @param type the p-code type of the value to write
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	private <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<N1>
			genRunConvMpIntLeg(Emitter<N0> em, Local<TRef<byte[]>> localArr, IntAccessGen access,
					int off, IntJitType type) {
		return em
				.emit(Op::aload, localArr)
				.emit(Op::ldc__i, off)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, access.chooseWriteName(type.size()),
					MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::retVoid);
	}

	/**
	 * Write an integer into a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being written.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the source value on top
	 * @param em the emitter typed with the incoming stack
	 * @param localArr a handle to the local holding the destination array reference
	 * @param endian the byte order
	 * @param type the p-code type of the value to write
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	private <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<N1> genRunConvInt(Emitter<N0> em,
			Local<TRef<byte[]>> localArr, Endian endian, IntJitType type) {
		return em
				.emit(this::genRunConvMpIntLeg, localArr, IntAccessGen.forEndian(endian), 0, type);
	}

	/**
	 * Write a long into a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being written.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the source value on top
	 * @param em the emitter typed with the incoming stack
	 * @param localArr a handle to the local holding the destination array reference
	 * @param endian the byte order
	 * @param type the p-code type of the value to write
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	private <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<N1> genRunConvLong(Emitter<N0> em,
			Local<TRef<byte[]>> localArr, Endian endian, LongJitType type) {
		LongAccessGen access = LongAccessGen.forEndian(endian);
		return em
				.emit(Op::aload, localArr)
				.emit(Op::ldc__i, 0)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, access.chooseWriteName(type.size()),
					MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::retVoid);
	}

	/**
	 * Write a float into a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being written.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the source value on top
	 * @param em the emitter typed with the incoming stack
	 * @param localArr a handle to the local holding the destination array reference
	 * @param endian the byte order
	 * @param type the p-code type of the value to write
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	private <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<N1> genRunConvFloat(
			Emitter<N0> em, Local<TRef<byte[]>> localArr, Endian endian, FloatJitType type) {
		return em
				.emit(FloatToInt.INSTANCE::convertStackToStack, type, IntJitType.I4, Ext.ZERO)
				.emit(this::genRunConvInt, localArr, endian, IntJitType.I4);
	}

	/**
	 * Write a double into a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being written.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the source value on top
	 * @param em the emitter typed with the incoming stack
	 * @param localArr a handle to the local holding the destination array reference
	 * @param endian the byte order
	 * @param type the p-code type of the value to write
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	private <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<N1> genRunConvDouble(
			Emitter<N0> em, Local<TRef<byte[]>> localArr, Endian endian, DoubleJitType type) {
		return em
				.emit(DoubleToLong.INSTANCE::convertStackToStack, type, LongJitType.I8, Ext.ZERO)
				.emit(this::genRunConvLong, localArr, endian, LongJitType.I8);
	}

	/**
	 * The implementation of {@link #genRunConvMpInt(Emitter, Local, Endian, Opnd, Scope)} for
	 * big-endian order
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localArr a handle to the local holding the destination array reference
	 * @param opnd the source operand (list of locals and p-code type)
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the incoming stack
	 */
	private <N extends Next> Emitter<N> genRunConvMpIntBE(Emitter<N> em,
			Local<TRef<byte[]>> localArr, Opnd<MpIntJitType> opnd, Scope scope) {
		List<SimpleOpnd<TInt, IntJitType>> legs = opnd.type().castLegsLE(opnd);
		int off = opnd.type().size();
		for (SimpleOpnd<TInt, IntJitType> l : legs) {
			off -= l.type().size();
			em = em
					.emit(l::read)
					.emit(this::genRunConvMpIntLeg, localArr, IntAccessGen.BE, off, l.type());
		}
		return em;
	}

	/**
	 * The implementation of {@link #genRunConvMpInt(Emitter, Local, Endian, Opnd, Scope)} for
	 * little-endian order
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localArr a handle to the local holding the destination array reference
	 * @param opnd the source operand (list of locals and p-code type)
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the incoming stack
	 */
	private <N extends Next> Emitter<N> genRunConvMpIntLE(Emitter<N> em,
			Local<TRef<byte[]>> localArr, Opnd<MpIntJitType> opnd, Scope scope) {
		List<SimpleOpnd<TInt, IntJitType>> legs = opnd.type().castLegsLE(opnd);
		int off = 0;
		for (SimpleOpnd<TInt, IntJitType> l : legs) {
			em = em
					.emit(l::read)
					.emit(this::genRunConvMpIntLeg, localArr, IntAccessGen.LE, off, l.type());
			off += l.type().size();
		}
		return em;
	}

	/**
	 * Write a double into a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being written. The {@code endian}
	 * parameter indicates the byte order in the destination array. The source operand's legs are
	 * always in little-endian order.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localArr a handle to the local holding the destination array reference
	 * @param endian the byte order
	 * @param opnd the source operand (list of locals and p-code type)
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the incoming stack
	 */
	private <N extends Next> Emitter<N> genRunConvMpInt(Emitter<N> em, Local<TRef<byte[]>> localArr,
			Endian endian, Opnd<MpIntJitType> opnd, Scope scope) {
		return switch (endian) {
			case BIG -> genRunConvMpIntBE(em, localArr, opnd, scope);
			case LITTLE -> genRunConvMpIntLE(em, localArr, opnd, scope);
		};
	}

	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitStoreOp op, JitBlock block, Scope scope) {
		FieldForSpaceIndirect field = gen.requestFieldForSpaceIndirect(op.space());

		Local<TRef<byte[]>> localArr = scope.decl(Types.T_BYTE_ARR, "arr");
		var emSpaceOffset = em
				.emit(field::genLoad, localThis, gen)
				.emit(gen::genReadToStack, localThis, op.offset(), LongJitType.I8, Ext.ZERO)
				.emit(Op::ldc__i, op.value().size())
				.emit(Op::newarray, Types.T_BYTE)
				.emit(Op::astore, localArr);

		Endian endian = gen.getAnalysisContext().getEndian();
		var emConv = switch (gen.getTypeModel().typeOf(op.value())) {
			case IntJitType t -> emSpaceOffset
					.emit(gen::genReadToStack, localThis, op.value(), t, Ext.ZERO)
					.emit(this::genRunConvInt, localArr, endian, t);
			case LongJitType t -> emSpaceOffset
					.emit(gen::genReadToStack, localThis, op.value(), t, Ext.ZERO)
					.emit(this::genRunConvLong, localArr, endian, t);
			case MpIntJitType t -> {
				var value = emSpaceOffset
						.emit(gen::genReadToOpnd, localThis, op.value(), t, Ext.ZERO, scope);
				yield value.em()
						.emit(this::genRunConvMpInt, localArr, endian, value.opnd(), scope);
			}
			case FloatJitType t -> emSpaceOffset
					.emit(gen::genReadToStack, localThis, op.value(), t, Ext.ZERO)
					.emit(this::genRunConvFloat, localArr, endian, t);
			case DoubleJitType t -> emSpaceOffset
					.emit(gen::genReadToStack, localThis, op.value(), t, Ext.ZERO)
					.emit(this::genRunConvDouble, localArr, endian, t);
			default -> throw new AssertionError();
		};
		return new LiveOpResult(emConv
				.emit(Op::aload, localArr)
				.emit(Op::ldc__i, 0)
				.emit(Op::ldc__i, op.value().size())
				.emit(Op::invokevirtual, T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE, "write",
					MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__WRITE, false)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid));
	}
}
