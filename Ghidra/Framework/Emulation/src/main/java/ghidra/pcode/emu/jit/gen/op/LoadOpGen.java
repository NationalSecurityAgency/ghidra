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

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.FieldForSpaceIndirect;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.access.IntAccessGen;
import ghidra.pcode.emu.jit.gen.access.LongAccessGen;
import ghidra.pcode.emu.jit.gen.opnd.*;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitLoadOp;
import ghidra.program.model.lang.Endian;

/**
 * The generator for a {@link JitLoadOp load}.
 * 
 * <p>
 * These ops are currently presumed to be indirect memory accesses. <b>TODO</b>: If we fold
 * constants, we could convert some of these to direct.
 * 
 * <p>
 * We request a field to pre-fetch the {@link JitBytesPcodeExecutorStateSpace space} and emit code
 * to load it onto the stack. We then emit code to load the offset onto the stack and convert it to
 * a JVM long, if necessary. The varnode size is loaded by emitting an
 * {@link Op#ldc__i(Emitter, int) ldc}, and finally we emit an invocation of
 * {@link JitBytesPcodeExecutorStateSpace#read(long, int)}. The result is a byte array, so we finish
 * by emitting the appropriate conversion and write the result to the output operand.
 */
public enum LoadOpGen implements OpGen<JitLoadOp> {
	/** The generator singleton */
	GEN;

	/**
	 * Read an integer (often a leg) from a given byte array
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with a ref to the byte array on top
	 * @param em the emitter typed with the incoming stack
	 * @param access the access generator for integers (determines the byte order)
	 * @param off the offset of the integer in the byte array
	 * @param type the p-code type of the value to read
	 * @return the emitter typed with the resulting stack, i.e., having popped the array ref and
	 *         pushed the result.
	 */
	private <N1 extends Next, N0 extends Ent<N1, TRef<byte[]>>> Emitter<Ent<N1, TInt>>
			genRunConvMpIntLeg(Emitter<N0> em, IntAccessGen access, int off, IntJitType type) {
		return em
				.emit(Op::ldc__i, off)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, access.chooseReadName(type.size()),
					MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}

	/**
	 * Read an integer from a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being read.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with a ref to the byte array on top
	 * @param em the emitter typed with the incoming stack
	 * @param endian the byte order
	 * @param type the p-code type of the value to read
	 * @return the emitter typed with the resulting stack, i.e., having popped the array ref and
	 *         pushed the result.
	 */
	private <N1 extends Next, N0 extends Ent<N1, TRef<byte[]>>> Emitter<Ent<N1, TInt>>
			genRunConvInt(Emitter<N0> em, Endian endian, IntJitType type) {
		return genRunConvMpIntLeg(em, IntAccessGen.forEndian(endian), 0, type);
	}

	/**
	 * Read a long from a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being read.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with a ref to the byte array on top
	 * @param em the emitter typed with the incoming stack
	 * @param endian the byte order
	 * @param type the p-code type of the value to read
	 * @return the emitter typed with the resulting stack, i.e., having popped the array ref and
	 *         pushed the result.
	 */
	private <N1 extends Next, N0 extends Ent<N1, TRef<byte[]>>> Emitter<Ent<N1, TLong>>
			genRunConvLong(Emitter<N0> em, Endian endian, LongJitType type) {
		LongAccessGen access = LongAccessGen.forEndian(endian);
		return em
				.emit(Op::ldc__i, 0)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, access.chooseReadName(type.size()),
					MDESC_JIT_COMPILED_PASSAGE__READ_LONGX, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}

	/**
	 * Read a float from a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being read.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with a ref to the byte array on top
	 * @param em the emitter typed with the incoming stack
	 * @param endian the byte order
	 * @param type the p-code type of the value to read
	 * @return the emitter typed with the resulting stack, i.e., having popped the array ref and
	 *         pushed the result.
	 */
	private <N1 extends Next, N0 extends Ent<N1, TRef<byte[]>>> Emitter<Ent<N1, TFloat>>
			genRunConvFloat(Emitter<N0> em, Endian endian, FloatJitType type) {
		return em
				.emit(this::genRunConvInt, endian, IntJitType.I4)
				.emit(IntToFloat.INSTANCE::convertStackToStack, IntJitType.I4, type, Ext.ZERO);
	}

	/**
	 * Read a double from a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being read.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with a ref to the byte array on top
	 * @param em the emitter typed with the incoming stack
	 * @param endian the byte order
	 * @param type the p-code type of the value to read
	 * @return the emitter typed with the resulting stack, i.e., having popped the array ref and
	 *         pushed the result.
	 */
	private <N1 extends Next, N0 extends Ent<N1, TRef<byte[]>>> Emitter<Ent<N1, TDouble>>
			genRunConvDouble(Emitter<N0> em, Endian endian, DoubleJitType type) {
		return em
				.emit(this::genRunConvLong, endian, LongJitType.I8)
				.emit(LongToDouble.INSTANCE::convertStackToStack, LongJitType.I4, type, Ext.ZERO);
	}

	/**
	 * The implementation of {@link #genRunConvMpInt(Emitter, Endian, MpIntJitType, String, Scope)}
	 * for big-endian order
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with a ref to the byte array on top
	 * @param em the emitter typed with the incoming stack
	 * @param type the p-code type of the value to read
	 * @param name the name prefix for the generated locals
	 * @param scope a scope for generating temporary local storage
	 * @return the operand containing the locals, and the emitter typed with the resulting stack,
	 *         i.e., having popped the array ref
	 */
	private <N1 extends Next, N0 extends Ent<N1, TRef<byte[]>>> OpndEm<MpIntJitType, N1>
			genRunConvMpIntBE(Emitter<N0> em, MpIntJitType type, String name, Scope scope) {
		Local<TRef<byte[]>> arr = scope.decl(Types.T_BYTE_ARR, "arr");
		var emStored = em
				.emit(Op::astore, arr);

		List<SimpleOpnd<TInt, IntJitType>> legs = new ArrayList<>();
		List<IntJitType> legTypes = type.legTypesLE();
		int off = 0;
		for (IntJitType lt : legTypes) {
			var leg = emStored
					.emit(Op::aload, arr)
					.emit(this::genRunConvMpIntLeg, IntAccessGen.BE, off, lt)
					.emit(Opnd::createInt, lt, "%s_off%d".formatted(name, off), scope);
			emStored = leg.em();
			legs.add(leg.opnd());
			off += lt.size();
		}
		return new OpndEm<>(MpIntLocalOpnd.of(type, name, legs), emStored);
	}

	/**
	 * The implementation of {@link #genRunConvMpInt(Emitter, Endian, MpIntJitType, String, Scope)}
	 * for little-endian order
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with a ref to the byte array on top
	 * @param em the emitter typed with the incoming stack
	 * @param type the p-code type of the value to read
	 * @param name the name prefix for the generated locals
	 * @param scope a scope for generating temporary local storage
	 * @return the operand containing the locals, and the emitter typed with the resulting stack,
	 *         i.e., having popped the array ref
	 */
	private <N1 extends Next, N0 extends Ent<N1, TRef<byte[]>>> OpndEm<MpIntJitType, N1>
			genRunConvMpIntLE(Emitter<N0> em, MpIntJitType type, String name, Scope scope) {
		Local<TRef<byte[]>> arr = scope.decl(Types.T_BYTE_ARR, "arr");
		var emStored = em
				.emit(Op::astore, arr);

		List<SimpleOpnd<TInt, IntJitType>> legs = new ArrayList<>();
		List<IntJitType> legTypes = type.legTypesLE();
		int off = type.size();
		for (IntJitType lt : legTypes) {
			off -= lt.size();
			var leg = emStored
					.emit(Op::aload, arr)
					.emit(this::genRunConvMpIntLeg, IntAccessGen.LE, off, lt)
					.emit(Opnd::createInt, lt, "%s_off%d".formatted(name, off), scope);
			emStored = leg.em();
			legs.add(leg.opnd());
		}
		return new OpndEm<>(MpIntLocalOpnd.of(type, name, legs), emStored);
	}

	/**
	 * Read a multi-precision integer from a given byte array
	 * <p>
	 * The byte array ought to exactly fit the type of the value being read. The {@code endian}
	 * parameter indicates the byte order in the source byte array. The resulting operand's legs are
	 * always in little-endian order.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with a ref to the byte array on top
	 * @param em the emitter typed with the incoming stack
	 * @param endian the byte order
	 * @param type the p-code type of the value to read
	 * @param name the name prefix for the generated locals
	 * @param scope a scope for generating temporary local storage
	 * @return the operand containing the locals, and the emitter typed with the resulting stack,
	 *         i.e., having popped the array ref
	 */
	private <N1 extends Next, N0 extends Ent<N1, TRef<byte[]>>> OpndEm<MpIntJitType, N1>
			genRunConvMpInt(Emitter<N0> em, Endian endian, MpIntJitType type, String name,
					Scope scope) {
		return switch (endian) {
			case BIG -> genRunConvMpIntBE(em, type, name, scope);
			case LITTLE -> genRunConvMpIntLE(em, type, name, scope);
		};
	}

	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitLoadOp op, JitBlock block, Scope scope) {
		FieldForSpaceIndirect field = gen.requestFieldForSpaceIndirect(op.space());

		var emArr = em
				.emit(field::genLoad, localThis, gen)
				.emit(gen::genReadToStack, localThis, op.offset(), LongJitType.I8, Ext.ZERO)
				.emit(Op::ldc__i, op.out().size())
				.emit(Op::invokevirtual, T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE, "read",
					MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__READ, false)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret);

		Endian endian = gen.getAnalysisContext().getEndian();
		em = switch (gen.getTypeModel().typeOf(op.out())) {
			case IntJitType t -> emArr
					.emit(this::genRunConvInt, endian, t)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			case LongJitType t -> emArr
					.emit(this::genRunConvLong, endian, t)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			case MpIntJitType t -> {
				var result = emArr
						.emit(this::genRunConvMpInt, endian, t, "load", scope);
				yield result.em()
						.emit(gen::genWriteFromOpnd, localThis, op.out(), result.opnd(), Ext.ZERO,
							scope);
			}
			case FloatJitType t -> emArr
					.emit(this::genRunConvFloat, endian, t)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			case DoubleJitType t -> emArr
					.emit(this::genRunConvDouble, endian, t)
					.emit(gen::genWriteFromStack, localThis, op.out(), t, Ext.ZERO, scope);
			default -> throw new AssertionError();
		};
		return new LiveOpResult(em);
	}
}
