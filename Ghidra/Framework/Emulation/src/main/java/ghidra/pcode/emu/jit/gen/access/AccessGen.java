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
package ghidra.pcode.emu.jit.gen.access;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.FieldForArrDirect;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitLoadOp;
import ghidra.pcode.emu.jit.op.JitStoreOp;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * A generator to emit code that accesses variables of various size in a
 * {@link JitBytesPcodeExecutorState state}, for a specific type and byte order.
 * <p>
 * This is used by variable birthing and retirement as well as direct memory accesses. Dynamic
 * memory accesses, i.e., {@link JitStoreOp store} and {@link JitLoadOp load} do not use this,
 * though they may borrow some portions.
 * 
 * @param <JT> the JIT type of the operand
 */
public interface AccessGen<JT extends JitType> {

	/**
	 * Lookup the generator for accessing variables for the given type and byte order
	 * 
	 * @param endian the byte order
	 * @param type the p-code type of the variable
	 * @return the access generator
	 */
	@SuppressWarnings("unchecked")
	public static <T extends JitType> AccessGen<T> lookup(Endian endian, T type) {
		return (AccessGen<T>) switch (endian) {
			case BIG -> switch (type) {
				case IntJitType t -> IntAccessGen.BE;
				case LongJitType t -> LongAccessGen.BE;
				case FloatJitType t -> FloatAccessGen.BE;
				case DoubleJitType t -> DoubleAccessGen.BE;
				case MpIntJitType t -> MpIntAccessGen.BE;
				default -> throw new AssertionError();
			};
			case LITTLE -> switch (type) {
				case IntJitType t -> IntAccessGen.LE;
				case LongJitType t -> LongAccessGen.LE;
				case FloatJitType t -> FloatAccessGen.LE;
				case DoubleJitType t -> DoubleAccessGen.LE;
				case MpIntJitType t -> MpIntAccessGen.LE;
				default -> throw new AssertionError();
			};
		};
	}

	/**
	 * Lookup the generator for accessing variables of simple types and the given byte order
	 * 
	 * @param <T> the JVM type of the variable
	 * @param <JT> the p-code type of the variable
	 * @param endian the byte order
	 * @param type the p-code type of the variable
	 * @return the access generator
	 */
	@SuppressWarnings("unchecked")
	public static <T extends BPrim<?>, JT extends SimpleJitType<T, JT>> SimpleAccessGen<T, JT>
			lookupSimple(Endian endian, JT type) {
		return (SimpleAccessGen<T, JT>) switch (endian) {
			case BIG -> switch (type) {
				case IntJitType t -> IntAccessGen.BE;
				case LongJitType t -> LongAccessGen.BE;
				case FloatJitType t -> FloatAccessGen.BE;
				case DoubleJitType t -> DoubleAccessGen.BE;
				default -> throw new AssertionError();
			};
			case LITTLE -> switch (type) {
				case IntJitType t -> IntAccessGen.LE;
				case LongJitType t -> LongAccessGen.LE;
				case FloatJitType t -> FloatAccessGen.LE;
				case DoubleJitType t -> DoubleAccessGen.LE;
				default -> throw new AssertionError();
			};
		};
	}

	/**
	 * Lookup the generator for accessing variables of multi-precision integer type and the given
	 * byte order
	 * 
	 * @param endian the byte order
	 * @return the access generator
	 */
	public static MpIntAccessGen lookupMp(Endian endian) {
		return switch (endian) {
			case BIG -> MpIntAccessGen.BE;
			case LITTLE -> MpIntAccessGen.LE;
		};
	}

	/**
	 * Emit bytecode to read the given varnode onto the stack as a p-code bool (JVM int)
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param vn the varnode
	 * @return the emitter typed with the resulting stack, i.e., having pushed the value
	 */
	public static <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>>
			genReadToBool(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
					Varnode vn) {
		AddressSpace space = vn.getAddress().getAddressSpace();
		long offset = vn.getOffset();
		long block = offset / BLOCK_SIZE * BLOCK_SIZE;
		int off = (int) (offset - block);
		int size = vn.getSize();
		FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
		if (off + size < BLOCK_SIZE) {
			return em
					.emit(blkField::genLoad, localThis, gen)
					.emit(Op::ldc__i, off)
					.emit(Op::ldc__i, size)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, "readBoolN",
						MDESC_JIT_COMPILED_PASSAGE__READ_BOOL_N, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret);
		}
		FieldForArrDirect nxtField =
			gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
		return em
				.emit(blkField::genLoad, localThis, gen)
				.emit(Op::ldc__i, off)
				.emit(Op::ldc__i, BLOCK_SIZE - off)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, "readBoolN",
					MDESC_JIT_COMPILED_PASSAGE__READ_BOOL_N, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(nxtField::genLoad, localThis, gen)
				.emit(Op::ldc__i, 0)
				.emit(Op::ldc__i, off + size - BLOCK_SIZE)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, "readBoolN",
					MDESC_JIT_COMPILED_PASSAGE__READ_BOOL_N, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::ior);
	}
}
