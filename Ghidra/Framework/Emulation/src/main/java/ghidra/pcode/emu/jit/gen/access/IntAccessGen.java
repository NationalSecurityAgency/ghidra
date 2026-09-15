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

import ghidra.pcode.emu.jit.gen.FieldForArrDirect;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Endian;

/**
 * The generator for writing integers.
 */
public enum IntAccessGen implements MethodAccessGen, ExportsLegAccessGen {
	/** The big-endian instance */
	BE {
		@Override
		public String chooseReadName(int size) {
			return switch (size) {
				case 1 -> "readInt1";
				case 2 -> "readIntBE2";
				case 3 -> "readIntBE3";
				case 4 -> "readIntBE4";
				default -> throw new AssertionError();
			};
		}

		@Override
		public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>>
				genReadLegToStack(Emitter<N> em, Local<TRef<THIS>> localThis,
						JitCodeGenerator<THIS> gen, AddressSpace space, long block, int off,
						int size) {
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				return em
						.emit(blkField::genLoad, localThis, gen)
						.emit(Op::ldc__i, off)
						.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
							chooseReadName(size),
							MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::ret);
			}
			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			return em
					.emit(blkField::genLoad, localThis, gen)
					.emit(Op::ldc__i, off)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseReadName(BLOCK_SIZE - off),
						MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::ldc__i, off + size - BLOCK_SIZE)
					.emit(Op::ishl)
					.emit(nxtField::genLoad, localThis, gen)
					.emit(Op::ldc__i, 0)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseReadName(off + size - BLOCK_SIZE),
						MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::ior);
		}

		@Override
		public String chooseWriteName(int size) {
			return switch (size) {
				case 1 -> "writeInt1";
				case 2 -> "writeIntBE2";
				case 3 -> "writeIntBE3";
				case 4 -> "writeIntBE4";
				default -> throw new AssertionError();
			};
		}

		@Override
		public <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TInt>>
				Emitter<N1> genWriteLegFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
						JitCodeGenerator<THIS> gen, AddressSpace space, long block, int off,
						int size) {
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				return em
						.emit(blkField::genLoad, localThis, gen)
						.emit(Op::ldc__i, off)
						.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
							chooseWriteName(size),
							MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::retVoid);
			}
			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			return em
					.emit(Op::dup)
					.emit(Op::ldc__i, off + size - BLOCK_SIZE)
					.emit(Op::iushr)
					.emit(blkField::genLoad, localThis, gen)
					.emit(Op::ldc__i, off)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseWriteName(BLOCK_SIZE - off),
						MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::retVoid)
					.emit(nxtField::genLoad, localThis, gen)
					.emit(Op::ldc__i, 0)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseWriteName(off + size - BLOCK_SIZE),
						MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::retVoid);
		}
	},
	/** The little-endian instance */
	LE {
		@Override
		public String chooseReadName(int size) {
			return switch (size) {
				case 1 -> "readInt1";
				case 2 -> "readIntLE2";
				case 3 -> "readIntLE3";
				case 4 -> "readIntLE4";
				default -> throw new AssertionError();
			};
		}

		@Override
		public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>>
				genReadLegToStack(Emitter<N> em, Local<TRef<THIS>> localThis,
						JitCodeGenerator<THIS> gen, AddressSpace space, long block, int off,
						int size) {
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				return em
						.emit(blkField::genLoad, localThis, gen)
						.emit(Op::ldc__i, off)
						.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
							chooseReadName(size),
							MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::ret);
			}
			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			return em
					.emit(nxtField::genLoad, localThis, gen)
					.emit(Op::ldc__i, 0)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseReadName(off + size - BLOCK_SIZE),
						MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(blkField::genLoad, localThis, gen)
					.emit(Op::ldc__i, off)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseReadName(BLOCK_SIZE - off),
						MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::ior);
		}

		@Override
		public String chooseWriteName(int size) {
			return switch (size) {
				case 1 -> "writeInt1";
				case 2 -> "writeIntLE2";
				case 3 -> "writeIntLE3";
				case 4 -> "writeIntLE4";
				default -> throw new AssertionError();
			};
		}

		@Override
		public <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TInt>>
				Emitter<N1> genWriteLegFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
						JitCodeGenerator<THIS> gen, AddressSpace space, long block, int off,
						int size) {
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				return em
						.emit(blkField::genLoad, localThis, gen)
						.emit(Op::ldc__i, off)
						.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
							chooseWriteName(size),
							MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::retVoid);
			}
			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			return em
					.emit(Op::dup)
					.emit(Op::ldc__i, BLOCK_SIZE - off)
					.emit(Op::iushr)
					.emit(nxtField::genLoad, localThis, gen)
					.emit(Op::ldc__i, 0)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseWriteName(off + size - BLOCK_SIZE),
						MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::retVoid)
					.emit(blkField::genLoad, localThis, gen)
					.emit(Op::ldc__i, off)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseWriteName(BLOCK_SIZE - off),
						MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::retVoid);
		}
	};

	/**
	 * Get the {@code int} access generator for the given byte order
	 * 
	 * @param endian the byte order
	 * @return the access generator
	 */
	public static IntAccessGen forEndian(Endian endian) {
		return switch (endian) {
			case BIG -> BE;
			case LITTLE -> LE;
		};
	}
}
