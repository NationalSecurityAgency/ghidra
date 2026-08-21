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

import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.gen.FieldForArrDirect;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TLong;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * Bytes writer for longs in big endian order.
 */
public enum LongAccessGen implements MethodAccessGen, SimpleAccessGen<TLong, LongJitType> {
	/** The big-endian instance */
	BE {
		@Override
		public String chooseReadName(int size) {
			return switch (size) {
				case 1 -> "readLong1";
				case 2 -> "readLongBE2";
				case 3 -> "readLongBE3";
				case 4 -> "readLongBE4";
				case 5 -> "readLongBE5";
				case 6 -> "readLongBE6";
				case 7 -> "readLongBE7";
				case 8 -> "readLongBE8";
				default -> throw new AssertionError();
			};
		}

		@Override
		public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TLong>>
				genReadToStack(Emitter<N> em, Local<TRef<THIS>> localThis,
						JitCodeGenerator<THIS> gen, Varnode vn) {
			long offset = vn.getOffset();
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int size = vn.getSize();
			AddressSpace space = vn.getAddress().getAddressSpace();
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				return em
						.emit(blkField::genLoad, localThis, gen)
						.emit(Op::ldc__i, off)
						.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
							chooseReadName(size),
							MDESC_JIT_COMPILED_PASSAGE__READ_LONGX, true)
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
						MDESC_JIT_COMPILED_PASSAGE__READ_LONGX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::ldc__i, off + size - BLOCK_SIZE)
					.emit(Op::lshl)
					.emit(nxtField::genLoad, localThis, gen)
					.emit(Op::ldc__i, 0)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseReadName(off + size - BLOCK_SIZE),
						MDESC_JIT_COMPILED_PASSAGE__READ_LONGX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::lor);
		}

		@Override
		public String chooseWriteName(int size) {
			return switch (size) {
				case 1 -> "writeLong1";
				case 2 -> "writeLongBE2";
				case 3 -> "writeLongBE3";
				case 4 -> "writeLongBE4";
				case 5 -> "writeLongBE5";
				case 6 -> "writeLongBE6";
				case 7 -> "writeLongBE7";
				case 8 -> "writeLongBE8";
				default -> throw new AssertionError();
			};
		}

		@Override
		public <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TLong>>
				Emitter<N1> genWriteFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
						JitCodeGenerator<THIS> gen, Varnode vn) {
			long offset = vn.getOffset();
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int size = vn.getSize();
			AddressSpace space = vn.getAddress().getAddressSpace();
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				return em
						.emit(blkField::genLoad, localThis, gen)
						.emit(Op::ldc__i, off)
						.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
							chooseWriteName(size),
							MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::retVoid);
			}
			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			return em
					.emit(Op::dup2__2)
					.emit(Op::ldc__i, off + size - BLOCK_SIZE)
					.emit(Op::lushr)
					.emit(blkField::genLoad, localThis, gen)
					.emit(Op::ldc__i, off)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseWriteName(BLOCK_SIZE - off),
						MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::retVoid)
					.emit(nxtField::genLoad, localThis, gen)
					.emit(Op::ldc__i, 0)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseWriteName(off + size - BLOCK_SIZE),
						MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true)
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
				case 1 -> "readLong1";
				case 2 -> "readLongLE2";
				case 3 -> "readLongLE3";
				case 4 -> "readLongLE4";
				case 5 -> "readLongLE5";
				case 6 -> "readLongLE6";
				case 7 -> "readLongLE7";
				case 8 -> "readLongLE8";
				default -> throw new AssertionError();
			};
		}

		@Override
		public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TLong>>
				genReadToStack(Emitter<N> em, Local<TRef<THIS>> localThis,
						JitCodeGenerator<THIS> gen, Varnode vn) {
			long offset = vn.getOffset();
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int size = vn.getSize();
			AddressSpace space = vn.getAddress().getAddressSpace();
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				return em
						.emit(blkField::genLoad, localThis, gen)
						.emit(Op::ldc__i, off)
						.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
							chooseReadName(size),
							MDESC_JIT_COMPILED_PASSAGE__READ_LONGX, true)
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
						MDESC_JIT_COMPILED_PASSAGE__READ_LONGX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(blkField::genLoad, localThis, gen)
					.emit(Op::ldc__i, off)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseReadName(BLOCK_SIZE - off),
						MDESC_JIT_COMPILED_PASSAGE__READ_LONGX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::lor);
		}

		@Override
		public String chooseWriteName(int size) {
			return switch (size) {
				case 1 -> "writeLong1";
				case 2 -> "writeLongLE2";
				case 3 -> "writeLongLE3";
				case 4 -> "writeLongLE4";
				case 5 -> "writeLongLE5";
				case 6 -> "writeLongLE6";
				case 7 -> "writeLongLE7";
				case 8 -> "writeLongLE8";
				default -> throw new AssertionError();
			};
		}

		@Override
		public <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TLong>>
				Emitter<N1> genWriteFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
						JitCodeGenerator<THIS> gen, Varnode vn) {
			long offset = vn.getOffset();
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int size = vn.getSize();
			AddressSpace space = vn.getAddress().getAddressSpace();
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				return em
						.emit(blkField::genLoad, localThis, gen)
						.emit(Op::ldc__i, off)
						.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
							chooseWriteName(size),
							MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::takeArg)
						.step(Inv::retVoid);
			}
			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			return em
					.emit(Op::dup2__2)
					.emit(Op::ldc__i, BLOCK_SIZE - off)
					.emit(Op::lushr)
					.emit(nxtField::genLoad, localThis, gen)
					.emit(Op::ldc__i, 0)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseWriteName(off + size - BLOCK_SIZE),
						MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::retVoid)
					.emit(blkField::genLoad, localThis, gen)
					.emit(Op::ldc__i, off)
					.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE,
						chooseWriteName(BLOCK_SIZE - off),
						MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::retVoid);
		}
	};

	/**
	 * Get the {@code long} access generator for the given byte order
	 * 
	 * @param endian the byte order
	 * @return the access generator
	 */
	public static LongAccessGen forEndian(Endian endian) {
		return switch (endian) {
			case BIG -> BE;
			case LITTLE -> LE;
		};
	}
}
