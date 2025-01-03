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
package ghidra.pcode.emu.jit.gen.type;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;
import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.gen.FieldForArrDirect;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * Bytes writer for longs in big endian order.
 */
public enum LongWriteGen implements MethodAccessGen {
	/** The big-endian instance */
	BE {
		@Override
		public String chooseName(int size) {
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
		public void generateCode(JitCodeGenerator gen, Varnode vn, MethodVisitor rv) {
			long offset = vn.getOffset();
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int size = vn.getSize();
			AddressSpace space = vn.getAddress().getAddressSpace();
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				blkField.generateLoadCode(gen, rv);
				rv.visitLdcInsn(off);
				rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, chooseName(size),
					MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true);
				return;
			}

			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			rv.visitInsn(DUP2);
			rv.visitInsn(off + size - BLOCK_SIZE);
			rv.visitInsn(LUSHR);
			blkField.generateLoadCode(gen, rv);
			rv.visitLdcInsn(off);
			rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
				chooseName(BLOCK_SIZE - off),
				MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true);

			nxtField.generateLoadCode(gen, rv);
			rv.visitLdcInsn(0);
			rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
				chooseName(off + size - BLOCK_SIZE), MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true);
		}
	},
	/** The little-endian instance */
	LE {
		@Override
		public String chooseName(int size) {
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
		public void generateCode(JitCodeGenerator gen, Varnode vn, MethodVisitor rv) {
			long offset = vn.getOffset();
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int size = vn.getSize();
			AddressSpace space = vn.getAddress().getAddressSpace();
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				blkField.generateLoadCode(gen, rv);
				rv.visitLdcInsn(off);
				rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, chooseName(size),
					MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true);
				return;
			}

			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			rv.visitInsn(DUP2);
			rv.visitLdcInsn(BLOCK_SIZE - off);
			rv.visitInsn(LUSHR);
			nxtField.generateLoadCode(gen, rv);
			rv.visitLdcInsn(0);
			rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
				chooseName(off + size - BLOCK_SIZE), MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true);

			blkField.generateLoadCode(gen, rv);
			rv.visitLdcInsn(off);
			rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
				chooseName(BLOCK_SIZE - off),
				MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true);
		}
	}
}
