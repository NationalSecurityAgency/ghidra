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

/**
 * The generator for reading integers.
 */
public enum IntReadGen implements MethodAccessGen, ExportsLegAccessGen {
	/** The big-endian instance */
	BE {
		@Override
		public String chooseName(int size) {
			return switch (size) {
				case 1 -> "readInt1";
				case 2 -> "readIntBE2";
				case 3 -> "readIntBE3";
				case 4 -> "readIntBE4";
				default -> throw new AssertionError();
			};
		}

		@Override
		public void generateMpCodeLeg(JitCodeGenerator gen, AddressSpace space, long block,
				int off, int size, MethodVisitor rv) {
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				blkField.generateLoadCode(gen, rv);
				rv.visitLdcInsn(off);
				rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, chooseName(size),
					MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true);
				return;
			}

			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			blkField.generateLoadCode(gen, rv);
			rv.visitLdcInsn(off);
			rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
				chooseName(BLOCK_SIZE - off),
				MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true);
			rv.visitLdcInsn(off + size - BLOCK_SIZE);
			rv.visitInsn(ISHL);

			nxtField.generateLoadCode(gen, rv);
			rv.visitLdcInsn(0);
			rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
				chooseName(off + size - BLOCK_SIZE), MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true);
			rv.visitInsn(IOR);
		}
	},
	/** The little-endian instance */
	LE {
		@Override
		public String chooseName(int size) {
			return switch (size) {
				case 1 -> "readInt1";
				case 2 -> "readIntLE2";
				case 3 -> "readIntLE3";
				case 4 -> "readIntLE4";
				default -> throw new AssertionError();
			};
		}

		@Override
		public void generateMpCodeLeg(JitCodeGenerator gen, AddressSpace space, long block,
				int off, int size, MethodVisitor rv) {
			FieldForArrDirect blkField = gen.requestFieldForArrDirect(space.getAddress(block));
			if (off + size <= BLOCK_SIZE) {
				blkField.generateLoadCode(gen, rv);
				rv.visitLdcInsn(off);
				rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, chooseName(size),
					MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true);
				return;
			}

			FieldForArrDirect nxtField =
				gen.requestFieldForArrDirect(space.getAddress(block + BLOCK_SIZE));
			nxtField.generateLoadCode(gen, rv);
			rv.visitLdcInsn(0);
			rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
				chooseName(off + size - BLOCK_SIZE), MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true);
			rv.visitLdcInsn(BLOCK_SIZE - off);
			rv.visitInsn(ISHL);

			blkField.generateLoadCode(gen, rv);
			rv.visitLdcInsn(off);
			rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
				chooseName(BLOCK_SIZE - off),
				MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true);
			rv.visitInsn(IOR);
		}
	}
}
