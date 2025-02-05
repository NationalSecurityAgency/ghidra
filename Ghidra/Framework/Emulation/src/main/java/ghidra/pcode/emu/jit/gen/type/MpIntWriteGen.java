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

import static ghidra.pcode.emu.jit.gen.GenConsts.BLOCK_SIZE;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * The generator for writing multi-precision ints.
 */
public enum MpIntWriteGen implements MpTypedAccessGen {
	/** The big-endian instance */
	BE {
		@Override
		public IntWriteGen getLegGen() {
			return IntWriteGen.BE;
		}

		@Override
		public void generateCode(JitCodeGenerator gen, Varnode vn, MethodVisitor rv) {
			ExportsLegAccessGen legGen = getLegGen();

			// Stack semantics, so must work in reverse of read
			AddressSpace space = vn.getAddress().getAddressSpace();
			int countFull = vn.getSize() / Integer.BYTES;
			int remSize = vn.getSize() % Integer.BYTES;
			long offset = vn.getOffset() + vn.getSize();
			for (int i = 0; i < countFull; i++) {
				offset -= Integer.BYTES;
				long block = offset / BLOCK_SIZE * BLOCK_SIZE;
				int off = (int) (offset - block);
				legGen.generateMpCodeLeg(gen, space, block, off, Integer.BYTES, rv);
			}
			if (remSize > 0) {
				offset -= remSize;
				long block = offset / BLOCK_SIZE * BLOCK_SIZE;
				int off = (int) (offset - block);
				legGen.generateMpCodeLeg(gen, space, block, off, remSize, rv);
			}
		}
	},
	/** The little-endian instance */
	LE {
		@Override
		public IntWriteGen getLegGen() {
			return IntWriteGen.LE;
		}

		@Override
		public void generateCode(JitCodeGenerator gen, Varnode vn, MethodVisitor rv) {
			ExportsLegAccessGen legGen = getLegGen();

			// Stack semantics, so must work in reverse of read
			AddressSpace space = vn.getAddress().getAddressSpace();
			int countFull = vn.getSize() / Integer.BYTES;
			int remSize = vn.getSize() % Integer.BYTES;
			long offset = vn.getOffset();
			for (int i = 0; i < countFull; i++) {
				long block = offset / BLOCK_SIZE * BLOCK_SIZE;
				int off = (int) (offset - block);
				legGen.generateMpCodeLeg(gen, space, block, off, Integer.BYTES, rv);
				offset += Integer.BYTES;
			}
			if (remSize > 0) {
				long block = offset / BLOCK_SIZE * BLOCK_SIZE;
				int off = (int) (offset - block);
				legGen.generateMpCodeLeg(gen, space, block, off, remSize, rv);
				offset += remSize;
			}
		}
	};

	@Override
	public abstract IntWriteGen getLegGen();
}
