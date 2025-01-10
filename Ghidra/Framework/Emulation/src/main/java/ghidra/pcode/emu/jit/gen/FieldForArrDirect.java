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
package ghidra.pcode.emu.jit.gen;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;
import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.program.model.address.Address;

/**
 * A field request for a pre-fetched page from the {@link JitBytesPcodeExecutorStateSpace}.
 * 
 * <p>
 * The field is used for direct memory accesses. For those, the address space and fixed address is
 * given in the p-code, so we are able to pre-fetch the page and access it directly at run time.
 * 
 * @param address the address contained by the page to pre-fetch
 */
public record FieldForArrDirect(Address address) implements InstanceFieldReq {
	@Override
	public String name() {
		return "arrDir_%s_%x".formatted(address.getAddressSpace().getName(),
			address.getOffset());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the address {@code ram:00600000}. The declaration is equivalent to:
	 * 
	 * <pre>
	 * private final byte[] arrDir_ram_600000;
	 * </pre>
	 * 
	 * <p>
	 * And the initialization is equivalent to:
	 * 
	 * <pre>
	 * arrDir_ram_600000 =
	 * 	state.getForSpace(ADDRESS_FACTORY.getAddressSpace(ramId)).getDirect(0x600000);
	 * </pre>
	 */
	@Override
	public void generateInitCode(JitCodeGenerator gen, ClassVisitor cv, MethodVisitor iv) {
		cv.visitField(ACC_PRIVATE | ACC_FINAL, name(), TDESC_BYTE_ARR, null, null);

		// [...]
		iv.visitVarInsn(ALOAD, 0);
		// [...,this]
		gen.generateLoadJitStateSpace(address.getAddressSpace(), iv);
		// [...,jitspace]
		iv.visitLdcInsn(address.getOffset());
		// [...,arr]
		iv.visitMethodInsn(INVOKEVIRTUAL, NAME_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE,
			"getDirect", MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__GET_DIRECT, false);
		iv.visitFieldInsn(PUTFIELD, gen.nameThis, name(), TDESC_BYTE_ARR);
		// [...]
	}

	@Override
	public void generateLoadCode(JitCodeGenerator gen, MethodVisitor rv) {
		// [...]
		rv.visitVarInsn(ALOAD, 0);
		// [...,this]
		rv.visitFieldInsn(GETFIELD, gen.nameThis, name(),
			TDESC_BYTE_ARR);
		// [...,arr]
	}
}
