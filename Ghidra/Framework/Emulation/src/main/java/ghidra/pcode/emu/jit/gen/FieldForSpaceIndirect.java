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

import static ghidra.pcode.emu.jit.gen.GenConsts.TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE;
import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.InitFixedLocal;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.RunFixedLocal;
import ghidra.program.model.address.AddressSpace;

/**
 * A field request for a pre-fetched {@link JitBytesPcodeExecutorStateSpace}
 * 
 * <p>
 * The field is used for indirect memory accesses. For those, the address space is given in the
 * p-code, but the offset must be computed at run time. Thus, we can pre-fetch the state space, but
 * not any particular page.
 * 
 * @param space the address space of the state space to pre-fetch
 */
public record FieldForSpaceIndirect(AddressSpace space) implements InstanceFieldReq {
	@Override
	public String name() {
		return "spaceInd_" + space.getName();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the "ram" space. The declaration is equivalent to:
	 * 
	 * <pre>
	 * private final {@link JitBytesPcodeExecutorStateSpace} spaceInd_ram;
	 * </pre>
	 * 
	 * <p>
	 * And the initialization is equivalent to:
	 * 
	 * <pre>
	 * spaceInd_ram = state.getForSpace(ADDRESS_FACTORY.getAddressSpace(ramId));
	 * </pre>
	 */
	@Override
	public void generateInitCode(JitCodeGenerator gen, ClassVisitor cv, MethodVisitor iv) {
		cv.visitField(ACC_PRIVATE | ACC_FINAL, name(),
			TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE, null, null);

		// [...]
		InitFixedLocal.THIS.generateLoadCode(iv);
		// [...,this]
		gen.generateLoadJitStateSpace(space, iv);
		// [...,this,jitspace]
		iv.visitFieldInsn(PUTFIELD, gen.nameThis, name(),
			TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE);
		// [...]
	}

	@Override
	public void generateLoadCode(JitCodeGenerator gen, MethodVisitor rv) {
		// [...]
		RunFixedLocal.THIS.generateLoadCode(rv);
		// [...,this]
		rv.visitFieldInsn(GETFIELD, gen.nameThis, name(),
			TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE);
		// [...,jitspace]
	}
}
