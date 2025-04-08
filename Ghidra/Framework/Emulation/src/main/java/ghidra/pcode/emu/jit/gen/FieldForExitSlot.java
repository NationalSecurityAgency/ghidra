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

import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.JitPassage.ExtBranch;
import ghidra.pcode.emu.jit.JitPcodeThread;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.InitFixedLocal;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.RunFixedLocal;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot;
import ghidra.program.model.lang.RegisterValue;

/**
 * A field request for an {@link ExitSlot}.
 * 
 * <p>
 * One of these is allocated per {@link ExtBranch#to()}. At run time, the first time a branch is
 * encountered from this passage to the given target, the slot calls
 * {@link JitPcodeThread#getEntry(AddrCtx) getEntry}{@code (target)} and keeps the reference. Each
 * subsequent encounter uses the kept reference. This reference is what gets returned by
 * {@link JitCompiledPassage#run(int)}, so now the thread already has in hand the next
 * {@link EntryPoint} to execute.
 * 
 * @param target the target address-contextreg pair of the branch exiting via this slot
 */
public record FieldForExitSlot(AddrCtx target) implements InstanceFieldReq {
	@Override
	public String name() {
		return "exit_%x_%s".formatted(target.address.getOffset(), target.biCtx.toString(16));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the target {@code (ram:00401234,ctx=80000000)}. The declaration is equivalent to:
	 * 
	 * <pre>
	 * private final {@link ExitSlot} exit_401234_80000000;
	 * </pre>
	 * 
	 * <p>
	 * And the initialization is equivalent to:
	 * 
	 * <pre>
	 * exit_401234_80000000 = {@link JitCompiledPassage#createExitSlot(long, RegisterValue) createExitSlot}(0x401234, CTX_80000000);
	 * </pre>
	 * 
	 * <p>
	 * Note that this method will ensure the {@code CTX_...} field is allocated and loads its value
	 * as needed.
	 */
	@Override
	public void generateInitCode(JitCodeGenerator gen, ClassVisitor cv, MethodVisitor iv) {
		FieldForContext ctxField = gen.requestStaticFieldForContext(target.rvCtx);
		cv.visitField(ACC_PRIVATE | ACC_FINAL, name(), TDESC_EXIT_SLOT, null, null);

		// []
		InitFixedLocal.THIS.generateLoadCode(iv);
		// [this]
		iv.visitInsn(DUP);
		// [this,this]
		iv.visitLdcInsn(target.address.getOffset());
		// [this,this,target:LONG]
		ctxField.generateLoadCode(gen, iv);
		// [this,this,target:LONG,ctx:RV]
		iv.visitMethodInsn(INVOKEINTERFACE, NAME_JIT_COMPILED_PASSAGE, "createExitSlot",
			MDESC_JIT_COMPILED_PASSAGE__CREATE_EXIT_SLOT, true);
		// [this,slot]
		iv.visitFieldInsn(PUTFIELD, gen.nameThis, name(), TDESC_EXIT_SLOT);
		// []
	}

	@Override
	public void generateLoadCode(JitCodeGenerator gen, MethodVisitor rv) {
		// []
		RunFixedLocal.THIS.generateLoadCode(rv);
		// [this]
		rv.visitFieldInsn(GETFIELD, gen.nameThis, name(), TDESC_EXIT_SLOT);
		// [slot]
	}
}
