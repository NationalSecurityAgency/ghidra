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
package ghidra.pcode.emu.jit.gen.var;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitAllocationModel.VarHandler;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.var.JitLocalOutVar;

/**
 * The generator for a local variable that is defined within the passage.
 */
public enum LocalOutVarGen implements LocalVarGen<JitLocalOutVar> {
	/** Singleton */
	GEN;

	@Override
	public void generateVarWriteCode(JitCodeGenerator gen, JitLocalOutVar v, JitType type,
			MethodVisitor rv) {
		VarHandler handler = gen.getAllocationModel().getHandler(v);
		handler.generateStoreCode(gen, type, rv);
	}
}
