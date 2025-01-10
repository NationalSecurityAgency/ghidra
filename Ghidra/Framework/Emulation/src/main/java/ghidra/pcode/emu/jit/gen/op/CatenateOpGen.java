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
package ghidra.pcode.emu.jit.gen.op;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitVarScopeModel;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitCatenateOp;

/**
 * The generator for a {@link JitCatenateOp catenate}.
 * 
 * <p>
 * We emit nothing. This generator ought never to be invoked, anyway, but things may change. The
 * argument here is similar to that of {@link PhiOpGen}.
 * 
 * @see JitVarScopeModel
 */
public enum CatenateOpGen implements OpGen<JitCatenateOp> {
	/** The generator singleton */
	GEN;

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitCatenateOp op, JitBlock block,
			MethodVisitor rv) {
		throw new AssertionError("Cannnot generate synthetic op");
	}
}
