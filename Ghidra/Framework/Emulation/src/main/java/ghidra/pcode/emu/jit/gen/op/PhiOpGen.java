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
import ghidra.pcode.emu.jit.op.JitPhiOp;

/**
 * The generator for a {@link JitPhiOp phi}.
 * 
 * <p>
 * We emit nothing. This generator ought not to be invoked, anyway, but things may change. In the
 * meantime, the design is that we allocate a JVM local per varnode. Since phi nodes are meant to
 * track possible definitions of the <em>same</em> varnode, there is no need to a phi node to emit
 * any code. The value, whichever option it happens to be, is already in its local variable.
 * 
 * @see JitVarScopeModel
 */
public enum PhiOpGen implements OpGen<JitPhiOp> {
	/** The generator singleton */
	GEN;

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitPhiOp op, JitBlock block,
			MethodVisitor rv) {
	}
}
