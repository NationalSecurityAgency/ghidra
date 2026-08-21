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
package ghidra.pcode.emu.jit.op;

import ghidra.pcode.emu.jit.analysis.JitVarScopeModel;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A synthetic p-code operator use-def node.
 * 
 * <p>
 * Synthetic nodes do not correspond to a {@link PcodeOp} emitted in the actual decoded passage.
 * Instead, they are created as part of the data flow analysis. They are used by downstream
 * analyzers, but do not directly result in any emitted bytecode.
 * 
 * @see JitVarScopeModel
 */
public interface JitSyntheticOp extends JitOp {
	@Override
	default PcodeOp op() {
		throw new UnsupportedOperationException();
	}
}
