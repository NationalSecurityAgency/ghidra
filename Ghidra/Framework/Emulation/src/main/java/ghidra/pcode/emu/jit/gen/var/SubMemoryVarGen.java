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

import ghidra.pcode.emu.jit.analysis.JitDataFlowArithmetic;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.var.JitVarnodeVar;
import ghidra.program.model.pcode.Varnode;

/**
 * A generator for a subpiece of a memory variable
 * 
 * @param <V> the class of p-code variable node in the use-def graph
 */
public interface SubMemoryVarGen<V extends JitVarnodeVar> extends MemoryVarGen<V> {

	/**
	 * {@return} the number of bytes to the right of the subpiece
	 */
	int byteOffset();

	/**
	 * {@return the size of the subpiece}
	 */
	int maxByteSize();

	@Override
	default Varnode getVarnode(JitCodeGenerator<?> gen, V v) {
		Varnode parent = MemoryVarGen.super.getVarnode(gen, v);
		return JitDataFlowArithmetic.subPieceVn(gen.getAnalysisContext().getEndian(), parent,
			byteOffset(), maxByteSize());
	}

	@Override
	default ValGen<V> subpiece(int byteOffset, int maxByteSize) {
		throw new AssertionError("Who's subpiecing a subpiece?");
	}
}
