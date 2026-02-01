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
package ghidra.pcode.emu.jit.var;

import ghidra.pcode.emu.jit.op.JitPhiOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A p-code variable that is an input to a passage, i.e., there are reads possible before writes.
 * 
 * <p>
 * These only appear as options to a {@link JitPhiOp phi} node. They are very common, because any
 * block that is also a valid passage entry (which is most of them) can have an option that is
 * defined outside the passage. It may very well be the only option.
 * 
 * @implNote We delay creation of passage-input variables until inter-block analysis, because the
 *           variable must turn up missing (i.e., not be defined prior in the same block) before we
 *           can consider it might be a passage input. We thus create a {@link JitPhiOp phi} node
 *           for it and record the input as just one of many options. We had at one point
 *           "simplified" single-option phi nodes, which covered the case where the varnode is
 *           <em>certainly</em> a passage input, but we found it difficult in terms of bookkeeping.
 *           Also, because of our variable allocation strategy, such simplification offered no real
 *           value during code generation.
 */
public class JitInputVar extends AbstractJitVarnodeVar {
	/**
	 * Construct a variable.
	 * 
	 * @param varnode the varnode
	 * @see JitPhiOp#addInputOption()
	 */
	public JitInputVar(Varnode varnode) {
		super(-1, varnode);
	}
}
