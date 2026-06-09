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

import java.math.BigInteger;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitOpUseModel;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.gen.var.ValGen;
import ghidra.pcode.emu.jit.op.JitOp;
import ghidra.pcode.emu.jit.op.JitPhiOp;

/**
 * A p-code value use-def node.
 * 
 * <p>
 * For a table of value/variable node classes and generators, see {@link ValGen}.
 */
public interface JitVal {
	/**
	 * The use of a value node by an operator node.
	 * 
	 * @param op the operator node
	 * @param position the position of the operand in the operator's inputs
	 */
	record ValUse(JitOp op, int position) {
		public JitTypeBehavior type() {
			return op.typeFor(position);
		}
	}

	/**
	 * Create a constant value.
	 * 
	 * @param size the size in bytes
	 * @param value the value
	 * @return the value node
	 */
	static JitConstVal constant(int size, BigInteger value) {
		return new JitConstVal(size, value);
	}

	/**
	 * The size in bytes.
	 * 
	 * @return the size
	 */
	int size();

	/**
	 * The list of uses.
	 * 
	 * @return the uses
	 */
	List<ValUse> uses();

	/**
	 * Add a use.
	 * 
	 * <p>
	 * In most cases, uses should be final, once this value node has been entered into the use-def
	 * graph. An exception deals with {@link JitPhiOp phi} nodes, as this analysis occurs after each
	 * intra-block portion of the graph has been constructed. During inter-block analysis,
	 * additional uses will get recorded. Even further uses may be recorded uding
	 * {@link JitOpUseModel op-use} analysis, since it may generate more {@link JitPhiOp phi} nodes.
	 * 
	 * @param op the operator node using this one
	 * @param position the position of this value in the operator's input operands
	 */
	void addUse(JitOp op, int position);

	/**
	 * Remove a use.
	 * 
	 * @param op as in {@link #addUse(JitOp, int)}
	 * @param position as in {@link #addUse(JitOp, int)}
	 * @see #addUse(JitOp, int)
	 */
	void removeUse(JitOp op, int position);
}
