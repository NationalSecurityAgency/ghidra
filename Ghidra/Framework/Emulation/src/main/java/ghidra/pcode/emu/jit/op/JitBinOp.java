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

import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.JitVal;

/**
 * A p-code operator use-def node with two inputs and one output.
 */
public interface JitBinOp extends JitDefOp {
	/**
	 * The use-def node for the left input operand
	 * 
	 * @return the input
	 */
	JitVal l();

	/**
	 * The use-def node for the right input operand
	 * 
	 * @return the input
	 */
	JitVal r();

	@Override
	default void link() {
		JitDefOp.super.link();
		l().addUse(this, 0);
		r().addUse(this, 1);
	}

	@Override
	default void unlink() {
		JitDefOp.super.unlink();
		l().removeUse(this, 0);
		r().removeUse(this, 1);
	}

	@Override
	default List<JitVal> inputs() {
		return List.of(l(), r());
	}

	/**
	 * The required type behavior for the left operand
	 * 
	 * @return the behavior
	 */
	JitTypeBehavior lType();

	/**
	 * The required type behavior for the right operand
	 * 
	 * @return the behavior
	 */
	JitTypeBehavior rType();

	@Override
	default JitTypeBehavior typeFor(int position) {
		return switch (position) {
			case 0 -> lType();
			case 1 -> rType();
			default -> throw new AssertionError();
		};
	}
}
