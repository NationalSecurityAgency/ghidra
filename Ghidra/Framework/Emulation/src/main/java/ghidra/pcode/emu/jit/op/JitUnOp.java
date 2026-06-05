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
 * A p-code operator use-def node with one input and one output.
 */
public interface JitUnOp extends JitDefOp {
	/**
	 * The use-def node for the input operand
	 * 
	 * @return the input
	 */
	JitVal u();

	@Override
	default void link() {
		JitDefOp.super.link();
		u().addUse(this, 0);
	}

	@Override
	default void unlink() {
		JitDefOp.super.unlink();
		u().removeUse(this, 0);
	}

	@Override
	default List<JitVal> inputs() {
		return List.of(u());
	}

	@Override
	default JitTypeBehavior typeFor(int position) {
		return switch (position) {
			case 0 -> uType();
			default -> throw new AssertionError();
		};
	}

	/**
	 * The required type behavior for the operand
	 * 
	 * @return the behavior
	 */
	JitTypeBehavior uType();
}
