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

import ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A use-def node for a {@link PcodeOp#CALLOTHER}.
 * 
 * <p>
 * This requires the {@link #userop()} to exist. For the case of a missing userop, we use
 * {@link JitCallOtherMissingOp}.
 * 
 * <p>
 * <b>TODO</b>: We have several considerations remaining, esp., since we'd like to handle system
 * calls via userops efficiently:
 * 
 * <ol>
 * 
 * <li>There are more inputs than listed in the op itself. In fact, the invocation is just
 * {@code syscall()}. The actual inputs are at least {@code RAX} and whatever parameters that
 * specific syscall wants.</li>
 * 
 * <li>We'd like to be able to evaluate {@code RAX} statically.</li>
 * 
 * <li>We Might like to inject the p-code rather than trying to compile and run it separately. Then,
 * in the case of a syscall, the actual Java callback should have known inputs and outputs. Would
 * probably <em>not</em> want to embed a huge if-elseif tree for syscall numbers, though, which is
 * why we'd like to evaluate RAX ahead of time. What if we can't, though? My thought is to retire
 * all the variables and just interpret the syscall.</li>
 * 
 * </ol>
 */
public interface JitCallOtherOpIf extends JitOp {

	/**
	 * The userop definition.
	 * 
	 * @return the definition from the library
	 */
	PcodeUseropDefinition<Object> userop();

	/**
	 * The arguments to the userop.
	 * 
	 * @return the list of use-def value nodes
	 */
	List<JitVal> args();

	@Override
	default List<JitVal> inputs() {
		return args();
	}

	/**
	 * The type behavior for each parameter in the userop definition
	 * 
	 * <p>
	 * These should correspond to each argument (input).
	 * 
	 * @return the list of behaviors
	 */
	List<JitTypeBehavior> inputTypes();

	@Override
	default JitTypeBehavior typeFor(int position) {
		return inputTypes().get(position);
	}

	/**
	 * Get the captured data flow state at the call site.
	 * 
	 * @return the state
	 */
	MiniDFState dfState();

	@Override
	default boolean canBeRemoved() {
		return !userop().hasSideEffects();
	}

	@Override
	default void link() {
		for (int i = 0; i < args().size(); i++) {
			args().get(i).addUse(this, i);
		}
	}

	@Override
	default void unlink() {
		for (int i = 0; i < args().size(); i++) {
			args().get(i).removeUse(this, i);
		}
	}
}
