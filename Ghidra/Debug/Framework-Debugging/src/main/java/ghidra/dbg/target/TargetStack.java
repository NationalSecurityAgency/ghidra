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
package ghidra.dbg.target;

import java.util.Collection;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerTargetObjectIface;

/**
 * Represents the execution stack, as unwound into frames by the debugger
 * 
 * <p>
 * Conventionally, if the debugger can also unwind register values, then each frame should present a
 * register bank. Otherwise, the same object presenting this stack should present the register bank.
 * 
 * <p>
 * TODO: Probably remove this. It serves only as a container of {@link TargetStackFrame}, which can
 * be discovered using the schema.
 */
@DebuggerTargetObjectIface("Stack")
public interface TargetStack extends TargetObject {

	/**
	 * Get the frames in this stack
	 * 
	 * <p>
	 * While it is most common for frames to be immediate children of the stack, that is not
	 * necessarily the case.
	 * 
	 * @implNote By default, this method collects all successor frames ordered by path. Overriding
	 *           that behavior is not yet supported.
	 * @return the stack frames
	 */
	default CompletableFuture<? extends Collection<? extends TargetStackFrame>> getFrames() {
		return DebugModelConventions.collectSuccessors(this, TargetStackFrame.class);
	}
}
