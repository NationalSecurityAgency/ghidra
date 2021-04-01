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
import ghidra.dbg.target.schema.TargetObjectSchema;

/**
 * A container of register descriptions
 * 
 * <p>
 * TODO: Remove this. It really doesn't add anything that can't be discovered via the schema. A
 * client searching for a register (description) container should use
 * {@link TargetObjectSchema#searchForCanonicalContainer(Class)}, or discover the bank first, and
 * ask for its descriptions.
 */
@DebuggerTargetObjectIface("RegisterContainer")
public interface TargetRegisterContainer extends TargetObject {

	/**
	 * Get the register descriptions in this container
	 * 
	 * <p>
	 * While it is most common for registers to be immediate children of the container, that is not
	 * necessarily the case. In fact, some models may present sub-registers as children of another
	 * register. This method must return all registers (including sub-registers, if applicable) in
	 * the container.
	 * 
	 * @implNote By default, this method collects all successor registers ordered by path.
	 *           Overriding that behavior is not yet supported.
	 * @return the register descriptions
	 * @deprecated I don't think this has any actual utility.
	 */
	@Deprecated(forRemoval = true)
	default CompletableFuture<? extends Collection<? extends TargetRegister>> getRegisters() {
		return DebugModelConventions.collectSuccessors(this, TargetRegister.class);
	}
}
