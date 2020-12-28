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
 * A container of register descriptions
 */
@DebuggerTargetObjectIface("RegisterContainer")
public interface TargetRegisterContainer<T extends TargetRegisterContainer<T>>
		extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetRegisterContainer<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetRegisterContainer.class;
	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<TargetRegisterContainer<?>> wclass = (Class) TargetRegisterContainer.class;

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
	 */
	default CompletableFuture<? extends Collection<? extends TargetRegister<?>>> getRegisters() {
		return DebugModelConventions.collectSuccessors(this, TargetRegister.tclass);
	}
}
