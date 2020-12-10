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

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.lifecycle.Experimental;

/**
 * A place for modules to reside
 * 
 * Also a hint interface which helps the user of the client locate modules which apply to a given
 * target object
 * 
 * TODO: Experiment with the idea of "synthetic modules" as presented by {@code dbgeng.dll}. Is
 * there a similar idea in GDB? This could allow us to expose Ghidra's symbol table to the connected
 * debugger.
 */
@DebuggerTargetObjectIface("ModuleContainer")
public interface TargetModuleContainer<T extends TargetModuleContainer<T>>
		extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetModuleContainer<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetModuleContainer.class;

	String SUPPORTS_SYNTHETIC_MODULES_ATTRIBUTE_NAME =
		PREFIX_INVISIBLE + "supports_synthetic_modules";

	@Experimental
	public default boolean supportsSyntheticModules() {
		return getTypedAttributeNowByName(SUPPORTS_SYNTHETIC_MODULES_ATTRIBUTE_NAME, Boolean.class,
			false);
	}

	@Experimental
	public default CompletableFuture<? extends TargetModule<?>> addSyntheticModule(String name) {
		throw new UnsupportedOperationException();
	}
}
