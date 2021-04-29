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
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.lifecycle.Experimental;

/**
 * A place for modules to reside
 * 
 * <p>
 * Also a hint interface which helps the user of the client locate modules which apply to a given
 * target object
 * 
 * <p>
 * TODO: Experiment with the idea of "synthetic modules" as presented by {@code dbgeng.dll}. Is
 * there a similar idea in GDB? This could allow us to expose Ghidra's symbol table and types to the
 * native debugger.
 * 
 * <p>
 * TODO: Rename this to {@code TargetModuleOperations}. Conventionally, it is a container of
 * modules, but it doesn't technically have to be. If we don't eventually go forward with synthetic
 * modules, then we could remove this interface altogether. A client searching for the module
 * container should use {@link TargetObjectSchema#searchForCanonicalContainer(Class)}.
 */
@DebuggerTargetObjectIface("ModuleContainer")
public interface TargetModuleContainer extends TargetObject {

	String SUPPORTS_SYNTHETIC_MODULES_ATTRIBUTE_NAME =
		PREFIX_INVISIBLE + "supports_synthetic_modules";

	@TargetAttributeType(
		name = SUPPORTS_SYNTHETIC_MODULES_ATTRIBUTE_NAME,
		fixed = true,
		hidden = true)
	@Experimental
	public default boolean supportsSyntheticModules() {
		return getTypedAttributeNowByName(SUPPORTS_SYNTHETIC_MODULES_ATTRIBUTE_NAME, Boolean.class,
			false);
	}

	@Experimental
	public default CompletableFuture<? extends TargetModule> addSyntheticModule(String name) {
		throw new UnsupportedOperationException();
	}
}
