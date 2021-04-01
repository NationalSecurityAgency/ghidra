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
package ghidra.dbg.jdi.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.ModuleReference;

import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "Module",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "UID", type = Long.class, fixed = true),
		@TargetAttributeType(type = Object.class)
	})
public class JdiModelTargetModule extends JdiModelTargetObjectReference {

	public static String getUniqueId(ModuleReference module) {
		return module.name() == null ? "#" + module.hashCode() : module.name();
	}

	protected final ModuleReference module;

	///protected final JdiModelTargetSymbolContainer symbols;

	public JdiModelTargetModule(JdiModelTargetModuleContainer modules, ModuleReference module,
			boolean isElement) {
		super(modules, module, isElement);
		this.module = module;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getUniqueId(module) //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		return module == null ? super.getDisplay() : getUniqueId(module);
	}

}
