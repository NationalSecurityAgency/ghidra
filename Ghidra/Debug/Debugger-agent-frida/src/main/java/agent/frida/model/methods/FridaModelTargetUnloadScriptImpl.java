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
package agent.frida.model.methods;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.frida.model.iface1.FridaModelTargetMethod;
import agent.frida.model.iface2.FridaModelTargetObject;
import agent.frida.model.impl.FridaModelTargetObjectImpl;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "UnloadScript",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class FridaModelTargetUnloadScriptImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetMethod {

	protected final TargetParameterMap paramDescs;
	private String target;

	public FridaModelTargetUnloadScriptImpl(FridaModelTargetObject object, String target) {
		super(object.getModel(), object, "unload", "UnloadScript");
		this.target = target;
		
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	protected Map<String, ParameterDescription<?>> computeParameters() {
		HashMap<String, ParameterDescription<?>> map =
			new HashMap<String, ParameterDescription<?>>();
		ParameterDescription<String> scriptName = ParameterDescription.create(String.class, "Name",
			true, target, "Script", "script to be unloaded");
		map.put("Name", scriptName);
		return map;
	}
	
	@Override
	public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
		getManager().unloadPermanentScript((String) arguments.get("Name"));
		return CompletableFuture.completedFuture(null);
	}

}
