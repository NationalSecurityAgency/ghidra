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
import agent.frida.model.iface2.FridaModelTargetMemoryContainer;
import agent.frida.model.impl.FridaModelTargetObjectImpl;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "MemoryWatch",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class FridaModelTargetMemoryWatchImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetMethod {
	
	protected final TargetParameterMap paramDescs;

	public FridaModelTargetMemoryWatchImpl(FridaModelTargetMemoryContainer memory) {
		super(memory.getModel(), memory, "watch", "MemoryWatch");
		
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	protected Map<String, ParameterDescription<?>> computeParameters() {
		HashMap<String, ParameterDescription<?>> map =
			new HashMap<String, ParameterDescription<?>>();
		ParameterDescription<String> address = ParameterDescription.create(String.class, "Address",
			true, "", "Address", "starting address");
		ParameterDescription<Long> size = ParameterDescription.create(Long.class, "Size", true,
			1L, "Size", "size to scan");
		ParameterDescription<String> onAccess = ParameterDescription.create(String.class, "OnAccess",
			true, "", "onAccess file", "JS file with onAccess implemenation");
		ParameterDescription<String> name = ParameterDescription.create(String.class, "Name",
			false, "watch", "name", "name for future unload");
		ParameterDescription<String> script = ParameterDescription.create(String.class, "Script",
			false, "", "script", "script to execute on result");
		map.put("Address", address);
		map.put("Size", size);
		map.put("OnAccess", onAccess);
		map.put("Name", name);
		map.put("Script", script);
		return map;
	}
	
	@Override
	public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
		getManager().watchMemory(arguments);
		return CompletableFuture.completedFuture(null);
	}

}
