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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.frida.model.iface1.FridaModelTargetMethod;
import agent.frida.model.iface2.FridaModelTargetMemoryContainer;
import agent.frida.model.impl.FridaModelTargetObjectImpl;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "MemoryProtect",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class FridaModelTargetMemoryProtectImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetMethod {

	protected final TargetParameterMap paramDescs;
	private boolean kernel;

	public FridaModelTargetMemoryProtectImpl(FridaModelTargetMemoryContainer memory, boolean kernel) {
		super(memory.getModel(), memory, "protect", "MemoryProtect");
		this.kernel = kernel;
		
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
			4096L, "Size", "size to protect");
		ParameterDescription<String> protection = ParameterDescription.create(String.class, "Prot",
			true, "", "Protection", "e.g. r-x");
		map.put("Address", address);
		map.put("Size", size);
		map.put("Prot", protection);
		return map;
	}
	
	@Override
	public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
		String cmd = kernel ? "Kernel" : "Memory";
 		getManager().console(cmd + ".protect(" + 
				"ptr(0x" + arguments.get("Address") + "), " +
				arguments.get("Size") + ", " +
				"'" + arguments.get("Prot") + "');");
		return CompletableFuture.completedFuture(null);
	}

}
