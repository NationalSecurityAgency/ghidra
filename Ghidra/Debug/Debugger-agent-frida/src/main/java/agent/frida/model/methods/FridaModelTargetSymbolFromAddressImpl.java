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
import agent.frida.model.iface2.FridaModelTargetSymbolContainer;
import agent.frida.model.impl.FridaModelTargetObjectImpl;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "SymbolFromAddress",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class FridaModelTargetSymbolFromAddressImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetMethod {

	protected final TargetParameterMap paramDescs;

	public FridaModelTargetSymbolFromAddressImpl(FridaModelTargetSymbolContainer symbols) {
		super(symbols.getModel(), symbols, "fromAddress", "SymbolFromAddress");
		
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
		map.put("Address", address);
		return map;
	}
	
	@Override
	public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
		String addr = (String) arguments.get("Address");
		if (!addr.startsWith("0x")) {
			addr = "0x" + addr;
		}
		getManager().console("DebugSymbol.fromAddress(" + 
				"ptr(" + addr + "));");
		return CompletableFuture.completedFuture(null);
	}

}
