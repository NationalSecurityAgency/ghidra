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
import agent.frida.model.impl.FridaModelTargetObjectImpl;
import agent.frida.model.impl.FridaModelTargetThreadContainerImpl;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ThreadSleep",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class FridaModelTargetThreadSleepImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetMethod {

	protected final TargetParameterMap paramDescs;

	public FridaModelTargetThreadSleepImpl(FridaModelTargetThreadContainerImpl threads) {
		super(threads.getModel(), threads, "sleep", "ThreadSleep");
		
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	protected Map<String, ParameterDescription<?>> computeParameters() {
		HashMap<String, ParameterDescription<?>> map =
			new HashMap<String, ParameterDescription<?>>();
		ParameterDescription<Long> fpath = ParameterDescription.create(Long.class, "Delay",
			true, 100L, "Delay", "sleep for current thread (seconds)");
		map.put("Delay", fpath);
		return map;
	}
	
	@Override
	public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
		getManager().console("Thread.sleep(" + 
				"'" + arguments.get("Delay") + "');");
		return CompletableFuture.completedFuture(null);
	}

}
