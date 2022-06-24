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

import agent.frida.manager.FridaThread;
import agent.frida.model.iface1.FridaModelTargetMethod;
import agent.frida.model.iface2.FridaModelTargetThreadContainer;
import agent.frida.model.impl.FridaModelTargetObjectImpl;
import agent.frida.model.impl.FridaModelTargetThreadImpl;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ThreadStalk",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class FridaModelTargetThreadStalkImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetMethod {
	
	protected final TargetParameterMap paramDescs;
	private boolean useCurrentThread;

	public FridaModelTargetThreadStalkImpl(FridaModelTargetThreadContainer threads) {
		super(threads.getModel(), threads, "stalk", "ThreadStalk");
		useCurrentThread = true;
		
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	public FridaModelTargetThreadStalkImpl(FridaModelTargetThreadImpl thread) {
		super(thread.getModel(), thread, "stalk", "ThreadStalk");
		useCurrentThread = false;
		
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	public String getTid() {
		Long tid = 0L;
		if (useCurrentThread) {
			FridaThread currentThread = getManager().getCurrentThread();
			if (currentThread != null) {	
				tid = currentThread.getTid();
			}
		} else {
			tid = ((FridaThread) getModelObject()).getTid();
		}
		return Long.toString(tid);
	}
	
	public Map<String, ParameterDescription<?>> computeParameters() {
		HashMap<String, ParameterDescription<?>> map =
			new HashMap<String, ParameterDescription<?>>();
		ParameterDescription<Boolean> e_calls = ParameterDescription.create(Boolean.class, "EventCall",
			true, true, "event=call", "CALL instruction");
		ParameterDescription<Boolean> e_ret = ParameterDescription.create(Boolean.class, "EventRet",
			true, false, "event=ret", "RET  instructions");
		ParameterDescription<Boolean> e_exec = ParameterDescription.create(Boolean.class, "EventExec",
			true, false, "event=exec", "all instructions (not recommended)");
		ParameterDescription<Boolean> e_block = ParameterDescription.create(Boolean.class, "EventBlock",
			true, false, "event=block", "block executed");
		ParameterDescription<Boolean> e_compile = ParameterDescription.create(Boolean.class, "EventCompile",
			true, false, "event=compile", "block compiled");
		ParameterDescription<String> onReceive = ParameterDescription.create(String.class, "OnReceive",
			false, "", "onRecv file", "JS file with onReceive implemenation");
		ParameterDescription<String> onCallSummary = ParameterDescription.create(String.class, "OnCallSummary",
			false, "", "onCall file", "JS file with onCallSummary implementation");
		ParameterDescription<String> name = ParameterDescription.create(String.class, "Name",
			false, "stalk", "name", "name for future unload");
		ParameterDescription<String> script = ParameterDescription.create(String.class, "Script",
			false, "", "script", "script to execute on result");
		map.put("EventCall", e_calls);
		map.put("EventRet", e_ret);
		map.put("EventExec", e_exec);
		map.put("EventBlock", e_block);
		map.put("EventCompile", e_compile);
		map.put("OnReceive", onReceive);
		map.put("OnCallSummary", onCallSummary);
		map.put("Name", name);
		map.put("Script", script);
		return map;
	}
	
	@Override
	public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
		getManager().stalkThread(getTid(), arguments);
		return CompletableFuture.completedFuture(null);
	}

}
