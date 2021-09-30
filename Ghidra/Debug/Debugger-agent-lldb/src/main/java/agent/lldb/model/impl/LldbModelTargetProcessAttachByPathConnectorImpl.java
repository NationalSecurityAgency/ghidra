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
package agent.lldb.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.lldb.model.iface2.LldbModelTargetConnector;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ProcessAttachByPathConnector",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class LldbModelTargetProcessAttachByPathConnectorImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetConnector {

	protected final LldbModelTargetConnectorContainerImpl connectors;
	protected final TargetParameterMap paramDescs;

	public LldbModelTargetProcessAttachByPathConnectorImpl(
			LldbModelTargetConnectorContainerImpl connectors,
			String name) {
		super(connectors.getModel(), connectors, name, name);
		this.connectors = connectors;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> setActive() {
		connectors.setDefaultConnector(this);
		return CompletableFuture.completedFuture(null);
	}

	protected Map<String, ParameterDescription<?>> computeParameters() {
		HashMap<String, ParameterDescription<?>> map =
			new LinkedHashMap<String, ParameterDescription<?>>();
		ParameterDescription<String> p0 = ParameterDescription.create(
			String.class, "Path", true, "", "Path", "path for the target process");
		map.put("Path", p0);
		ParameterDescription<Boolean> p1 = ParameterDescription.create(
			Boolean.class, "Exists", false, true, "Exists", "target process is running");
		map.put("Exists", p1);
		ParameterDescription<Boolean> p2 = ParameterDescription.create(
			Boolean.class, "Async", false, true, "Async", "connect asynchronously");
		map.put("Async", p2);
		return map;
	}

	@Override
	public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		String path1 = (String) args.get("Path");
		Boolean exists = (Boolean) args.get("Exists");
		Boolean async = (Boolean) args.get("Async");
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getManager().attach(path1, !exists, async).handle(seq::nextIgnore);
		}).finish().exceptionally((exc) -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}
}
