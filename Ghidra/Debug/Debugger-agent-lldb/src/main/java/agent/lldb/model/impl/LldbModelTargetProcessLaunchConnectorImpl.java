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
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ProcessLaunchConnector",
	elements = { //
		@TargetElementType(type = Void.class) //
	},
	attributes = { //
		@TargetAttributeType(type = Void.class) //
	})
public class LldbModelTargetProcessLaunchConnectorImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetConnector {

	protected final LldbModelTargetConnectorContainerImpl connectors;
	protected final TargetParameterMap paramDescs;

	public LldbModelTargetProcessLaunchConnectorImpl(
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
			new HashMap<String, ParameterDescription<?>>();
		ParameterDescription<String> param = ParameterDescription.create(String.class, "args", true,
			"", "Cmd", "executable to be launched");
		map.put("args", param);
		return map;
	}

	@Override
	public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		return launch(
			CmdLineParser.tokenize(TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS.get(args)));
	}

	public CompletableFuture<Void> launch(List<String> args) {
		String fileName = args.get(0);
		List<String> nargs = new ArrayList<>();
		for (int i = 1; i < args.size(); i++) {
			nargs.add(args.get(i));
		}
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getManager().launch(fileName, nargs).handle(seq::nextIgnore);
		}).finish().exceptionally((exc) -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}
}
