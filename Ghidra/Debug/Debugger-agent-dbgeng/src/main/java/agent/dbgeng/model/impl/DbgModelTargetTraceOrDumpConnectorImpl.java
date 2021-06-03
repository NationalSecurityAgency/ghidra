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
package agent.dbgeng.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.model.iface2.DbgModelTargetConnector;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "TraceOrDumpConnector",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class DbgModelTargetTraceOrDumpConnectorImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetConnector {

	protected final DbgModelTargetConnectorContainerImpl connectors;
	protected final TargetParameterMap paramDescs;

	public DbgModelTargetTraceOrDumpConnectorImpl(DbgModelTargetConnectorContainerImpl connectors,
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
		ParameterDescription<String> p1 = ParameterDescription.create(String.class, "CommandLine",
			true, ".opendump", "Cmd", "native loader command");
		ParameterDescription<String> p2 = ParameterDescription.create(String.class, "TraceOrDump",
			true, "", "File", "trace or dump to be loaded");
		map.put("CommandLine", p1);
		map.put("TraceOrDump", p2);
		return map;
	}

	@Override
	public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getManager().openFile(args).handle(seq::nextIgnore);
		}).finish().exceptionally((exc) -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}
}
