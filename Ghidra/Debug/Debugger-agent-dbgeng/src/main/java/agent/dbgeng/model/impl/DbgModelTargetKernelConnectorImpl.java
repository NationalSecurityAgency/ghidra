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

import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.DbgModelTargetConnector;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "KernelConnector",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class DbgModelTargetKernelConnectorImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetConnector {

	protected final DbgModelTargetConnectorContainerImpl connectors;
	protected final TargetParameterMap paramDescs;

	public DbgModelTargetKernelConnectorImpl(DbgModelTargetConnectorContainerImpl connectors,
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
		ParameterDescription<Long> flags = ParameterDescription.create(Long.class, "Flags", true,
			0L, "Flags", "0=target 1=eXDI driver");
		ParameterDescription<String> options = ParameterDescription.create(String.class, "Options",
			true, "", "Options", "-k connection options");
		map.put("Flags", flags);
		map.put("Options", options);
		return map;
	}

	@Override
	public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			DbgManagerImpl manager = getManager();
			manager.addProcess();
			manager.attachKernel(args).handle(seq::nextIgnore);
		}).finish().exceptionally((exc) -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}
}
