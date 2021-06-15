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
package ghidra.dbg.jdi.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.connect.Connector;
import com.sun.jdi.connect.Connector.Argument;

import ghidra.dbg.jdi.model.iface1.JdiModelSelectableObject;
import ghidra.dbg.jdi.model.iface1.JdiModelTargetLauncher;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "Connector",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(
			name = "Description",
			type = String.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Default Arguments",
			type = Object.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Transport",
			type = Object.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetConnector extends JdiModelTargetObjectImpl
		implements JdiModelSelectableObject,
		// TODO: Make a JidModelTargetLaunchingConnector and JdiModelTargetAttachingConnector
		JdiModelTargetLauncher {

	protected final JdiModelTargetConnectorContainer connectors;
	protected final Connector cx;
	protected final TargetParameterMap paramDescs;

	public JdiModelTargetConnector(JdiModelTargetConnectorContainer connectors, Connector cx,
			boolean isElement) {
		super(connectors, cx.name(), cx, isElement);
		this.connectors = connectors;
		this.cx = cx;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, cx.name(), //
			"Description", cx.description(), //
			"Default Arguments", cx.defaultArguments(), //
			"Transport", cx.transport(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		return cx == null ? super.getDisplay() : cx.name();
	}

	@Override
	public CompletableFuture<Void> setActive() {
		connectors.setDefaultConnector(this);
		return CompletableFuture.completedFuture(null);
	}

	protected Map<String, ParameterDescription<?>> computeParameters() {
		return JdiModelTargetLauncher.getParameters(cx.defaultArguments());
	}

	@Override
	public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		Map<String, Argument> jdiArgs =
			JdiModelTargetLauncher.getArguments(cx.defaultArguments(), paramDescs, args);
		return getManager().addVM(cx, jdiArgs).thenApply(__ -> null);
	}
}
