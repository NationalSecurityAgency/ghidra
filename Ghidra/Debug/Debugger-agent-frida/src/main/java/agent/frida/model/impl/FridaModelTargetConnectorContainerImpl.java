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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;

import agent.frida.model.iface2.FridaModelTargetConnector;
import agent.frida.model.iface2.FridaModelTargetRoot;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ConnectorContainer",
	attributes = {
		@TargetAttributeType(
			name = "Launch process",
			type = FridaModelTargetProcessLaunchConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Launch process w/ options",
			type = FridaModelTargetProcessLaunchWithOptionsConnectorImpl.class,
			required = false,
			fixed = true),
		@TargetAttributeType(
			name = "Attach to process by pid",
			type = FridaModelTargetProcessAttachByPidConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class FridaModelTargetConnectorContainerImpl extends FridaModelTargetObjectImpl {

	protected final FridaModelTargetRoot root;

	private FridaModelTargetConnector defaultConnector;

	protected final FridaModelTargetProcessLaunchConnectorImpl processLauncher;
	protected final FridaModelTargetProcessLaunchWithOptionsConnectorImpl processLauncherEx;
	protected final FridaModelTargetProcessAttachByPidConnectorImpl processAttacherByPid;

	public FridaModelTargetConnectorContainerImpl(FridaModelTargetRoot root) {
		super(root.getModel(), root, "Connectors", "ConnectorsContainer");
		this.root = root;

		this.processLauncher =
				new FridaModelTargetProcessLaunchConnectorImpl(this, "Launch process");
		this.processLauncherEx =
				new FridaModelTargetProcessLaunchWithOptionsConnectorImpl(this, "Launch process w/ options");
		this.processAttacherByPid =
			new FridaModelTargetProcessAttachByPidConnectorImpl(this, "Attach to process by pid");
		this.defaultConnector = processLauncher;

		changeAttributes(List.of(), List.of( //
			processAttacherByPid, //
			processLauncher, //
			processLauncherEx //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, "Connectors" //
		), "Initialized");
	}

	public FridaModelTargetConnector getDefaultConnector() {
		return defaultConnector;
	}

	public void setDefaultConnector(FridaModelTargetConnector defaultConnector) {
		this.defaultConnector = defaultConnector;
		root.setDefaultConnector(defaultConnector);
	}

}
