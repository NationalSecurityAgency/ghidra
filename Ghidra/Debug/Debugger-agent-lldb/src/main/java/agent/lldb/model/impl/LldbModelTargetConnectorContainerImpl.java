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

import java.util.List;
import java.util.Map;

import agent.lldb.model.iface2.LldbModelTargetConnector;
import agent.lldb.model.iface2.LldbModelTargetRoot;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ConnectorContainer",
	attributes = {
		@TargetAttributeType(
			name = "Launch process",
			type = LldbModelTargetProcessLaunchConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Launch process w/ options",
			type = LldbModelTargetProcessLaunchWithOptionsConnectorImpl.class,
			required = false,
			fixed = true),
		@TargetAttributeType(
			name = "Attach to process by pid",
			type = LldbModelTargetProcessAttachByPidConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Attach to process by name",
			type = LldbModelTargetProcessAttachByNameConnectorImpl.class,
			required = false,
			fixed = true),
		@TargetAttributeType(
			name = "Attach to process by path",
			type = LldbModelTargetProcessAttachByPathConnectorImpl.class,
			required = false,
			fixed = true),
		@TargetAttributeType(
			name = "Load trace/dump",
			type = LldbModelTargetTraceOrDumpConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Attach to kernel",
			type = LldbModelTargetKernelConnectorImpl.class,
			required = false,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class LldbModelTargetConnectorContainerImpl extends LldbModelTargetObjectImpl {

	protected final LldbModelTargetRoot root;

	private LldbModelTargetConnector defaultConnector;

	protected final LldbModelTargetProcessLaunchConnectorImpl processLauncher;
	protected final LldbModelTargetProcessLaunchWithOptionsConnectorImpl processLauncherEx;
	protected final LldbModelTargetProcessAttachByPidConnectorImpl processAttacherByPid;
	protected final LldbModelTargetProcessAttachByNameConnectorImpl processAttacherByName;
	protected final LldbModelTargetProcessAttachByPathConnectorImpl processAttacherByPath;
	protected final LldbModelTargetTraceOrDumpConnectorImpl traceLoader;
	protected final LldbModelTargetKernelConnectorImpl kernelAttacher;

	public LldbModelTargetConnectorContainerImpl(LldbModelTargetRoot root) {
		super(root.getModel(), root, "Connectors", "ConnectorsContainer");
		this.root = root;

		this.processLauncher =
				new LldbModelTargetProcessLaunchConnectorImpl(this, "Launch process");
		this.processLauncherEx =
				new LldbModelTargetProcessLaunchWithOptionsConnectorImpl(this, "Launch process w/ options");
		this.processAttacherByPid =
			new LldbModelTargetProcessAttachByPidConnectorImpl(this, "Attach to process by pid");
		this.processAttacherByName =
			new LldbModelTargetProcessAttachByNameConnectorImpl(this, "Attach to process by name");
		this.processAttacherByPath =
			new LldbModelTargetProcessAttachByPathConnectorImpl(this, "Attach to process by path");
		this.traceLoader = new LldbModelTargetTraceOrDumpConnectorImpl(this, "Load trace/dump");
		this.kernelAttacher = new LldbModelTargetKernelConnectorImpl(this, "Attach to kernel");
		this.defaultConnector = processLauncher;

		changeAttributes(List.of(), List.of( //
			processAttacherByPid, //
			processAttacherByName, //
			processAttacherByPath, //
			processLauncher, //
			processLauncherEx, //
			traceLoader //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, "Connectors" //
		), "Initialized");
	}

	public LldbModelTargetConnector getDefaultConnector() {
		return defaultConnector;
	}

	public void setDefaultConnector(LldbModelTargetConnector defaultConnector) {
		this.defaultConnector = defaultConnector;
		root.setDefaultConnector(defaultConnector);
	}

}
