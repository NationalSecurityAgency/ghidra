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

import java.util.List;
import java.util.Map;

import agent.dbgeng.model.iface2.DbgModelTargetConnector;
import agent.dbgeng.model.iface2.DbgModelTargetRoot;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ConnectorContainer",
	attributes = {
		@TargetAttributeType(
			name = "Launch process",
			type = DbgModelTargetProcessLaunchConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Attach to process",
			type = DbgModelTargetProcessAttachConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Load trace/dump",
			type = DbgModelTargetTraceOrDumpConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Attach to kernel",
			type = DbgModelTargetKernelConnectorImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class DbgModelTargetConnectorContainerImpl extends DbgModelTargetObjectImpl {

	protected final DbgModelTargetRoot root;

	private DbgModelTargetConnector defaultConnector;

	protected final DbgModelTargetProcessLaunchConnectorImpl processLauncher;
	protected final DbgModelTargetProcessAttachConnectorImpl processAttacher;
	protected final DbgModelTargetTraceOrDumpConnectorImpl traceLoader;
	protected final DbgModelTargetKernelConnectorImpl kernelAttacher;

	public DbgModelTargetConnectorContainerImpl(DbgModelTargetRoot root) {
		super(root.getModel(), root, "Connectors", "ConnectorsContainer");
		this.root = root;

		this.processLauncher = new DbgModelTargetProcessLaunchConnectorImpl(this, "Launch process");
		this.processAttacher =
			new DbgModelTargetProcessAttachConnectorImpl(this, "Attach to process");
		this.traceLoader = new DbgModelTargetTraceOrDumpConnectorImpl(this, "Load trace/dump");
		this.kernelAttacher = new DbgModelTargetKernelConnectorImpl(this, "Attach to kernel");
		this.defaultConnector = processLauncher;

		changeAttributes(List.of(), List.of( //
			processAttacher, //
			processLauncher, //
			traceLoader, //
			kernelAttacher //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, "Connectors" //
		), "Initialized");
	}

	public DbgModelTargetConnector getDefaultConnector() {
		return defaultConnector;
	}

	public void setDefaultConnector(DbgModelTargetConnector defaultConnector) {
		this.defaultConnector = defaultConnector;
		root.setDefaultConnector(defaultConnector);
	}

}
