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

import agent.frida.model.iface2.FridaModelTargetMemoryContainer;
import agent.frida.model.iface2.FridaModelTargetModuleContainer;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "DebugContainer",
	attributes = {
		@TargetAttributeType(
			name = "Modules",
			type = FridaModelTargetModuleContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Memory",
			type = FridaModelTargetMemoryContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class FridaModelTargetKernelImpl extends FridaModelTargetObjectImpl {

	protected final FridaModelTargetKernelMemoryContainerImpl memory;
	protected final FridaModelTargetKernelModuleContainerImpl modules;

	public FridaModelTargetKernelImpl(FridaModelTargetSessionImpl session) {
		super(session.getModel(), session, "Kernel", "Kernel");

		this.memory = new FridaModelTargetKernelMemoryContainerImpl(this);
		this.modules = new FridaModelTargetKernelModuleContainerImpl(this);

		changeAttributes(List.of(), List.of(  //
			memory,
			modules //
		), Map.of(
			"Base", session.getSession().getAttribute("kbase"), //
			"PageSize", session.getSession().getAttribute("kPageSize") //
		), "Initialized");
	}

	public FridaModelTargetMemoryContainer getMemory() {
		return memory;
	}

	public FridaModelTargetModuleContainer getModules() {
		return modules;
	}

}
