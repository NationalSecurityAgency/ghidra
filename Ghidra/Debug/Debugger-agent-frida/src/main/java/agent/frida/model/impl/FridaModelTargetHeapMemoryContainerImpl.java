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

import java.util.concurrent.CompletableFuture;

import agent.frida.model.iface2.FridaModelTargetProcess;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "Memory",
	elementResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = FridaModelTargetMemoryRegionImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class FridaModelTargetHeapMemoryContainerImpl extends FridaModelTargetMemoryContainerImpl {

	public FridaModelTargetHeapMemoryContainerImpl(FridaModelTargetProcess process) {
		super(process, "Memory (Heap)");
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		return getManager().listHeapMemory(process.getProcess());
	}

}
