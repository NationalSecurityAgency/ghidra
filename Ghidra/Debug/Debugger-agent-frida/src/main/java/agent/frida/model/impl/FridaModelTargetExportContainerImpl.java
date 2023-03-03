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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.frida.manager.FridaExport;
import agent.frida.model.iface2.FridaModelTargetExportContainer;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ExportContainer",
	elements = {
		@TargetElementType(type = FridaModelTargetExportImpl.class) },
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class FridaModelTargetExportContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetExportContainer {

	protected final FridaModelTargetModuleImpl module;

	public FridaModelTargetExportContainerImpl(FridaModelTargetModuleImpl module) {
		super(module.getModel(), module, "Exports", "ExportContainer");
		this.module = module;
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		return getManager().listModuleExports(module.getModule()).thenAccept(byName -> {
			List<TargetObject> symbols;
			synchronized (this) {
				symbols = byName.values()
						.stream()
						.map(this::getTargetExport)
						.collect(Collectors.toList());
			}
			setElements(symbols, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized FridaModelTargetExportImpl getTargetExport(FridaExport symbol) {
		TargetObject targetObject = getMapObject(symbol);
		if (targetObject != null) {
			FridaModelTargetExportImpl targetExport = (FridaModelTargetExportImpl) targetObject;
			targetExport.setModelObject(symbol);
			return targetExport;
		}
		return new FridaModelTargetExportImpl(this, symbol);
	}
}
