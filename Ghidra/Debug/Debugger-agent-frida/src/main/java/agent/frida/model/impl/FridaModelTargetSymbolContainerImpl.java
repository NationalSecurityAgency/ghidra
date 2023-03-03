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

import agent.frida.manager.FridaSymbol;
import agent.frida.model.iface2.FridaModelTargetSymbolContainer;
import agent.frida.model.methods.*;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "SymbolContainer",
	elements = {
		@TargetElementType(type = FridaModelTargetSymbolImpl.class) },
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Object.class) },
	canonicalContainer = true)
public class FridaModelTargetSymbolContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetSymbolContainer {

	protected final FridaModelTargetModuleImpl module;
	private FridaModelTargetSymbolFromAddressImpl fromAddr;
	private FridaModelTargetSymbolFromNameImpl fromName;
	private FridaModelTargetSymbolLoadImpl load;

	public FridaModelTargetSymbolContainerImpl(FridaModelTargetModuleImpl module) {
		super(module.getModel(), module, "Symbols", "SymbolContainer");
		this.module = module;
		
		this.fromAddr = new FridaModelTargetSymbolFromAddressImpl(this);
		this.fromName = new FridaModelTargetSymbolFromNameImpl(this);
		this.load = new FridaModelTargetSymbolLoadImpl(this);
		this.changeAttributes(List.of(), List.of( //
			fromAddr, //
			fromName, //
			load //
		), Map.of(), "Initialized");

	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		return getManager().listModuleSymbols(module.getModule()).thenAccept(byName -> {
			List<TargetObject> symbols;
			synchronized (this) {
				symbols = byName.values()
						.stream()
						.map(this::getTargetSymbol)
						.collect(Collectors.toList());
			}
			setElements(symbols, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized FridaModelTargetSymbolImpl getTargetSymbol(FridaSymbol symbol) {
		TargetObject targetObject = getMapObject(symbol);
		if (targetObject != null) {
			FridaModelTargetSymbolImpl targetSymbol = (FridaModelTargetSymbolImpl) targetObject;
			targetSymbol.setModelObject(symbol);
			return targetSymbol;
		}
		return new FridaModelTargetSymbolImpl(this, symbol);
	}
}
