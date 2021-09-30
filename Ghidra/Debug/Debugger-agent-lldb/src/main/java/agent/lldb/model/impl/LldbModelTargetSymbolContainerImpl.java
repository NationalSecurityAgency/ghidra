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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.SBSymbol;
import agent.lldb.model.iface2.LldbModelTargetSymbolContainer;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "SymbolContainer",
	elements = {
		@TargetElementType(type = LldbModelTargetSymbolImpl.class) },
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class LldbModelTargetSymbolContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetSymbolContainer {

	protected final LldbModelTargetModuleImpl module;

	public LldbModelTargetSymbolContainerImpl(LldbModelTargetModuleImpl module) {
		super(module.getModel(), module, "Symbols", "SymbolContainer");
		this.module = module;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
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
	public synchronized LldbModelTargetSymbolImpl getTargetSymbol(SBSymbol symbol) {
		TargetObject targetObject = getMapObject(symbol);
		if (targetObject != null) {
			LldbModelTargetSymbolImpl targetSymbol = (LldbModelTargetSymbolImpl) targetObject;
			targetSymbol.setModelObject(symbol);
			return targetSymbol;
		}
		return new LldbModelTargetSymbolImpl(this, symbol);
	}
}
