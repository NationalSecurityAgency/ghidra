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
package agent.gdb.model.impl;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.impl.GdbMinimalSymbol;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSymbolNamespace;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "SymbolContainer",
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class GdbModelTargetSymbolContainer
		extends DefaultTargetObject<GdbModelTargetSymbol, GdbModelTargetModule>
		implements TargetSymbolNamespace {
	public static final String NAME = "Symbols";

	protected final GdbModelImpl impl;
	protected final GdbModelTargetModule module;

	public GdbModelTargetSymbolContainer(GdbModelTargetModule module) {
		super(module.impl, module, NAME, "SymbolContainer");
		this.impl = module.impl;
		this.module = module;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return module.module.listMinimalSymbols().thenAccept(byName -> {
			List<GdbModelTargetSymbol> symbols;
			synchronized (this) {
				symbols = byName.values()
						.stream()
						.map(this::getTargetSymbol)
						.collect(Collectors.toList());
			}
			setElements(symbols, "Refreshed");
		});
	}

	protected synchronized GdbModelTargetSymbol getTargetSymbol(GdbMinimalSymbol symbol) {
		TargetObject modelObject = impl.getModelObject(symbol);
		if (modelObject != null) {
			return (GdbModelTargetSymbol) modelObject;
		}
		return new GdbModelTargetSymbol(this, symbol);
	}
}
