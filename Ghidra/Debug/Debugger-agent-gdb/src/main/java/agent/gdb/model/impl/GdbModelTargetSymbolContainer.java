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
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.impl.GdbMinimalSymbol;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetSymbolNamespace;
import ghidra.util.datastruct.WeakValueHashMap;

public class GdbModelTargetSymbolContainer
		extends DefaultTargetObject<GdbModelTargetSymbol, GdbModelTargetModule>
		implements TargetSymbolNamespace<GdbModelTargetSymbolContainer> {
	protected final GdbModelImpl impl;
	protected final GdbModelTargetModule module;

	protected final Map<String, GdbModelTargetSymbol> symbolsByName = new WeakValueHashMap<>();

	public GdbModelTargetSymbolContainer(GdbModelTargetModule module) {
		super(module.impl, module, "Symbols", "SymbolContainer");
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
			changeAttributes(List.of(), Map.of(
				UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED //
			), "Refreshed");
		});
	}

	protected synchronized GdbModelTargetSymbol getTargetSymbol(GdbMinimalSymbol symbol) {
		return symbolsByName.computeIfAbsent(symbol.getName(),
			n -> new GdbModelTargetSymbol(this, symbol));
	}
}
