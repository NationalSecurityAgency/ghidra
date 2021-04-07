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

import agent.gdb.manager.impl.GdbMinimalSymbol;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSymbol;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "Symbol",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetSymbol extends
		DefaultTargetObject<TargetObject, GdbModelTargetSymbolContainer> implements TargetSymbol {
	protected static String indexSymbol(GdbMinimalSymbol symbol) {
		return symbol.getName();
	}

	protected static String keySymbol(GdbMinimalSymbol symbol) {
		return PathUtils.makeKey(indexSymbol(symbol));
	}

	protected final boolean constant;
	protected final Address value;
	protected final long size;

	public GdbModelTargetSymbol(GdbModelTargetSymbolContainer symbols, GdbMinimalSymbol symbol) {
		super(symbols.impl, symbols, keySymbol(symbol), "Symbol");
		symbols.impl.addModelObject(symbol, this);
		this.constant = false;
		this.value = symbols.impl.space.getAddress(symbol.getAddress());
		this.size = 0;

		changeAttributes(List.of(), Map.of(
			NAMESPACE_ATTRIBUTE_NAME, symbols,
			// TODO: DATA_TYPE
			VALUE_ATTRIBUTE_NAME, value,
			SIZE_ATTRIBUTE_NAME, size,
			DISPLAY_ATTRIBUTE_NAME, symbol.getName()),
			"Initialized");
	}

	@Override
	public GdbModelTargetSymbolContainer getNamespace() {
		return parent;
	}

	@Override
	public boolean isConstant() {
		return constant;
	}

	@Override
	public Address getValue() {
		return value;
	}

	@Override
	public long getSize() {
		return size;
	}
}
