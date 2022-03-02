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

import agent.frida.manager.FridaSymbol;
import agent.frida.model.iface2.FridaModelTargetSymbol;
import agent.frida.model.methods.FridaModelTargetFunctionInterceptorImpl;
import agent.frida.model.methods.FridaModelTargetUnloadScriptImpl;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSymbol;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;

@TargetObjectSchemaInfo(
	name = "Symbol",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = TargetSymbol.NAMESPACE_ATTRIBUTE_NAME,
			type = FridaModelTargetSymbolContainerImpl.class),
		@TargetAttributeType(name = TargetObject.VALUE_ATTRIBUTE_NAME, type = Address.class),
		@TargetAttributeType(name = TargetSymbol.SIZE_ATTRIBUTE_NAME, type = long.class),
		@TargetAttributeType(name = "Name", type = String.class),
		@TargetAttributeType(name = "Size", type = long.class),
		@TargetAttributeType(name = "TypeId", type = int.class),
		@TargetAttributeType(name = "Tag", type = int.class),
		@TargetAttributeType(type = Object.class) })
public class FridaModelTargetSymbolImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetSymbol {
	protected static String indexSymbol(FridaSymbol symbol) {
		return symbol.getName();
	}

	protected static String keySymbol(FridaSymbol symbol) {
		return PathUtils.makeKey(indexSymbol(symbol));
	}

	protected final boolean constant;
	protected Address value;
	protected long size;
	private FridaModelTargetFunctionInterceptorImpl intercept;
	private FridaModelTargetUnloadScriptImpl unload;

	public FridaModelTargetSymbolImpl(FridaModelTargetSymbolContainerImpl symbols,
			FridaSymbol symbol) {
		super(symbols.getModel(), symbols, keySymbol(symbol), symbol, "Symbol");
		this.constant = false;
		try {
			this.value = symbols.getModel()
					.getAddressSpace("ram")
					.getAddress(symbol.getAddress());
		} catch (AddressFormatException e) {
			e.printStackTrace();
		}
		this.size = symbol.getSize();
		this.intercept = new FridaModelTargetFunctionInterceptorImpl(this);
		this.unload = new FridaModelTargetUnloadScriptImpl(this, intercept.getName());

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			NAMESPACE_ATTRIBUTE_NAME, symbols, //
			VALUE_ATTRIBUTE_NAME, value, //
			SIZE_ATTRIBUTE_NAME, size //
		), "Initialized");
		changeAttributes(List.of(), List.of(), Map.of( //
			"Name", symbol.getName(), //
			"Address", symbol.getAddress(), //
			"Size", size, //
			//"Module", symbol.getModule(), //
			"Type", symbol.getType(), //
			"IsGlobal", symbol.isGlobal(), //
			intercept.getName(), intercept, //
			unload.getName(), unload //
		), "Initialized");
		if (symbol.getSectionId() != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				"Section", symbol.getSectionId()//
			), "Initialized");
		}
	}

	public String getDescription(int level) {
		FridaSymbol symbol = (FridaSymbol) getModelObject();
		return symbol.getName();
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
