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

import SWIG.*;
import agent.lldb.model.iface2.LldbModelTargetSession;
import agent.lldb.model.iface2.LldbModelTargetSymbol;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSymbol;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "Symbol",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = TargetSymbol.NAMESPACE_ATTRIBUTE_NAME,
			type = LldbModelTargetSymbolContainerImpl.class),
		@TargetAttributeType(name = TargetObject.VALUE_ATTRIBUTE_NAME, type = Address.class),
		@TargetAttributeType(name = TargetSymbol.SIZE_ATTRIBUTE_NAME, type = long.class),
		@TargetAttributeType(name = "Name", type = String.class),
		@TargetAttributeType(name = "Size", type = long.class),
		@TargetAttributeType(name = "TypeId", type = int.class),
		@TargetAttributeType(name = "Tag", type = int.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetSymbolImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetSymbol {
	protected static String indexSymbol(SBSymbol symbol) {
		return symbol.GetName();
	}

	protected static String keySymbol(SBSymbol symbol) {
		return PathUtils.makeKey(indexSymbol(symbol));
	}

	protected final boolean constant;
	protected Address value;
	protected long size;

	public LldbModelTargetSymbolImpl(LldbModelTargetSymbolContainerImpl symbols,
			SBSymbol symbol) {
		super(symbols.getModel(), symbols, keySymbol(symbol), symbol, "Symbol");
		this.constant = false;
		LldbModelTargetSession session = this.getParentSession();
		SBTarget target = (SBTarget) session.getModelObject();
		this.value = symbols.getModel()
				.getAddressSpace("ram")
				.getAddress(symbol.GetStartAddress().GetLoadAddress(target).longValue());
		this.size = symbol.GetEndAddress()
				.GetOffset()
				.subtract(symbol.GetStartAddress().GetOffset())
				.longValue();

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			NAMESPACE_ATTRIBUTE_NAME, symbols, //
			VALUE_ATTRIBUTE_NAME, value, //
			SIZE_ATTRIBUTE_NAME, size //
		/*
		"Name", symbol.getName(), //
		"Size", size, //
		"TypeId", symbol.getTypeId(), //
		"Tag", symbol.getTag() //
		*/
		), "Initialized");
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBSymbol symbol = (SBSymbol) getModelObject();
		symbol.GetDescription(stream);
		return stream.GetData();
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
