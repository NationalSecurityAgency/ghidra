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

import agent.frida.manager.FridaExport;
import agent.frida.model.iface2.FridaModelTargetExport;
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
	name = "Export",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(name = TargetObject.VALUE_ATTRIBUTE_NAME, type = Address.class),
		@TargetAttributeType(name = TargetSymbol.SIZE_ATTRIBUTE_NAME, type = long.class),
		@TargetAttributeType(name = "Address", type = Address.class),
		@TargetAttributeType(name = "Name", type = String.class),
		@TargetAttributeType(name = "Type", type = String.class),
		@TargetAttributeType(type = Object.class) })
public class FridaModelTargetExportImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetExport {
	protected static String indexExport(FridaExport symbol) {
		return symbol.getName();
	}

	protected static String keyExport(FridaExport symbol) {
		return PathUtils.makeKey(indexExport(symbol));
	}

	protected final boolean constant;
	protected Address value;
	protected String name;
	private FridaModelTargetFunctionInterceptorImpl intercept;
	private FridaModelTargetUnloadScriptImpl unload;

	public FridaModelTargetExportImpl(FridaModelTargetExportContainerImpl exports,
			FridaExport export) {
		super(exports.getModel(), exports, keyExport(export), export, "Export");
		this.constant = false;
		try {
			this.value = exports.getModel()
					.getAddressSpace("ram")
					.getAddress(export.getAddress());
		} catch (AddressFormatException e) {
			e.printStackTrace();
		}
		this.name = export.getName();
		this.intercept = new FridaModelTargetFunctionInterceptorImpl(this);
		this.unload = new FridaModelTargetUnloadScriptImpl(this, intercept.getName());

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			VALUE_ATTRIBUTE_NAME, value, //
			"Address", value, //
			"Name", export.getName(), //
			"Type", export.getType(), //
			intercept.getName(), intercept, //
			unload.getName(), unload //
		), "Initialized");
	}

	public String getDescription(int level) {
		FridaExport symbol = (FridaExport) getModelObject();
		return symbol.getName();
	}

	@Override
	public Address getValue() {
		return value;
	}

	@Override
	public String getName() {
		return name;
	}
}
