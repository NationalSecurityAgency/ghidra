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

import agent.frida.manager.FridaImport;
import agent.frida.model.iface2.FridaModelTargetImport;
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
	name = "Import",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(name = TargetObject.VALUE_ATTRIBUTE_NAME, type = Address.class),
		@TargetAttributeType(name = TargetSymbol.SIZE_ATTRIBUTE_NAME, type = long.class),
		@TargetAttributeType(name = "Name", type = String.class),
		@TargetAttributeType(name = "Address", type = Address.class),
		@TargetAttributeType(name = "Type", type = String.class),
		@TargetAttributeType(name = "Slot", type = String.class),
		@TargetAttributeType(type = Object.class) })
public class FridaModelTargetImportImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetImport {
	protected static String indexImport(FridaImport symbol) {
		return symbol.getName();
	}

	protected static String keyImport(FridaImport symbol) {
		return PathUtils.makeKey(indexImport(symbol));
	}

	protected final boolean constant;
	protected Address value;
	protected long size;
	protected String name;
	private FridaModelTargetFunctionInterceptorImpl intercept;
	private FridaModelTargetUnloadScriptImpl unload;

	public FridaModelTargetImportImpl(FridaModelTargetImportContainerImpl imports,
			FridaImport imp) {
		super(imports.getModel(), imports, keyImport(imp), imp, "Import");
		this.constant = false;
		try {
			this.value = imports.getModel()
					.getAddressSpace("ram")
					.getAddress(imp.getAddress());
		} catch (AddressFormatException e) {
			e.printStackTrace();
		}
		this.name = imp.getName();
		this.intercept = new FridaModelTargetFunctionInterceptorImpl(this);
		this.unload = new FridaModelTargetUnloadScriptImpl(this, intercept.getName());

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			VALUE_ATTRIBUTE_NAME, value, //
			"Address", value, //
			"Name", imp.getName(), //
			"Type", imp.getType(), //
			"Slot", imp.getSlot(), //
			intercept.getName(), intercept, //
			unload.getName(), unload //
		), "Initialized");
	}

	public String getDescription(int level) {
		FridaImport symbol = (FridaImport) getModelObject();
		return symbol.getName();
	}

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

	@Override
	public String getName() {
		return name;
	}
}
