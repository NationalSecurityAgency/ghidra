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
package ghidra.app.util.bin.format.golang.rtti.types;

import java.io.IOException;
import java.util.Set;

import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.app.util.viewer.field.AddressAnnotatedStringHandler;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;

/**
 * {@link GoType} structure that defines a pointer.
 */
@StructureMapping(structureName = {"runtime.ptrtype", "internal/abi.PtrType"})
public class GoPointerType extends GoType {
	@FieldMapping
	@MarkupReference("getElement")
	private long elem;

	public GoPointerType() {
		// empty
	}

	/**
	 * Returns a reference to the element's type.
	 * 
	 * @return reference to the element's type
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoType getElement() throws IOException {
		return programContext.getGoType(elem);
	}

	@Override
	public DataType recoverDataType() throws IOException {
		DataType elementDT = programContext.getRecoveredType(getElement());
		DataType self = programContext.getCachedRecoveredDataType(this);
		if (self != null) {
			return self;
		}
		return new PointerDataType(elementDT, programContext.getDTM());
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!super.discoverGoTypes(discoveredTypes)) {
			return false;
		}
		GoType element = getElement();
		if (element != null) {
			element.discoverGoTypes(discoveredTypes);
		}
		return true;
	}

	@Override
	public String getStructureNamespace() throws IOException {
		GoType elementType = getElement();
		return elementType != null
				? elementType.getStructureNamespace()
				: super.getStructureNamespace();
	}

	@Override
	protected String getTypeDeclString() throws IOException {
		// type PointerTypeName *elementType
		String selfName = getName();
		String elemName = programContext.getGoTypeName(elem);
		String defStr = "*" + elemName;
		String defStrWithLinks =
			"*" + AddressAnnotatedStringHandler.createAddressAnnotationString(elem, elemName);
		boolean hasName = !defStr.equals(selfName);
		return "type %s%s".formatted(hasName ? selfName + " " : "", defStrWithLinks);
	}

}
