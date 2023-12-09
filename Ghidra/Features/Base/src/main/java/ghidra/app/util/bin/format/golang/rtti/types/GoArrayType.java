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
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;

/**
 * {@link GoType} structure that defines an array.
 */
@StructureMapping(structureName = "runtime.arraytype")
public class GoArrayType extends GoType {

	@FieldMapping
	@MarkupReference("getElement")
	private long elem;  // pointer to element type

	@FieldMapping
	@MarkupReference("getSliceType")
	private long slice;	// pointer to slice type

	@FieldMapping
	private long len;

	public GoArrayType() {
		// empty
	}

	/**
	 * Returns a reference to the {@link GoType} of the elements of this array.
	 *  
	 * @return reference to the {@link GoType} of the elements of this array
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoType getElement() throws IOException {
		return programContext.getGoType(elem);
	}

	/**
	 * Returns a reference to the {@link GoType} that defines the slice version of this array. 
	 * @return reference to the {@link GoType} that defines the slice version of this array
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoType getSliceType() throws IOException {
		return programContext.getGoType(slice);
	}

	@Override
	public DataType recoverDataType() throws IOException {
		DataType elementDt = programContext.getRecoveredType(getElement());
		DataType self = programContext.getCachedRecoveredDataType(this);
		if (self != null) {
			return self;
		}
		return new ArrayDataType(elementDt, (int) len, -1);
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!super.discoverGoTypes(discoveredTypes)) {
			return false;
		}
		GoType elementType = getElement();
		GoType sliceType = getSliceType();
		if (elementType != null) {
			elementType.discoverGoTypes(discoveredTypes);
		}
		if (sliceType != null) {
			sliceType.discoverGoTypes(discoveredTypes);
		}
		return true;
	}

	@Override
	public String getStructureNamespace() throws IOException {
		String packagePath = getPackagePathString();
		if (packagePath != null && !packagePath.isEmpty()) {
			return packagePath;
		}
		GoType elementType = getElement();
		if (elementType != null) {
			return elementType.getStructureNamespace();
		}
		return super.getStructureNamespace();
	}

	@Override
	protected String getTypeDeclString() throws IOException {
		// type CustomArraytype [elementcount]elementType
		String selfName = typ.getName();
		String elemName = programContext.getGoTypeName(elem);
		String arrayDefStr = "[%d]%s".formatted(len, elemName);
		String defStrWithLinks = "[%d]%s".formatted(len,
			AddressAnnotatedStringHandler.createAddressAnnotationString(elem, elemName));
		boolean hasName = !arrayDefStr.equals(selfName);

		return "type %s%s".formatted(hasName ? selfName + " " : "", defStrWithLinks);
	}

}
