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

import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.app.util.viewer.field.AddressAnnotatedStringHandler;
import ghidra.program.model.data.*;

/**
 * Golang type information about a specific slice type.
 * <p>
 * See {@link GoRttiMapper#getGenericSliceDT()} or the "runtime.slice" type for the definition of
 * a instance of a slice variable in memory. 
*/
@StructureMapping(structureName = "runtime.slicetype")
public class GoSliceType extends GoType {

	@FieldMapping
	@MarkupReference("getElement")
	private long elem;

	public GoSliceType() {
		// empty
	}

	/**
	 * Returns a reference to the element's type.
	 * @return reference to the element's type
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoType getElement() throws IOException {
		return programContext.getGoType(elem);
	}

	@Override
	public DataType recoverDataType() throws IOException {
		Structure genericSliceDT = programContext.getGenericSliceDT();

		StructureDataType sliceDT =
			new StructureDataType(programContext.getRecoveredTypesCp(getPackagePathString()),
				getUniqueTypename(), genericSliceDT.getLength(), programContext.getDTM());

		// ensure the sliceDT is filled out before getting the element's data type to ensure
		// any other data types pulled in that ref this slice don't change size when trying to
		// enable packing
		sliceDT.replaceWith(genericSliceDT);

		programContext.cacheRecoveredDataType(this, sliceDT);

		// fixup the generic void* field with the specific element* type
		GoType elementType = getElement();
		DataType elementDT = programContext.getRecoveredType(elementType);
		Pointer elementPtrDT = programContext.getDTM().getPointer(elementDT);

		int arrayPtrComponentIndex = 0; /* HACK, field ordinal of void* data field in slice type */
		DataTypeComponent arrayDTC = genericSliceDT.getComponent(arrayPtrComponentIndex);
		sliceDT.replace(arrayPtrComponentIndex, elementPtrDT, -1, arrayDTC.getFieldName(),
			arrayDTC.getComment());

		return sliceDT;
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!super.discoverGoTypes(discoveredTypes)) {
			return false;
		}
		GoType elementType = getElement();
		if (elementType != null) {
			elementType.discoverGoTypes(discoveredTypes);
		}
		return true;
	}

	@Override
	public String getStructureNamespace() throws IOException {
		String packagePath = getPackagePathString();
		if (packagePath != null) {
			return packagePath;
		}
		GoType elementType = getElement();
		return elementType != null
				? elementType.getStructureNamespace()
				: super.getStructureNamespace();
	}

	@Override
	protected String getTypeDeclString() throws IOException {
		// type CustomSliceType []elementType
		String selfName = typ.getName();
		String elemName = programContext.getGoTypeName(elem);
		String defStr = "[]%s".formatted(elemName);
		String defStrWithLinks = "[]%s".formatted(
			AddressAnnotatedStringHandler.createAddressAnnotationString(elem, elemName));
		boolean hasName = !defStr.equals(selfName);

		return "type %s%s".formatted(hasName ? selfName + " " : "", defStrWithLinks);
	}

}
