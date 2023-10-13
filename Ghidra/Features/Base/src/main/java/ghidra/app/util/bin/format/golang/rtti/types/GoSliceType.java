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
	@MarkupReference("element")
	private long elem;

	public GoSliceType() {
	}

	@Markup
	public GoType getElement() throws IOException {
		return programContext.getGoType(elem);
	}

	@Override
	public DataType recoverDataType() throws IOException {
		StructureDataType sliceDT = new StructureDataType(programContext.getRecoveredTypesCp(),
			typ.getNameString(), 0, programContext.getDTM());
		programContext.cacheRecoveredDataType(this, sliceDT);

		// fixup the generic void* field with the specific element* type
		GoType elementType = getElement();
		DataType elementDT = elementType.recoverDataType();
		Pointer elementPtrDT = programContext.getDTM().getPointer(elementDT);

		Structure genericSliceDT = programContext.getGenericSliceDT();
		sliceDT.replaceWith(genericSliceDT);

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

}
