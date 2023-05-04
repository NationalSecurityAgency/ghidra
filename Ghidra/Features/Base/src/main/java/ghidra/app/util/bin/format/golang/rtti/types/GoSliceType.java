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

import java.util.Set;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.*;

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
		int arrayPtrComponentIndex = 0; /* HACK, field ordinal of void* data field in slice type */
		Structure genericSliceDT = programContext.getGenericSliceDT();
		DataTypeComponent arrayDTC = genericSliceDT.getComponent(arrayPtrComponentIndex);

		GoType elementType = getElement();
		DataType elementDT = elementType.recoverDataType();
		Pointer elementPtrDT = programContext.getDTM().getPointer(elementDT);

		StructureDataType sliceDT =
			new StructureDataType(programContext.getRecoveredTypesCp(), typ.getNameString(), 0,
				programContext.getDTM());
		sliceDT.replaceWith(genericSliceDT);
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
