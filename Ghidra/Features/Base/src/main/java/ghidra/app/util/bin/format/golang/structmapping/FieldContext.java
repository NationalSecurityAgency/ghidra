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
package ghidra.app.util.bin.format.golang.structmapping;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.DWARFUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.symbol.*;

/**
 * Context of an individual field that is being deserialized
 * 
 * @param <T> the class that contains this field
 */
public record FieldContext<T> (
		StructureContext<T> structureContext,
		FieldMappingInfo<T> fieldInfo,
		DataTypeComponent dtc,
		BinaryReader reader) {

	public T getStructureInstance() {
		return structureContext.getStructureInstance();
	}

	public DataTypeMapper getDataTypeMapper() {
		return structureContext().getDataTypeMapper();
	}

	public void appendComment(int commentType, String prefix, String comment, String sep)
			throws IOException {
		DWARFUtil.appendComment(structureContext.getProgram(), getAddress(), commentType, prefix,
			comment, sep);
	}

	public void addReference(Address refDest) throws IOException {
		ReferenceManager refMgr = structureContext.getProgram().getReferenceManager();

		Address fieldAddr = getAddress();
		refMgr.addMemoryReference(fieldAddr, refDest, RefType.DATA, SourceType.IMPORTED, 0);
	}

	public Address getAddress() {
		return structureContext.getStructureAddress().add(dtc.getOffset());
	}

	public <R> R getValue(Class<R> expectedType) throws IOException {
		return fieldInfo.getValue(structureContext.getStructureInstance(), expectedType);
	}

}
