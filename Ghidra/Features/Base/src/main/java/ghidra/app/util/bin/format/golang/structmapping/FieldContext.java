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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeComponent;

/**
 * Context of an individual field that is being deserialized, or being markedup.
 * 
 * @param <T> the class that contains this field
 * @param structureContext {@link StructureContext} that contains this field 
 * @param fieldInfo {@link FieldMappingInfo} immutable information about this field
 * @param dtc {@link DataTypeComponent} that this field maps to
 * @param reader {@link BinaryReader} to use when reading data, may be null if this context is
 * for markup operations instead of deserialization
 */
public record FieldContext<T> (
		StructureContext<T> structureContext,
		FieldMappingInfo<T> fieldInfo,
		DataTypeComponent dtc,
		BinaryReader reader) {

	/**
	 * Returns the structure instance that contains this field.
	 * 
	 * @return structure instance that contains this field
	 */
	public T getStructureInstance() {
		return structureContext.getStructureInstance();
	}

	/**
	 * Returns the address of this structure field.
	 * 
	 * @return the address of this field
	 */
	public Address getAddress() {
		return structureContext.getStructureAddress().add(dtc.getOffset());
	}

	/**
	 * Returns the value of this java field.
	 * 
	 * @param <R> result type
	 * @param expectedType class of expected result type
	 * @return value of this java field, as type R
	 * @throws IOException if error getting or converting value
	 */
	public <R> R getValue(Class<R> expectedType) throws IOException {
		return fieldInfo.getValue(structureContext.getStructureInstance(), expectedType);
	}

}
