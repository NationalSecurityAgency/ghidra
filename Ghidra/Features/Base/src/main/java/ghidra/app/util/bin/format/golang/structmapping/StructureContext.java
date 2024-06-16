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
import ghidra.program.model.data.*;

/**
 * Information about an instance of a structure that has been read from the memory of a 
 * Ghidra program.
 * <p>
 * All {@link StructureMapping} tagged classes must have a {@link ContextField} tagged
 * StructureContext field for that class to be able to access meta-data about its self, and
 * for other classes to reference it when performing markup:
 * <pre>
 * &#64;StructureMapping(structureName = "mydatatype")
 * class MyDataType {
 * 	&#64;ContextField
 * 	private StructureContext&lt;MyDataType&gt; context;
 * 
 * 	&#64;FieldMapping
 * 	private long someField;
 *  ...
 * </pre>
 * 
 * @param <T> a java class that has been tagged with a {@link StructureMapping} annotation.
 */
public class StructureContext<T> {
	protected final DataTypeMapper dataTypeMapper;
	protected final StructureMappingInfo<T> mappingInfo;
	protected final DataType containingFieldDataType;
	protected final BinaryReader reader;
	protected final long structureStart;
	protected T structureInstance;
	protected Structure structureDataType;

	/**
	 * Creates an instance of a {@link StructureContext}.
	 * 
	 * @param dataTypeMapper mapping context for the program
	 * @param mappingInfo mapping information about this structure
	 * @param reader {@link BinaryReader} positioned at the start of the structure to be read, or
	 * null if this is a limited-use context object
	 */
	public StructureContext(DataTypeMapper dataTypeMapper, StructureMappingInfo<T> mappingInfo,
			BinaryReader reader) {
		this(dataTypeMapper, mappingInfo, null, reader);
	}

	/**
	 * Creates an instance of a {@link StructureContext}.
	 * 
	 * @param dataTypeMapper mapping context for the program
	 * @param mappingInfo mapping information about this structure
	 * @param containingFieldDataType optional, the DataType of the field that contained the
	 * instance being deserialized
	 * @param reader {@link BinaryReader} positioned at the start of the structure to be read, or
	 * null if this is a limited-use context object
	 */
	public StructureContext(DataTypeMapper dataTypeMapper, StructureMappingInfo<T> mappingInfo,
			DataType containingFieldDataType, BinaryReader reader) {
		this.dataTypeMapper = dataTypeMapper;
		this.mappingInfo = mappingInfo;
		this.containingFieldDataType = containingFieldDataType;
		this.reader = reader;
		this.structureStart = reader != null ? reader.getPointerIndex() : -1;
		this.structureDataType = mappingInfo.getStructureDataType();
	}

	/**
	 * Creates a new instance of the structure by deserializing the structure's marked
	 * fields into java fields.
	 *   
	 * @return new instance of structure
	 * @throws IOException if error reading
	 */
	public T readNewInstance() throws IOException {
		structureInstance = mappingInfo.getInstanceCreator().get(this);

		mappingInfo.assignContextFieldValues(this);

		mappingInfo.readStructure(this);

		ReflectionHelper.invokeMethods(mappingInfo.getAfterMethods(), structureInstance);

		// TODO: capture actual structure length by checking BinaryReader position?

		return structureInstance;
	}

	/**
	 * Returns the {@link StructureMappingInfo} for this structure's class.
	 * 
	 * @return {@link StructureMappingInfo} for this structure's class
	 */
	public StructureMappingInfo<T> getMappingInfo() {
		return mappingInfo;
	}

	/**
	 * Returns a reference to the root {@link DataTypeMapper}, as a plain DataTypeMapper type.  If
	 * a more specific DataTypeMapper type is needed, either type-cast this value, or use
	 * a {@link ContextField} tag on a field in your class that specifies the correct 
	 * DataTypeMapper type.
	 *  
	 * @return the program mapping context that control's this structure instance
	 */
	public DataTypeMapper getDataTypeMapper() {
		return dataTypeMapper;
	}

	/**
	 * Returns the {@link DataType} of the field that this object instance was contained inside of,
	 * or null if this instance was not a field inside another structure.
	 * <p>
	 * For instance, if a structure was being deserialized because it was a field inside 
	 * another structure, the actual Ghidra data type of the field may be slightly different
	 * than the structure data type defined at the top of the structmapped 
	 * class (ie. {@code @StructureMapping(structureName='struct')}.  The containing field's
	 * data type could allow custom logic to enrich or modify this struct's behavior.
	 * 
	 * @return {@link DataType} of the field that this object instance was contained inside of
	 */
	public DataType getContainingFieldDataType() {
		return containingFieldDataType;
	}

	/**
	 * Returns the address in the program of this structure instance.
	 * 
	 * @return {@link Address}
	 */
	public Address getStructureAddress() {
		return dataTypeMapper.getDataAddress(structureStart);
	}

	/**
	 * Returns the address of an offset from the start of this structure instance.
	 * 
	 * @param fieldOffset number of bytes from the beginning of this structure where a field (or
	 * other location of interest) starts
	 * @return {@link Address} of specified offset
	 */
	public Address getFieldAddress(long fieldOffset) {
		return getStructureAddress().add(fieldOffset);
	}

	/**
	 * Returns the stream location of an offset from the start of this structure instance.
	 * 
	 * @param fieldOffset number of bytes from the beginning of this structure where a field (or
	 * other location of interest) starts
	 * @return absolute offset / position in the program / BinaryReader stream
	 */
	public long getFieldLocation(long fieldOffset) {
		return structureStart + fieldOffset;
	}

	/**
	 * Returns the stream location of this structure instance.
	 * 
	 * @return absolute offset / position in the program / BinaryReader stream of this structure
	 */
	public long getStructureStart() {
		return structureStart;
	}

	/**
	 * Returns the stream location of the end of this structure instance.
	 * 
	 * @return absolute offset / position in the program / BinaryReader stream of the byte after
	 * this structure
	 */
	public long getStructureEnd() {
		return structureStart + getStructureLength();
	}

	/**
	 * Returns the length of this structure instance.
	 * 
	 * @return length of this structure, or 0 if this structure is a variable length structure
	 * that does not have a fixed length 
	 */
	public int getStructureLength() {
		return structureDataType != null
				? structureDataType.getLength()
				: 0;
	}

	/**
	 * Returns a reference to the object instance that was deserialized.
	 * 
	 * @return reference to deserialized structure mapped object
	 */
	public T getStructureInstance() {
		return structureInstance;
	}

	/**
	 * Returns the {@link BinaryReader} that is used to deserialize this structure.
	 * 
	 * @return {@link BinaryReader} that is used to deserialize this structure
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * Returns an independent {@link BinaryReader} that is positioned at the start of the
	 * specified field.
	 * 
	 * @param fieldOffset number of bytes from the beginning of this structure where a field (or
	 * other location of interest) starts
	 * @return new {@link BinaryReader} positioned at the specified relative offset
	 */
	public BinaryReader getFieldReader(long fieldOffset) {
		return reader.clone(structureStart + fieldOffset);
	}


	/**
	 * Creates a new {@link FieldContext} for a specific field.
	 * 
	 * @param fmi {@link FieldMappingInfo field} of interest 
	 * @param includeReader boolean flag, if true create a BinaryReader for the field, if false no
	 * BinaryReader will be created
	 * @return new {@link FieldContext}
	 */
	public FieldContext<T> createFieldContext(FieldMappingInfo<T> fmi, boolean includeReader) {
		DataTypeComponent dtc = fmi.getDtc(structureDataType);
		BinaryReader fieldReader = includeReader ? getFieldReader(dtc.getOffset()) : null;
		FieldContext<T> readContext = new FieldContext<>(this, fmi, dtc, fieldReader);
		return readContext;
	}

	/**
	 * Returns the Ghidra {@link Structure structure data type} that represents this object.
	 * <p>
	 * If this is an instance of a variable length structure mapped class, a custom structure data
	 * type will be minted that exactly matches this instance's variable length fields.
	 * 
	 * @return Ghidra {@link Structure structure data type} that represents this object
	 * @throws IOException if error constructing new struct data type
	 */
	public Structure getStructureDataType() throws IOException {
		if (structureDataType == null) {
			// if this is a variable length struct, a new custom struct datatype needs to be created
			structureDataType = mappingInfo.createStructureDataType(this);
		}
		return structureDataType;
	}

	@Override
	public String toString() {
		return "StructureContext<%s> { offset: %s}".formatted(
			mappingInfo.getTargetClass().getSimpleName(),
			Long.toUnsignedString(structureStart, 16));
	}

}
