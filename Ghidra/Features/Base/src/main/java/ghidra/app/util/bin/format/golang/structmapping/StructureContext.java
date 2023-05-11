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
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

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
	protected final BinaryReader reader;
	protected final long structureStart;
	protected T structureInstance;
	protected Structure structureDataType;

	public StructureContext(DataTypeMapper dataTypeMapper, StructureMappingInfo<T> mappingInfo,
			BinaryReader reader) {
		this.dataTypeMapper = dataTypeMapper;
		this.mappingInfo = mappingInfo;
		this.reader = reader;
		this.structureStart = reader.getPointerIndex();
		this.structureDataType = mappingInfo.getStructureDataType();
	}

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
	 * @return
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
	 * @return
	 */
	public DataTypeMapper getDataTypeMapper() {
		return dataTypeMapper;
	}

	public Program getProgram() {
		return dataTypeMapper.program;
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
	 * @param fieldOffset
	 * @return
	 */
	public Address getFieldAddress(long fieldOffset) {
		return getStructureAddress().add(fieldOffset);
	}

	/**
	 * Returns the stream location of an offset from the start of this structure instance.
	 * 
	 * @param fieldOffset
	 * @return
	 */
	public long getFieldLocation(long fieldOffset) {
		return structureStart + fieldOffset;
	}

	/**
	 * Returns the stream location of this structure instance.
	 * 
	 * @return
	 */
	public long getStructureStart() {
		return structureStart;
	}

	/**
	 * Returns the stream location of the end of this structure instance.
	 * 
	 * @return
	 */
	public long getStructureEnd() {
		return structureStart + getStructureLength();
	}

	/**
	 * Returns the length of this structure instance.
	 * 
	 * @return
	 */
	public int getStructureLength() {
		return structureDataType != null
				? structureDataType.getLength()
				: 0;
	}

	public T getStructureInstance() {
		return structureInstance;
	}

	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * Returns an independent {@link BinaryReader} that is positioned at the start of the
	 * specified field.
	 * 
	 * @param fieldOffset
	 * @return
	 */
	public BinaryReader getFieldReader(long fieldOffset) {
		return reader.clone(structureStart + fieldOffset);
	}


	public FieldContext<T> createFieldContext(FieldMappingInfo<T> fmi, boolean includeReader) {
		DataTypeComponent dtc = fmi.getDtc(structureDataType);
		BinaryReader fieldReader = includeReader ? getFieldReader(dtc.getOffset()) : null;
		FieldContext<T> readContext = new FieldContext<>(this, fmi, dtc, fieldReader);
		return readContext;
	}

	/**
	 * Places a comment at the start of this structure, appending to any previous values 
	 * already there.
	 * 
	 * @param commentType
	 * @param prefix
	 * @param comment
	 * @param sep
	 * @throws IOException
	 */
	public void appendComment(int commentType, String prefix, String comment, String sep)
			throws IOException {
		DWARFUtil.appendComment(dataTypeMapper.getProgram(), getStructureAddress(), commentType,
			prefix, comment, sep);
	}

	public boolean isAlreadyMarkedup() {
		Address addr = getStructureAddress();
		Data data = getProgram().getListing().getDataContaining(addr);
		if (data != null && data.getBaseDataType() instanceof Structure) {
			return true;
		}
		return false;
	}

	/**
	 * @param nested if true, it is assumed that the Ghidra data types have already been
	 * placed and only markup needs to be performed.
	 * 
	 * @throws IOException
	 */
	public void markupStructure(boolean nested) throws IOException {
		Address addr = getStructureAddress();
		if (!nested && !dataTypeMapper.markedupStructs.add(addr)) {
			return;
		}

		if (!nested) {
			try {
				Structure structDT = getStructureDataType();
				dataTypeMapper.markupAddress(addr, structDT);
			}
			catch (IOException e) {
				throw new IOException("Markup failed for structure %s at %s"
						.formatted(mappingInfo.getDescription(), getStructureAddress()),
					e);
			}

			if (structureInstance instanceof StructureMarkup<?> sm) {
				String structureLabel = sm.getStructureLabel();
				if (structureLabel != null) {
					dataTypeMapper.labelAddress(addr, structureLabel);
				}
			}
		}

		markupFields();

		if (structureInstance instanceof StructureMarkup<?> sm) {
			sm.additionalMarkup();
		}

	}

	public void markupFields() throws IOException {
		for (FieldMappingInfo<T> fmi : mappingInfo.getFields()) {
			for (FieldMarkupFunction<T> func : fmi.getMarkupFuncs()) {
				func.markupField(createFieldContext(fmi, false));
			}
		}
		if (structureInstance instanceof StructureMarkup<?> sm) {
			for (Object externalInstance : sm.getExternalInstancesToMarkup()) {
				dataTypeMapper.markup(externalInstance, false);
			}
		}

		for (StructureMarkupFunction<T> markupFunc : mappingInfo.getMarkupFuncs()) {
			markupFunc.markupStructure(this);
		}

	}

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
