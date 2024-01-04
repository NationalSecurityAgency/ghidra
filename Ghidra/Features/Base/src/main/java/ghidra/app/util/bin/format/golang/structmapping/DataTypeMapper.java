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
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.dwarf4.next.DWARFDataTypeConflictHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.DataConverter;
import ghidra.util.task.TaskMonitor;

/**
 * Information about {@link StructureMapping} classes and their metadata.
 * <p>
 * To use the full might and majesty of StructureMapping(tm), a DataTypeMapper must be created. It
 * must be able to {@link #addArchiveSearchCategoryPath(CategoryPath...) find} 
 * ({@link #addProgramSearchCategoryPath(CategoryPath...) more find}) the Ghidra structure data
 * types being used, and it must {@link #registerStructure(Class) know} about all classes that are
 * going to participate during deserialization and markup.
 * <p>
 * Structure mapped classes can receive a reference to the specific DataTypeMapper type that 
 * created them by declaring a {@code DataTypeMapper} field, and tagging it with 
 * the @{@link ContextField} annotation:
 * 
 * <pre>
 * class MyDataTypeMapper extends DataTypeMapper {
 *  public MyDataTypeMapper() {
 *    ...
 *   registerStructure(MyDataType.class);
 *  }
 *  public void foo() { ... }
 * }
 * 
 * &#64;StructureMapping(structureName = "mydatatype")
 * class MyDataType {
 * 
 *  &#64;ContextField
 *  private MyDataTypeMapper myDataTypeMapper;
 *  
 *  &#64;ContextField
 *  private StructureContext&lt;MyDataType&gt; context;
 * 
 *  &#64;FieldMapping
 *  private long someField;
 * 
 * void bar() {
 *  context.getDataTypeMapper().getProgram(); // can only access methods defined on base DataTypeMapper type
 *  myDataTypeMapper.foo(); // same context as previous line, but typed correctly
 * ...
 * </pre>
 * 
 */
public class DataTypeMapper implements AutoCloseable {
	protected Program program;
	protected DataTypeManager programDTM;
	protected DataTypeManager archiveDTM;
	protected List<CategoryPath> programSearchCPs = new ArrayList<>();
	protected List<CategoryPath> archiveSearchCPs = new ArrayList<>();
	protected Map<Class<?>, StructureMappingInfo<?>> mappingInfo = new HashMap<>();

	/**
	 * Creates and initializes a DataTypeMapper.
	 * 
	 * @param program the {@link Program} that will contain the deserialized data
	 * @param archiveGDT path to a gdt data type archive that will be searched when
	 * a {@link #getType(String, Class)} is called, or {@code null} if no archive
	 * @throws IOException if error opening data type archive
	 */
	protected DataTypeMapper(Program program, ResourceFile archiveGDT) throws IOException {
		this.program = program;
		this.programDTM = program.getDataTypeManager();
		this.archiveDTM =
			archiveGDT != null ? FileDataTypeManager.openFileArchive(archiveGDT, false) : null;
	}

	@Override
	public void close() {
		if (archiveDTM != null) {
			archiveDTM.close();
			archiveDTM = null;
		}
	}

	/**
	 * CategoryPath location (in the program) where new data types will be created to represent
	 * variable length structures.
	 *    
	 * @return {@link CategoryPath}, default is ROOT
	 */
	public CategoryPath getDefaultVariableLengthStructCategoryPath() {
		return CategoryPath.ROOT;
	}

	/**
	 * Returns the program.
	 * 
	 * @return ghidra {@link Program}
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Creates a {@link MarkupSession} that is controlled by the specified {@link TaskMonitor}.
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @return new {@link MarkupSession}
	 */
	public MarkupSession createMarkupSession(TaskMonitor monitor) {
		return new MarkupSession(this, monitor);
	}

	/**
	 * Returns a {@link DataConverter} appropriate for the current program.
	 *  
	 * @return {@link DataConverter}
	 */
	public DataConverter getDataConverter() {
		return DataConverter.getInstance(program.getMemory().isBigEndian());
	}

	/**
	 * Adds category paths to a search list, used when looking for a data type.
	 * <p>
	 * See {@link #getType(String, Class)}.
	 * 
	 * @param paths vararg list of {@link CategoryPath}s
	 */
	public void addProgramSearchCategoryPath(CategoryPath... paths) {
		programSearchCPs.addAll(Arrays.asList(paths));
	}

	/**
	 * Adds category paths to a search list, used when looking for a data type.
	 * <p>
	 * See {@link #getType(String, Class)}.
	 * 
	 * @param paths vararg list of {@link CategoryPath}s
	 */
	public void addArchiveSearchCategoryPath(CategoryPath... paths) {
		archiveSearchCPs.addAll(Arrays.asList(paths));
	}

	/**
	 * Registers a class that has {@link StructureMapping structure mapping} information.
	 * 
	 * @param <T> structure mapped class type
	 * @param clazz class that represents a structure, marked with {@link StructureMapping} 
	 * annotation
	 * @throws IOException if the class's Ghidra structure data type could not be found
	 */
	public <T> void registerStructure(Class<T> clazz) throws IOException {
		StructureMapping sma = clazz.getAnnotation(StructureMapping.class);
		List<String> structNames = sma != null ? Arrays.asList(sma.structureName()) : List.of();
		Structure structDT = getType(structNames, Structure.class);
		if (structDT == null) {
			String dtName = structNames.isEmpty() ? "<missing>" : String.join("|", structNames);
			if (!StructureReader.class.isAssignableFrom(clazz)) {
				throw new IOException("Missing struct definition for class %s, structure name: [%s]"
						.formatted(clazz.getSimpleName(), dtName));
			}
			if (structNames.size() != 1) {
				throw new IOException(
					"Bad StructMapping,StructureReader definition for class %s, structure name: [%s]"
							.formatted(clazz.getSimpleName(), dtName));
			}
		}

		try {
			StructureMappingInfo<T> structMappingInfo =
				StructureMappingInfo.fromClass(clazz, structDT);
			mappingInfo.put(clazz, structMappingInfo);
		}
		catch (IllegalArgumentException e) {
			throw new IOException(e.getMessage());
		}
	}

	/**
	 * Registers the specified {@link StructureMapping structure mapping} classes.
	 *  
	 * @param classes list of classes to register
	 * @throws IOException if a class's Ghidra structure data type could not be found
	 */
	public void registerStructures(List<Class<?>> classes) throws IOException {
		for (Class<?> clazz : classes) {
			registerStructure(clazz);
		}
	}

	/**
	 * Returns the {@link StructureMappingInfo} for a class (that has already been registered).
	 * 
	 * @param <T> structure mapped class type
	 * @param clazz the class
	 * @return {@link StructureMappingInfo} for the specified class, or null if the class was
	 * not previously {@link #registerStructure(Class) registered}
	 */
	@SuppressWarnings("unchecked")
	public <T> StructureMappingInfo<T> getStructureMappingInfo(Class<T> clazz) {
		StructureMappingInfo<?> smi = mappingInfo.get(clazz);
		return (StructureMappingInfo<T>) smi;
	}

	/**
	 * Returns the {@link StructureMappingInfo} for an object instance.
	 *  
	 * @param <T> structure mapped class type
	 * @param structureInstance an instance of a previously registered 
	 * {@link StructureMapping structure mapping} class, or null
	 * @return {@link StructureMappingInfo} for the instance, or null if the class was
	 * not previously {@link #registerStructure(Class) registered}
	 */
	@SuppressWarnings("unchecked")
	public <T> StructureMappingInfo<T> getStructureMappingInfo(T structureInstance) {
		return structureInstance != null
				? (StructureMappingInfo<T>) mappingInfo.get(structureInstance.getClass())
				: null;
	}

	/**
	 * Returns a Ghidra structure data type representing the specified class.
	 * 
	 * @param clazz a structure mapped class
	 * @return {@link Structure} data type, or null if the class was a struct with variable length
	 * fields
	 */
	public Structure getStructureDataType(Class<?> clazz) {
		StructureMappingInfo<?> smi = mappingInfo.get(clazz);
		return smi != null ? smi.getStructureDataType() : null;
	}

	/**
	 * Returns the name of the Ghidra structure that has been registered for the specified
	 * structure mapped class.
	 * 
	 * @param clazz a structure mapped class
	 * @return name of the corresponding Ghidra structure data type, or null if class was not
	 * registered
	 */
	public String getStructureDataTypeName(Class<?> clazz) {
		StructureMappingInfo<?> mi = mappingInfo.get(clazz);
		return mi != null ? mi.getStructureName() : null;
	}

	/**
	 * Returns a named {@link DataType}, searching the registered 
	 * {@link #addProgramSearchCategoryPath(CategoryPath...) program}
	 * and {@link #addArchiveSearchCategoryPath(CategoryPath...) archive} category paths.
	 * <p>
	 * DataTypes that were found in the attached archive gdt manager will be copied into the
	 * program's data type manager before being returned.
	 * 
	 * @param <T> DataType or derived type
	 * @param name {@link DataType} name
	 * @param clazz expected DataType class
	 * @return DataType or null if not found
	 */
	public <T extends DataType> T getType(String name, Class<T> clazz) {
		DataType dataType = findType(name, programSearchCPs, programDTM);
		if (dataType == null && archiveDTM != null) {
			dataType = findType(name, archiveSearchCPs, archiveDTM);
			if (dataType != null) {
				dataType = programDTM.resolve(dataType, DWARFDataTypeConflictHandler.INSTANCE);
			}
		}
		if (dataType == null) {
			dataType =
				BuiltInDataTypeManager.getDataTypeManager().getDataType(CategoryPath.ROOT, name);
		}
		return clazz.isInstance(dataType) ? clazz.cast(dataType) : null;
	}

	/**
	 * Returns a named {@link DataType}, searching the registered
	 * {@link #addProgramSearchCategoryPath(CategoryPath...) program}
	 * and {@link #addArchiveSearchCategoryPath(CategoryPath...) archive} category paths.
	 * <p>
	 * DataTypes that were found in the attached archive gdt manager will be copied into the
	 * program's data type manager before being returned.
	 *
	 * @param <T> DataType or derived type
	 * @param names list containing the data type name and any alternates
	 * @param clazz expected DataType class
	 * @return DataType or null if not found
	 */
	public <T extends DataType> T getType(List<String> names, Class<T> clazz) {
		for (String dtName : names) {
			if (dtName != null && !dtName.isBlank()) {
				T result = getType(dtName, clazz);
				if (result != null) {
					return result;
				}
			}
		}
		return null;
	}

	/**
	 * Returns a named {@link DataType}, searching the registered
	 * {@link #addProgramSearchCategoryPath(CategoryPath...) program}
	 * and {@link #addArchiveSearchCategoryPath(CategoryPath...) archive} category paths.
	 * <p>
	 * DataTypes that were found in the attached archive gdt manager will be copied into the
	 * program's data type manager before being returned.
	 * 
	 * @param <T> DataType or derived type
	 * @param name {@link DataType} name
	 * @param clazz expected DataType class
	 * @param defaultValue value to return if the requested data type was not found
	 * @return DataType or {@code defaultValue} if not found
	 */
	public <T extends DataType> T getTypeOrDefault(String name, Class<T> clazz, T defaultValue) {
		T result = getType(name, clazz);
		return result != null ? result : defaultValue;
	}

	/**
	 * Returns the program's data type manager.
	 * 
	 * @return program's {@link DataTypeManager}
	 */
	public DataTypeManager getDTM() {
		return programDTM;
	}

	/**
	 * Returns the {@link StructureContext} of a structure mapped instance.
	 * 
	 * @param <T> java type of a class that is structure mapped
	 * @param structureInstance an existing instance of type T
	 * @return {@link StructureContext} of the instance, or null if instance was null or not
	 * a structure mapped object 
	 */
	public <T> StructureContext<T> getStructureContextOfInstance(T structureInstance) {
		StructureMappingInfo<T> smi =
			structureInstance != null ? getStructureMappingInfo(structureInstance) : null;
		return smi != null ? smi.recoverStructureContext(structureInstance) : null;
	}

	/**
	 * Attempts to convert an instance of an object (that represents a chunk of memory in
	 * the program) into its Address.
	 * 
	 * @param <T> type of the object
	 * @param structureInstance instance of an object that represents something in the program's
	 * memory
	 * @return {@link Address} of the object, or null if not found or not a supported object
	 */
	public <T> Address getAddressOfStructure(T structureInstance) {
		StructureMappingInfo<T> smi =
			structureInstance != null ? getStructureMappingInfo(structureInstance) : null;
		StructureContext<T> structureContext =
			smi != null ? smi.recoverStructureContext(structureInstance) : null;
		return structureContext != null ? structureContext.getStructureAddress() : null;
	}

	/**
	 * Returns the address of the last byte of a structure.
	 * 
	 * @param <T> type of object
	 * @param structureInstance instance of an object that represents something in the program's
	 * memory
	 * @return {@link Address} of the last byte of the object, or null if not found 
	 * or not a supported object
	 */
	public <T> Address getMaxAddressOfStructure(T structureInstance) {
		StructureMappingInfo<T> smi =
			structureInstance != null ? getStructureMappingInfo(structureInstance) : null;
		StructureContext<T> structureContext =
			smi != null ? smi.recoverStructureContext(structureInstance) : null;
		return structureContext != null
				? structureContext.getStructureAddress()
						.add(structureContext.getStructureLength() - 1)
				: null;
	}

	/**
	 * Reads a structure mapped object from the current position of the specified BinaryReader.
	 * 
	 * @param <T> type of object
	 * @param structureClass structure mapped object class
	 * @param structReader {@link BinaryReader} positioned at the start of an object
	 * @return new object instance of type T
	 * @throws IOException if error reading
	 * @throws IllegalArgumentException if specified structureClass is not valid
	 */
	public <T> T readStructure(Class<T> structureClass, BinaryReader structReader)
			throws IOException {
		return readStructure(structureClass, null, structReader);
	}

	/**
	 * Reads a structure mapped object from the current position of the specified BinaryReader.
	 * 
	 * @param <T> type of object
	 * @param structureClass structure mapped object class
	 * @param containingFieldDataType optional, data type of the structure field that contained the
	 * object instance that is being read (may be different than the data type that was specified in
	 * the matching {@link StructureMappingInfo})
	 * @param structReader {@link BinaryReader} positioned at the start of an object
	 * @return new object instance of type T
	 * @throws IOException if error reading
	 * @throws IllegalArgumentException if specified structureClass is not valid
	 */
	public <T> T readStructure(Class<T> structureClass, DataType containingFieldDataType,
			BinaryReader structReader) throws IOException {
		StructureContext<T> structureContext =
			createStructureContext(structureClass, containingFieldDataType, structReader);

		T result = structureContext.readNewInstance();
		return result;
	}

	/**
	 * Reads a structure mapped object from the specified position of the program.
	 * 
	 * @param <T> type of object
	 * @param structureClass structure mapped object class
	 * @param position of object
	 * @return new object instance of type T
	 * @throws IOException if error reading
	 * @throws IllegalArgumentException if specified structureClass is not valid
	 */
	public <T> T readStructure(Class<T> structureClass, long position) throws IOException {
		return readStructure(structureClass, getReader(position));
	}

	/**
	 * Reads a structure mapped object from the specified Address of the program.
	 * 
	 * @param <T> type of object
	 * @param structureClass structure mapped object class
	 * @param address location of object
	 * @return new object instance of type T
	 * @throws IOException if error reading
	 * @throws IllegalArgumentException if specified structureClass is not valid
	 */
	public <T> T readStructure(Class<T> structureClass, Address address) throws IOException {
		return readStructure(structureClass, getReader(address.getOffset()));
	}

	/**
	 * Creates a {@link BinaryReader}, at the specified position.
	 *  
	 * @param position location in the program
	 * @return new {@link BinaryReader} 
	 */
	public BinaryReader getReader(long position) {
		BinaryReader reader = createProgramReader();
		reader.setPointerIndex(position);
		return reader;
	}

	/**
	 * Converts an offset into an Address.
	 * 
	 * @param offset numeric offset
	 * @return {@link Address}
	 */
	public Address getDataAddress(long offset) {
		return program.getImageBase().getNewAddress(offset);
	}

	/**
	 * Converts an offset into an Address.
	 * 
	 * @param offset numeric offset
	 * @return {@link Address}
	 */
	public Address getCodeAddress(long offset) {
		return program.getImageBase().getNewAddress(offset);
	}

	@Override
	public String toString() {
		return "DataTypeMapper { program: %s }".formatted(program.getName());
	}

	/**
	 * Creates a new BinaryReader that reads bytes from the current program's memory image.
	 * <p>
	 * Address offsets and index offsets in the BinaryReader should be synonymous.
	 * 
	 * @return new BinaryReader
	 */
	protected BinaryReader createProgramReader() {
		MemoryByteProvider bp =
			new MemoryByteProvider(program.getMemory(), program.getImageBase().getAddressSpace());
		return new BinaryReader(bp, !program.getMemory().isBigEndian());
	}

	protected DataType findType(String name, List<CategoryPath> searchList, DataTypeManager dtm) {
		for (CategoryPath searchCP : searchList) {
			DataType dataType = dtm.getDataType(searchCP, name);
			if (dataType != null) {
				return dataType;
			}
		}
		return null;
	}

	private <T> StructureContext<T> createStructureContext(Class<T> structureClass,
			DataType containingFieldDataType, BinaryReader reader) throws IllegalArgumentException {
		StructureMappingInfo<T> smi = getStructureMappingInfo(structureClass);
		if (smi == null) {
			throw new IllegalArgumentException(
				"Unknown structure mapped class: " + structureClass.getSimpleName());
		}
		return new StructureContext<>(this, smi, containingFieldDataType, reader);
	}

	/**
	 * Creates an artificial structure context to be used in some limited situations.
	 * 
	 * @param <T> type of structure mapped object
	 * @param structureClass class of structure mapped object
	 * @return new {@link StructureContext}
	 */
	public <T> StructureContext<T> createArtificialStructureContext(Class<T> structureClass) {
		StructureMappingInfo<T> smi = getStructureMappingInfo(structureClass);
		if (smi == null) {
			throw new IllegalArgumentException(
				"Unknown structure mapped class: " + structureClass.getSimpleName());
		}
		return new StructureContext<>(this, smi, null);
	}

}
