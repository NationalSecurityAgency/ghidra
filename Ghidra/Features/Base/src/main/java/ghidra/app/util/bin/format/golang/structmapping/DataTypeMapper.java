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
import java.lang.reflect.Array;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.dwarf4.next.DWARFDataTypeConflictHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.DataConverter;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Information about {@link StructureMapping} classes and their metadata, as well as
 * accumulated information about structure instances that have been deserialized.
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
	protected Set<Address> markedupStructs = new HashSet<>();
	protected TaskMonitor markupTaskMonitor = TaskMonitor.DUMMY;

	/**
	 * 
	 * @param program
	 * @param archiveGDT
	 * @throws IOException
	 */
	protected DataTypeMapper(Program program, ResourceFile archiveGDT) throws IOException {
		this.program = program;
		this.programDTM = program.getDataTypeManager();
		this.archiveDTM = archiveGDT != null
				? FileDataTypeManager.openFileArchive(archiveGDT, false)
				: null;
	}

	@Override
	public void close() {
		if (archiveDTM != null) {
			archiveDTM.close();
			archiveDTM = null;
		}
	}

	public CategoryPath getDefaultVariableLengthStructCategoryPath() {
		return CategoryPath.ROOT;
	}

	public Program getProgram() {
		return program;
	}

	protected BinaryReader createProgramReader() {
		MemoryByteProvider bp =
			new MemoryByteProvider(program.getMemory(), program.getImageBase().getAddressSpace());
		return new BinaryReader(bp, !program.getMemory().isBigEndian());
	}

	public DataConverter getDataConverter() {
		return DataConverter.getInstance(program.getMemory().isBigEndian());
	}

	public DataTypeMapper addProgramSearchCategoryPath(CategoryPath... paths) {
		programSearchCPs.addAll(Arrays.asList(paths));
		return this;
	}

	public DataTypeMapper addArchiveSearchCategoryPath(CategoryPath... paths) {
		archiveSearchCPs.addAll(Arrays.asList(paths));
		return this;
	}

	/**
	 * Registers a class that has {@link StructureMapping structure mapping} information.
	 * 
	 * @param <T>
	 * @param clazz
	 * @throws IOException if the class's Ghidra structure data type could not be found
	 */
	public <T> void registerStructure(Class<T> clazz) throws IOException {
		Structure structDT = null;
		String structName = StructureMappingInfo.getStructureDataTypeNameForClass(clazz);
		if (structName != null && !structName.isBlank()) {
			structDT = getType(structName, Structure.class);
		}
		if (!StructureReader.class.isAssignableFrom(clazz) && structDT == null) {
			if (structName == null || structName.isBlank()) {
				structName = "<missing>";
			}
			throw new IOException(
				"Missing struct definition %s - %s".formatted(clazz.getSimpleName(),
					structName));
		}

		StructureMappingInfo<T> structMappingInfo = StructureMappingInfo.fromClass(clazz, structDT);
		mappingInfo.put(clazz, structMappingInfo);
	}

	public void registerStructures(List<Class<?>> classes) throws IOException {
		for (Class<?> clazz : classes) {
			registerStructure(clazz);
		}
	}

	@SuppressWarnings("unchecked")
	public <T> StructureMappingInfo<T> getStructureMappingInfo(Class<T> clazz) {
		StructureMappingInfo<?> smi = mappingInfo.get(clazz);
		return (StructureMappingInfo<T>) smi;
	}

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
		StructureMappingInfo<?> mi = mappingInfo.get(clazz);
		return mi != null ? mi.getStructureDataType() : null;
	}

	/**
	 * Returns the name of the Ghidra structure that has been registered for the specified
	 * structure mapped class.
	 * 
	 * @param clazz
	 * @return
	 */
	public String getStructureDataTypeName(Class<?> clazz) {
		StructureMappingInfo<?> mi = mappingInfo.get(clazz);
		return mi != null ? mi.getStructureName() : null;
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

	/**
	 * Returns a named {@link DataType}, searching the registered 
	 * {@link #addProgramSearchCategoryPath(CategoryPath...) program}
	 * and {@link #addArchiveSearchCategoryPath(CategoryPath...) archive} category paths.
	 * 
	 * @param <T>
	 * @param name
	 * @param clazz
	 * @return
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

	public <T extends DataType> T getTypeOrDefault(String name, Class<T> clazz, T defaultValue) {
		T result = getType(name, clazz);
		return result != null ? result : defaultValue;
	}

	public DataTypeManager getDTM() {
		return programDTM;
	}

	private <T> StructureContext<T> getStructureContext(Class<T> structureClass,
			BinaryReader reader) {
		StructureMappingInfo<T> smi = getStructureMappingInfo(structureClass);
		if (smi == null) {
			throw new IllegalArgumentException(
				"Unknown structure mapped class: " + structureClass.getSimpleName());
		}
		return new StructureContext<>(this, smi, reader);
	}

	public <T> StructureContext<T> getExistingStructureContext(T structureInstance)
			throws IOException {
		StructureMappingInfo<T> smi = structureInstance != null
				? getStructureMappingInfo(structureInstance)
				: null;
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
	 * @throws IOException
	 */
	public <T> Address getExistingStructureAddress(T structureInstance) throws IOException {
		StructureMappingInfo<T> smi = structureInstance != null
				? getStructureMappingInfo(structureInstance)
				: null;
		StructureContext<T> structureContext = smi != null
				? smi.recoverStructureContext(structureInstance)
				: null;
		return structureContext != null
				? structureContext.getStructureAddress()
				: null;
	}

	public void setMarkupTaskMonitor(TaskMonitor monitor) {
		this.markupTaskMonitor = Objects.requireNonNullElse(monitor, TaskMonitor.DUMMY);
	}

	public <T> void markup(T obj, boolean nested) throws IOException {
		if (markupTaskMonitor.isCancelled()) {
			throw new IOException("Markup canceled");
		}
		if (obj == null) {
			return;
		}
		if (obj instanceof Collection<?> list) {
			for (Object listElement : list) {
				markup(listElement, nested);
			}
		}
		else if (obj.getClass().isArray()) {
			int len = Array.getLength(obj);
			for (int i = 0; i < len; i++) {
				markup(Array.get(obj, i), nested);
			}
		}
		else if (obj instanceof Iterator<?> it) {
			while (it.hasNext()) {
				Object itElement = it.next();
				markup(itElement, nested);
			}
		}
		else {
			StructureContext<T> structureContext = getExistingStructureContext(obj);
			if (structureContext == null) {
				throw new IllegalArgumentException();
			}
			markupTaskMonitor.incrementProgress(1);
			structureContext.markupStructure(nested);
		}
	}

	public <T> T readStructure(Class<T> structureClass, BinaryReader structReader)
			throws IOException {
		StructureContext<T> structureContext = getStructureContext(structureClass, structReader);

		T result = structureContext.readNewInstance();
		return result;
	}

	public <T> T readStructure(Class<T> structureClass, long position) throws IOException {
		return readStructure(structureClass, getReader(position));
	}

	public <T> T readStructure(Class<T> structureClass, Address address) throws IOException {
		return readStructure(structureClass, getReader(address.getOffset()));
	}

	public BinaryReader getReader(long position) {
		BinaryReader reader = createProgramReader();
		reader.setPointerIndex(position);
		return reader;
	}


	public Address getDataAddress(long offset) {
		return program.getImageBase().getNewAddress(offset);
	}

	public Address getCodeAddress(long offset) {
		return program.getImageBase().getNewAddress(offset);
	}

	public void labelAddress(Address addr, String symbolName) throws IOException {
		try {
			SymbolTable symbolTable = getProgram().getSymbolTable();
			Symbol[] symbols = symbolTable.getSymbols(addr);
			if (symbols.length == 0 || symbols[0].isDynamic()) {
				symbolName = SymbolUtilities.replaceInvalidChars(symbolName, true);
				symbolTable.createLabel(addr, symbolName, SourceType.IMPORTED);
			}
		}
		catch (InvalidInputException e) {
			throw new IOException(e);
		}
	}

	public <T> void labelStructure(T obj, String symbolName) throws IOException {
		Address addr = getExistingStructureAddress(obj);
		labelAddress(addr, symbolName);
	}

	public void markupAddress(Address addr, DataType dt) throws IOException {
		markupAddress(addr, dt, -1);
	}

	public void markupAddress(Address addr, DataType dt, int length) throws IOException {
		try {
			DataUtilities.createData(program, addr, dt, length, false,
				ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
		}
		catch (CodeUnitInsertionException e) {
			throw new IOException(e);
		}

	}

	public void markupAddressIfUndefined(Address addr, DataType dt) throws IOException {
		Data data = DataUtilities.getDataAtAddress(program, addr);
		if (data == null || Undefined.isUndefined(data.getBaseDataType())) {
			markupAddress(addr, dt);
		}
	}

	@Override
	public String toString() {
		return "DataTypeMapper { program: %s}".formatted(program.getName());
	}
}
