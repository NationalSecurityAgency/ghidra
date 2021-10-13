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
// Script to fix up Windows RTTI vtables and structures 
//@category C++

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

public class FixUpRttiAnalysisScript extends GhidraScript {

	private static final String RTTI_BASE_CLASS_ARRAY_LABEL = "RTTI_Base_Class_Array";
	private static final String RTTI_CLASS_HIERARCHY_DESCRIPTOR_LABEL =
		"RTTI_Class_Hierarchy_Descriptor";
	private static final String RTTI_BASE_CLASS_DESCRIPTOR_LABEL = "RTTI_Base_Class_Descriptor";
	private static final String RTTI_BASE_COMPLETE_OBJECT_LOADER_LABEL =
		"RTTI_Complete_Object_Locator";
	private static final String RTTI_BASE_CLASS_DESCRIPTOR_DATA_NAME = "RTTIBaseClassDescriptor";
	private static final String RTTI_BASE_COMPLETE_OBJECT_LOADER_DATA_NAME =
		"RTTICompleteObjectLocator";
	private static final String RTTI_CLASS_HIERARCHY_DESCRIPTOR_DATA_NAME =
		"RTTIClassHierarchyDescriptor";
	private static final String VFTABLE_META_PTR_LABEL = "vftable_meta_ptr";
	private static final String VFTABLE_LABEL = "vftable";

	SymbolTable symbolTable = null;
	DataTypeManager dataTypeManager = null;
	GlobalNamespace globalNamespace = null;
	int defaultPointerSize = 0;
	boolean isWindows = false;

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("There is no open program");
			return;
		}

		setIsWindows();

		if (!isWindows) {
			println("This script only handles Windows programs");
			return;
		}

		// TODO: check version and only run if before 9.3?

		symbolTable = currentProgram.getSymbolTable();
		dataTypeManager = currentProgram.getDataTypeManager();
		globalNamespace = (GlobalNamespace) currentProgram.getGlobalNamespace();

		defaultPointerSize = currentProgram.getDefaultPointerSize();
		if (defaultPointerSize != 4 && defaultPointerSize != 8) {
			println("This script only works on 32 or 64 bit programs");
			return;
		}

		applyMissingRTTIStructures();
	}

	/**
	 * Method to find and apply missing RTTI structures
	 * @throws CancelledException if cancelled
	 * @throws Exception if error applying label or data
	 */
	private List<Symbol> applyMissingRTTIStructures() throws CancelledException, Exception {

		List<Symbol> completeObjectLocatorSymbols = createMissingRTTICompleteObjectLocator();

		List<Symbol> baseClassDescriptorSymbols = createMissingBaseClassDescriptors();

		List<Address> classHierarchyDescriptors = createMissingClassHierarchyDescriptors(
			baseClassDescriptorSymbols, completeObjectLocatorSymbols);

		createMissingBaseClassArrays(classHierarchyDescriptors);

		List<Symbol> vftableSymbols = createMissingVftableSymbols(completeObjectLocatorSymbols);
		return vftableSymbols;

	}

	/**
	 * Method to set the global variable isWindows
	 */
	private void setIsWindows() {

		String compilerID =
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		isWindows = compilerID.contains("windows");
	}

	/**
	 * Method to iterate over all symbols with Base Class Descriptor symbol and if
	 * the correct data type has not already been created, do so. 
	 * @return List of all symbols with valid (even previously) BaseClassDescriptor structure applied
	 * @throws CancelledException when cancelled
	 * @throws Exception when data cannot be created
	 */
	private List<Symbol> createMissingRTTICompleteObjectLocator()
			throws CancelledException, Exception {

		List<Symbol> completeObjectLocatorSymbols = new ArrayList<Symbol>();

		SymbolIterator dataSymbols =
			symbolTable.getSymbols(getInitializedMemory(), SymbolType.LABEL, true);

		while (dataSymbols.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = dataSymbols.next();
			if (!symbol.getName().contains(RTTI_BASE_COMPLETE_OBJECT_LOADER_LABEL)) {
				continue;
			}

			Data data = getDataAt(symbol.getAddress());
			if (data != null &&
				data.getDataType().getName().contains(RTTI_BASE_COMPLETE_OBJECT_LOADER_DATA_NAME)) {
				completeObjectLocatorSymbols.add(symbol);
				continue;
			}

			// for some reason it was named but not created so create it
			data = createCompleteObjectLocator(symbol.getAddress());
			if (data != null &&
				data.getDataType().getName().contains(RTTI_BASE_COMPLETE_OBJECT_LOADER_DATA_NAME)) {
				completeObjectLocatorSymbols.add(symbol);
				continue;
			}

			println("Cannot create RTTI_CompleteObjectLocator at " + symbol.getAddress());

		}
		return completeObjectLocatorSymbols;
	}

	/**
	 * Method to create a CompleteObjectLocator structure at the given address
	 * @param address the address where the structure will be created
	 * @return the created CompleteObjectLocator data or null if it couldn't be created
	 * @throws CancelledException if cancelled
	 * @throws Exception if error creating data
	 */
	private Data createCompleteObjectLocator(Address address) throws CancelledException, Exception {

		DataType completeObjLocatorDataType = dataTypeManager.getDataType(CategoryPath.ROOT,
			RTTI_BASE_COMPLETE_OBJECT_LOADER_DATA_NAME);
		if (completeObjLocatorDataType == null) {
			return null;
		}

		int sizeOfDt = completeObjLocatorDataType.getLength();

		clearListing(address, address.add(sizeOfDt));
		Data completeObjectLocator = createData(address, completeObjLocatorDataType);
		if (completeObjectLocator == null) {
			return null;
		}
		return completeObjectLocator;
	}

	/**
	 * Method to iterate over all symbols with Base Class Descriptor symbol and if
	 * the correct data type has not already been created, do so. 
	 * @return List of all symbols with valid (even previously) BaseClassDescriptor structure applied
	 * @throws Exception when cancelled
	 */
	private List<Symbol> createMissingBaseClassDescriptors() throws Exception {

		List<Symbol> baseClassDescriptorSymbols = new ArrayList<Symbol>();

		SymbolIterator dataSymbols =
			symbolTable.getSymbols(getInitializedMemory(), SymbolType.LABEL, true);

		while (dataSymbols.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = dataSymbols.next();
			if (!symbol.getName().contains(RTTI_BASE_CLASS_DESCRIPTOR_LABEL)) {
				continue;
			}

			Data data = getDataAt(symbol.getAddress());
			if (data != null &&
				data.getDataType().getName().contains(RTTI_BASE_CLASS_DESCRIPTOR_DATA_NAME)) {
				baseClassDescriptorSymbols.add(symbol);
				continue;
			}

			// for some reason it was named but not created so create it
			data = createBaseClassDescriptor(symbol.getAddress());
			if (data != null &&
				data.getDataType().getName().contains(RTTI_BASE_CLASS_DESCRIPTOR_DATA_NAME)) {
				baseClassDescriptorSymbols.add(symbol);
				continue;
			}

			println("Cannot create RTTI_Base_Class_Descriptor at " + symbol.getAddress());

		}
		return baseClassDescriptorSymbols;
	}

	/**
	 * Method to create a BaseClassDescriptor structure at the given address
	 * @param baseClassDescriptorAddress the address where the structure will be created
	 * @return the created BaseClassDescriptor data or null if it couldn't be created
	 * @throws CancelledException if cancelled
	 * @throws Exception if error creating data
	 */
	private Data createBaseClassDescriptor(Address baseClassDescriptorAddress)
			throws CancelledException, Exception {

		DataType baseClassDescriptor =
			dataTypeManager.getDataType(CategoryPath.ROOT, RTTI_BASE_CLASS_DESCRIPTOR_DATA_NAME);

		int sizeOfDt = baseClassDescriptor.getLength();

		clearListing(baseClassDescriptorAddress, baseClassDescriptorAddress.add(sizeOfDt));
		Data baseClassDescArray = createData(baseClassDescriptorAddress, baseClassDescriptor);
		if (baseClassDescArray == null) {
			return null;
		}
		return baseClassDescArray;
	}

	/**
	 * Method to apply missing RTTI Base Class Descriptor structures and symbols  
	 * @param address address to apply the missing structure and symbol
	 * @param numBaseClasses number of base classes in the array pointing to BaseClassDescriptors
	 * @param classNamespace name of the class
	 * @throws AddressOutOfBoundsException if try clear listing at address out of bounds
	 * @throws MemoryAccessException  if cannot access memory
	 * @throws CancelledException if cancelled 
	 * @throws Exception if issue making data
	 */
	private void createBaseClassDescriptors(Address address, int numBaseClasses,
			Namespace classNamespace) throws CancelledException, MemoryAccessException,
			AddressOutOfBoundsException, Exception {

		for (int i = 0; i < numBaseClasses; i++) {

			monitor.checkCanceled();

			Address baseClassDescriptorAddress = getReferencedAddress(address.add(i * 4));

			Data baseClassDescriptor = getDataAt(baseClassDescriptorAddress);
			if (baseClassDescriptor == null || !baseClassDescriptor.getDataType()
					.getName()
					.equals(
						RTTI_BASE_CLASS_DESCRIPTOR_DATA_NAME)) {

				int num1 = getInt(baseClassDescriptorAddress.add(8));
				int num2 = getInt(baseClassDescriptorAddress.add(12));
				int num3 = getInt(baseClassDescriptorAddress.add(16));
				int num4 = getInt(baseClassDescriptorAddress.add(20));

				baseClassDescriptor = createBaseClassDescriptor(baseClassDescriptorAddress);
				if (baseClassDescriptor != null) {
					symbolTable.createLabel(
						baseClassDescriptorAddress, RTTI_BASE_CLASS_DESCRIPTOR_LABEL + "_at_(" +
							num1 + "," + num2 + "," + num3 + "," + num4 + ")",
						classNamespace, SourceType.ANALYSIS);
				}
				else {
					println(
						"Failed to create a baseClassDescArray structure at " + address.toString());
				}
			}
		}
	}

	/**
	 * 
	 * @param baseClassDescriptors the given list of BaseClassDescriptor symbols
	 * @param completeObjectLocators the given list of CompleteObjectLocator symbols
	 * @return list of ClassHierarchyDescriptor addresses
	 * @throws CancelledException if cancelled
	 * @throws MemoryAccessException if memory cannot be read
	 * @throws InvalidInputException if issue setting return type
	 * @throws AddressOutOfBoundsException if try clear listing at address out of bounds
	 * @throws Exception if there is an issue creating a label
	 */
	private List<Address> createMissingClassHierarchyDescriptors(List<Symbol> baseClassDescriptors,
			List<Symbol> completeObjectLocators) throws CancelledException, MemoryAccessException,
			InvalidInputException, AddressOutOfBoundsException, Exception {

		List<Address> classHierarchyDescriptorAddresses = new ArrayList<Address>();

		Iterator<Symbol> baseClassDescriptorIterator = baseClassDescriptors.iterator();
		while (baseClassDescriptorIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = baseClassDescriptorIterator.next();
			Address classHierarchyDescriptorAddress = createClassHierarchyDescriptor(
				symbol.getAddress().add(24), symbol.getParentNamespace());

			if (classHierarchyDescriptorAddress != null &&
				!classHierarchyDescriptorAddresses.contains(classHierarchyDescriptorAddress)) {
				classHierarchyDescriptorAddresses.add(classHierarchyDescriptorAddress);
			}

		}

		Iterator<Symbol> completeObjectLocatorIterator = completeObjectLocators.iterator();
		while (completeObjectLocatorIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = completeObjectLocatorIterator.next();
			Address classHierarchyDescriptorAddress = createClassHierarchyDescriptor(
				symbol.getAddress().add(16), symbol.getParentNamespace());
			if (classHierarchyDescriptorAddress != null &&
				!classHierarchyDescriptorAddresses.contains(classHierarchyDescriptorAddress)) {
				classHierarchyDescriptorAddresses.add(classHierarchyDescriptorAddress);
			}
		}

		return classHierarchyDescriptorAddresses;

	}

	/**
	 * 
	 * @param address the address where the ClassHierarchyDescriptor is to be created
	 * @param classNamespace the namespace of the class
	 * @return the given class's ClassHierarchyDescriptor address
	 * @throws CancelledException if cancelled
	 * @throws MemoryAccessException if memory cannot be read
	 * @throws InvalidInputException if issue setting return type
	 * @throws Exception if issue creating label
	 */
	private Address createClassHierarchyDescriptor(Address address, Namespace classNamespace)
			throws CancelledException, MemoryAccessException, InvalidInputException, Exception {

		Address classHierarchyDescriptorAddress = getReferencedAddress(address);

		Data classHierarchyStructure = getDataAt(classHierarchyDescriptorAddress);

		if (classHierarchyStructure != null &&
			classHierarchyStructure.getDataType()
					.getName()
					.equals(
						RTTI_CLASS_HIERARCHY_DESCRIPTOR_DATA_NAME)) {
			return classHierarchyDescriptorAddress;

		}

		Symbol classHierarchySymbol;

		classHierarchySymbol = symbolTable.createLabel(classHierarchyDescriptorAddress,
			RTTI_CLASS_HIERARCHY_DESCRIPTOR_LABEL, classNamespace, SourceType.ANALYSIS);

		classHierarchyStructure = createClassHierarchyStructure(classHierarchyDescriptorAddress);

		if (classHierarchyStructure == null) {
			println("Failed to create a classHierarchyDescriptor structure at " +
				classHierarchyDescriptorAddress.toString());
			symbolTable.removeSymbolSpecial(classHierarchySymbol);
			return null;
		}
		return classHierarchyDescriptorAddress;
	}

	/**
	 * Method to create a ClassHierarchyDescriptor structure at the given address 
	 * @param classHierarchyDescriptorAddress the address where the structure will be created
	 * @return the created ClassHierarchyDescriptor data or null if it couldn't be created
	 * @throws CancelledException if cancelled
	 * @throws AddressOutOfBoundsException if try clear listing at address out of bounds
	 * @throws Exception if issue creating data
	 */
	private Data createClassHierarchyStructure(Address classHierarchyDescriptorAddress)
			throws CancelledException, AddressOutOfBoundsException, Exception {

		DataType classHDatatype = dataTypeManager.getDataType(CategoryPath.ROOT,
			RTTI_CLASS_HIERARCHY_DESCRIPTOR_DATA_NAME);
		int sizeOfDt = classHDatatype.getLength();
		clearListing(classHierarchyDescriptorAddress,
			classHierarchyDescriptorAddress.add(sizeOfDt));

		Data classHierarchyStructure = createData(classHierarchyDescriptorAddress, classHDatatype);
		if (classHierarchyStructure == null) {
			return null;
		}
		return classHierarchyStructure;
	}

	/**
	 * 
	 * @param classHierarchyDescriptors the given list of applied ClassHierarchyDescriptor structures
	 * @return a list of base class array addresses
	 * @throws CancelledException if cancelled
	 * @throws MemoryAccessException if memory cannot be read
	 * @throws AddressOutOfBoundsException if try clear listing at address out of bounds
	 * @throws Exception if there is an issue creating a label
	 */
	private List<Address> createMissingBaseClassArrays(List<Address> classHierarchyDescriptors)
			throws CancelledException, MemoryAccessException, AddressOutOfBoundsException,
			Exception {

		List<Address> baseClassArrayAddresses = new ArrayList<Address>();

		Iterator<Address> classHierarchyDescriptorIterator = classHierarchyDescriptors.iterator();

		while (classHierarchyDescriptorIterator.hasNext()) {

			monitor.checkCanceled();

			Address classHierarchyDescriptorAddress = classHierarchyDescriptorIterator.next();
			Symbol classHierarchyDescriptorSymbol =
				symbolTable.getPrimarySymbol(classHierarchyDescriptorAddress);
			Namespace classNamespace = classHierarchyDescriptorSymbol.getParentNamespace();

			int numBaseClasses = getInt(classHierarchyDescriptorAddress.add(8));

			Address baseClassArrayAddress =
				getReferencedAddress(classHierarchyDescriptorAddress.add(12));

			Data baseClassDescArray = getDataAt(baseClassArrayAddress);

			if (baseClassDescArray != null && baseClassDescArray.isArray()) {
				baseClassArrayAddresses.add(baseClassArrayAddress);
				continue;
			}

			baseClassDescArray = createBaseClassArray(baseClassArrayAddress, numBaseClasses);
			if (baseClassDescArray != null && baseClassDescArray.isArray()) {
				Symbol primarySymbol = symbolTable.getPrimarySymbol(baseClassArrayAddress);
				if (primarySymbol == null ||
					!primarySymbol.getName().contains(RTTI_BASE_CLASS_ARRAY_LABEL)) {

					symbolTable.createLabel(baseClassArrayAddress, RTTI_BASE_CLASS_ARRAY_LABEL,
						classNamespace, SourceType.ANALYSIS);
				}
				baseClassArrayAddresses.add(baseClassArrayAddress);
				createBaseClassDescriptors(baseClassArrayAddress, numBaseClasses, classNamespace);
				continue;
			}

			println("Failed to create a baseClassDescArray structure at " +
				baseClassArrayAddress.toString());
		}
		return baseClassArrayAddresses;
	}

	/**
	 * Method to create a base class array at the given address with the given number of base class's in the array
	 * @param baseClassArrayAddress the address where the array will be created
	 * @param numBaseClasses the number of BaseClass's in the array 
	 * @return the created BaseClassArray data or null if cannot retrieve it
	 * @throws CancelledException if cancelled
	 * @throws Exception if error creating data
	 */
	private Data createBaseClassArray(Address baseClassArrayAddress, int numBaseClasses)
			throws CancelledException, Exception {

		int sizeOfDt;
		ArrayDataType baseClassDescArrayDT;

		int addressSize = baseClassArrayAddress.getSize();
		if (addressSize == 32) {
			DataType baseClassDescriptor = dataTypeManager.getDataType(CategoryPath.ROOT,
				RTTI_BASE_CLASS_DESCRIPTOR_DATA_NAME);
			PointerDataType baseClassDescriptorPtr = new PointerDataType(baseClassDescriptor);
			sizeOfDt = baseClassDescriptorPtr.getLength();

			baseClassDescArrayDT =
				new ArrayDataType(baseClassDescriptorPtr, numBaseClasses, sizeOfDt);
		}
		else if (addressSize == 64) {
			DataType imageBaseOffset =
				dataTypeManager.getDataType(CategoryPath.ROOT, "ImageBaseOffset32");
			sizeOfDt = imageBaseOffset.getLength();
			baseClassDescArrayDT = new ArrayDataType(imageBaseOffset, numBaseClasses, sizeOfDt);
		}
		else {
			return null;
		}

		clearListing(baseClassArrayAddress, baseClassArrayAddress.add(numBaseClasses * sizeOfDt));
		Data baseClassDescArray = createData(baseClassArrayAddress, baseClassDescArrayDT);

		if (baseClassDescArray == null) {
			return null;
		}
		return baseClassDescArray;
	}

	/**
	 * Method to create missing vftables and return a list of them
	 * @param completeObjectLocatorSymbols the list of completeObjectLocatorSymbols
	 * @return list of vftable symbols
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException  if invalid input
	 * @throws CircularDependencyException  if namespace has circular dependency
	 * @throws DuplicateNameException if try to create label with duplicate name in namespace
	 */
	private List<Symbol> createMissingVftableSymbols(List<Symbol> completeObjectLocatorSymbols)
			throws CancelledException, InvalidInputException, DuplicateNameException,
			CircularDependencyException {

		List<Symbol> vftables = new ArrayList<Symbol>();

		Iterator<Symbol> iterator = completeObjectLocatorSymbols.iterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			Symbol completeObjectLocatorSymbol = iterator.next();

			Address completeObjectLocatorAddress = completeObjectLocatorSymbol.getAddress();

			Namespace classNamespace = completeObjectLocatorSymbol.getParentNamespace();
			if (classNamespace.equals(globalNamespace)) {
				println("no class namespace for " + completeObjectLocatorAddress.toString());
				continue;
			}

			Reference[] referencesTo = getReferencesTo(completeObjectLocatorAddress);
			if (referencesTo.length == 0) {
				println("no refs to " + completeObjectLocatorAddress.toString());
				continue;
			}

			for (Reference refTo : referencesTo) {
				Address vftableMetaPointer = refTo.getFromAddress();
				if (vftableMetaPointer == null) {
					println("can't retrieve meta address");
					continue;
				}
				Address vftableAddress = vftableMetaPointer.add(defaultPointerSize);
				if (vftableAddress == null) {
					println("can't retrieve vftable address");
					continue;
				}

				// if not created, create vftable meta pointer label

				if (getGivenSymbol(vftableAddress, VFTABLE_META_PTR_LABEL,
					classNamespace) == null) {

					symbolTable.createLabel(vftableMetaPointer, VFTABLE_META_PTR_LABEL,
						classNamespace, SourceType.ANALYSIS);
				}

				// if not created, create vftable label
				Symbol vftableSymbol =
					getGivenSymbol(vftableAddress, VFTABLE_LABEL, classNamespace);
				if (vftableSymbol == null) {

					vftableSymbol = symbolTable.createLabel(vftableAddress, VFTABLE_LABEL,
						classNamespace, SourceType.ANALYSIS);

					if (vftableSymbol == null) {
						continue;
					}
				}

				if (!vftables.contains(vftableSymbol)) {
					vftables.add(vftableSymbol);
				}

			}
		}
		return vftables;
	}

	/**
	 * Method to retrieve the symbol with the given address, containing name (containing to account
	 * for pdb case where sometimes has extra chars) and namespace
	 * @param address the given address
	 * @param name the given name
	 * @param namespace the given namespace
	 * @return the symbol with the given address, containing name, with given namespace
	 * @throws CancelledException if cancelled
	 */
	private Symbol getGivenSymbol(Address address, String name, Namespace namespace)
			throws CancelledException {

		SymbolIterator symbols = symbolTable.getSymbolsAsIterator(address);
		for (Symbol sym : symbols) {
			monitor.checkCanceled();
			if (sym.getName().contains(name) && sym.getParentNamespace().equals(namespace)) {
				return sym;
			}
		}
		return null;
	}

	/**
	 * Method to return referenced address at the given address
	 * @param address the address to look for a referenced address at
	 * @return the first referenced address from the given address
	 * @throws MemoryAccessException if memory cannot be read
	 */
	private Address getReferencedAddress(Address address) throws MemoryAccessException {

		//TODO: switch to this then test then just rewrite the call and get rid of this method
		// MSDataTypeUtils.getReferencedAddress(currentProgram, address);
		// this will work whether there is a created reference or not
		int addressSize = address.getSize();
		if (addressSize == 32) {
			long offset = getInt(address);

			return address.getNewAddress(offset);
		}

		// this currently will workn only if there is a created reference
		// TODO: get ibo bytes and figure out what the ibo ref address would be
		if (addressSize == 64) {
			Reference refs[] = getReferencesFrom(address);
			if (refs.length == 0) {
				return null;
			}
			return refs[0].getToAddress();
		}
		return null;
	}

	/**
	 * Method to retrieve the AddressSet of the current program's initialized memory
	 * @return the AddressSet of the current program's initialized memory
	 * @throws CancelledException if cancelled
	 */
	private AddressSet getInitializedMemory() throws CancelledException {

		AddressSet dataAddresses = new AddressSet();
		MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

		for (MemoryBlock block : blocks) {
			monitor.checkCanceled();

			if (block.isInitialized()) {
				dataAddresses.add(block.getStart(), block.getEnd());
			}
		}
		return dataAddresses;
	}

}
