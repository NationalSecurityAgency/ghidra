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
//DO NOT RUN. THIS IS NOT A SCRIPT! THIS IS A CLASS THAT IS USED BY SCRIPTS.
package classrecovery;

import java.util.*;

import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.decompiler.util.FillOutStructureHelper.OffsetPcodeOpPair;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class RTTIWindowsClassRecoverer extends RTTIClassRecoverer {

	//TODO: make a passed in param
	private static final boolean USE_SHORT_TEMPLATE_NAMES_IN_STRUCTURE_FIELDS = true;

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
//	private static final String VFTABLE_LABEL = "vftable";

	private static final String CLASS_VTABLE_STRUCT_NAME = "_vbtable";
	private static final String CLASS_VTABLE_PTR_FIELD_EXT = "vftablePtr";

	private static final int CHD_MULTINH = 0x00000001; //Multiple inheritance
	private static final int CHD_VIRTINH = 0x00000002; //Virtual inheritance
	private static final int CHD_AMBIGUOUS = 0x00000004; //Multiple inheritance with repeated base classes
	private static final int NONE = -1;
	private static final int UNKNOWN = -2;

	private static final String DELETING_DESTRUCTOR = "deleting_destructor";
	private static final String SCALAR_DELETING_DESCTRUCTOR = "scalar_deleting_destructor";
	private static final String VECTOR_DELETING_DESCTRUCTOR = "vector_deleting_destructor";

	boolean isPDBLoaded;

	public RTTIWindowsClassRecoverer(Program program, ServiceProvider serviceProvider,
			FlatProgramAPI api, boolean createBookmarks, boolean useShortTemplates,
			boolean nameVFunctions, boolean isPDBLoaded, TaskMonitor monitor) throws Exception {

		super(program, serviceProvider, api, createBookmarks, useShortTemplates, nameVFunctions,
			isPDBLoaded, monitor);

		this.isPDBLoaded = isPDBLoaded;
	}

	@Override
	public boolean containsRTTI() throws CancelledException {

		if (!hasTypeInfoVftable()) {
			return false;
		}

		return true;
	}

	@Override
	public boolean isValidProgramType() {
		if (!isVisualStudioOrClangPe()) {
			return false;
		}
		return true;
	}

	@Override
	public void fixUpProgram() throws CancelledException, Exception {

		if (ghidraVersion.compareTo("10.0") < 0) {

			fixUpRttiAnalysis();

		}
		// if there are undefined areas that reference vftables attempt to create functions
		// containing them
		List<Symbol> vftableSymbols = getListOfVftableSymbols();

		createMissingFunctions(vftableSymbols);

		return;
	}

	@Override
	public List<RecoveredClass> createRecoveredClasses() throws Exception {

		List<Symbol> vftableSymbols;

		vftableSymbols = getListOfVftableSymbols();

		List<RecoveredClass> recoveredClasses =
			recoverClassesFromClassHierarchyDescriptors(vftableSymbols);

		determineVftableOffsetsfromRTTI(recoveredClasses);

		// If no new classes have been recovered, no need to continue. Return out of script.
		if (recoveredClasses.isEmpty()) {

			return recoveredClasses;
		}

		// figure out class hierarchies using either RTTI or vftable refs
		monitor.setMessage("Assigning class inheritance and hierarchies");
		assignClassInheritanceAndHierarchies(recoveredClasses);

		// Since PDB has applied so much information, use it to figure out the class member data 4
		// items (if it has them) and the constructors and destructors. 
		if (isPDBLoaded) {
			monitor.setMessage(
				"Attempting to use pdb to assign class hierarchies and extend known pdb data " +
					"type information ...");

			retrieveExistingClassStructures(recoveredClasses);

			// assign constructors and destructors based on name
			assignConstructorsAndDestructorsUsingExistingName(recoveredClasses);
		}
		// otherwise figure everything out from scratch
		else {
			monitor.setMessage("Figuring out class method types");
			processConstructorAndDestructors(recoveredClasses);

		}

		// create order of vftable in constructor map for each class that has a constructor so far
		createVftableOrderMap(recoveredClasses);

		determineParentClassInfoFromBaseClassArray(recoveredClasses);

		assignParentClassToVftables(recoveredClasses);

		// using all the information found above, create the class structures, add the constructor,
		// destructor, vfunctions to class which finds the appropriate class structure and assigns 
		// to "this" param
		monitor.setMessage("Creating class data types and applying class structures");
		figureOutClassDataMembers(recoveredClasses);

		if (USE_SHORT_TEMPLATE_NAMES_IN_STRUCTURE_FIELDS) {
			extendedFlatAPI.createShortenedTemplateNamesForClasses(recoveredClasses);
		}

		createAndApplyClassStructures(recoveredClasses);

		// fix purecall vfunction definitions
		fixupPurecallFunctionDefs();

		if (!isPDBLoaded) {
			// create better vftable labels for multi vftable classes
			updateMultiVftableLabels(recoveredClasses);
			removeEmptyClassesAndStructures();

			// fix up deleting destructors to have vector and scalar names and to split 
			// non-contiguous ones into two seaparate functions
			fixUpDeletingDestructors(recoveredClasses);
		}

		return recoveredClasses;

	}

	private boolean isVisualStudioOrClangPe() {
		return program.getExecutableFormat().equals(PeLoader.PE_NAME) &&
			(program.getCompiler().equals(CompilerEnum.VisualStudio.toString()) ||
				program.getCompiler().equals(CompilerEnum.Clang.toString()));
	}

	private boolean hasTypeInfoVftable() throws CancelledException {

		List<Symbol> vftableSymbols = getListOfVftableSymbols();

		for (Symbol symbol : vftableSymbols) {
			monitor.checkCancelled();
			if (symbol.getParentNamespace().getName().equals("type_info")) {
				return true;
			}
		}
		return false;
	}

//	/**
//	 * Method to determine if the current program has RTTI data applied to it
//	 * @return true if the current program has RTTI data applied to it
//	 * @throws CancelledException if cancelled
//	 */
//	private boolean programHasRTTIApplied() throws CancelledException {
//
//		// First check to see if the RTTICompleteObjectLocator data type exists. If not there has
//		// been no RTTI applied
//		DataType completeObjLocatorDataType = dataTypeManager.getDataType(CategoryPath.ROOT,
//			RTTI_BASE_COMPLETE_OBJECT_LOADER_DATA_NAME);
//		if (completeObjLocatorDataType == null) {
//			return false;
//		}
//
//		// Next check that a RTTICompleteObjectLocator has been applied somewhere to make sure that
//		// we don't have the case where pdb ran and created the data type but rtti didn't run so didn't
//		// apply any of the data types
//		return hasSymbolAndDataType(RTTI_BASE_COMPLETE_OBJECT_LOADER_LABEL,
//			completeObjLocatorDataType);
//	}
//
//	private void runRTTIAnalyzer() throws Exception {
////		Analyzer analyzer = new RttiAnalyzer();
////		analyzer.added(program, program.getAddressFactory().getAddressSet(), monitor,
////			new MessageLog());
//	}
//
//	/**
//	 * Method to find all the vftables in the program 
//	 * @return list of all vftable symbols
//	 * @throws CancelledException when cancelled
//	 */
//	//TODO: pull into separate methods and check separately above
//	private boolean hasSymbolAndDataType(String symbolName, DataType datatype)
//			throws CancelledException {
//
//		String pdbName = "`" + symbolName + "'";
//		SymbolIterator symbols =
//			program.getSymbolTable().getSymbolIterator("*" + symbolName + "*", true);
//
//		while (symbols.hasNext()) {
//			monitor.checkCancelled();
//			Symbol symbol = symbols.next();
//			if (symbol.getName().equals(symbolName) || symbol.getName().equals(pdbName)) {
//				Data dataAt = program.getListing().getDefinedDataAt(symbol.getAddress());
//				if (dataAt.getDataType().equals(datatype)) {
//					return true;
//				}
//			}
//
//		}
//		return false;
//	}

	public void fixUpRttiAnalysis() throws CancelledException, Exception {
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
			monitor.checkCancelled();
			Symbol symbol = dataSymbols.next();
			if (!symbol.getName().contains(RTTI_BASE_COMPLETE_OBJECT_LOADER_LABEL)) {
				continue;
			}

			Data data = extendedFlatAPI.getDataAt(symbol.getAddress());
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

			Msg.debug(this, "Cannot create RTTI_CompleteObjectLocator at " + symbol.getAddress());

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

		api.clearListing(address, address.add(sizeOfDt));
		Data completeObjectLocator =
			extendedFlatAPI.createData(address, completeObjLocatorDataType);
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
			monitor.checkCancelled();
			Symbol symbol = dataSymbols.next();
			if (!symbol.getName().contains(RTTI_BASE_CLASS_DESCRIPTOR_LABEL)) {
				continue;
			}

			Data data = extendedFlatAPI.getDataAt(symbol.getAddress());
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

			Msg.debug(this, "Cannot create RTTI_Base_Class_Descriptor at " + symbol.getAddress());

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

		api.clearListing(baseClassDescriptorAddress, baseClassDescriptorAddress.add(sizeOfDt));
		Data baseClassDescArray =
			extendedFlatAPI.createData(baseClassDescriptorAddress, baseClassDescriptor);
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

			monitor.checkCancelled();
			//TODO: extendedFlatAPI.getReferencedAddress(address, getIboIf64bit);
			Address baseClassDescriptorAddress = getReferencedAddress(address.add(i * 4));

			Data baseClassDescriptor = extendedFlatAPI.getDataAt(baseClassDescriptorAddress);
			if (baseClassDescriptor == null || !baseClassDescriptor.getDataType()
					.getName()
					.equals(RTTI_BASE_CLASS_DESCRIPTOR_DATA_NAME)) {

				int num1 = extendedFlatAPI.getInt(baseClassDescriptorAddress.add(8));
				int num2 = extendedFlatAPI.getInt(baseClassDescriptorAddress.add(12));
				int num3 = extendedFlatAPI.getInt(baseClassDescriptorAddress.add(16));
				int num4 = extendedFlatAPI.getInt(baseClassDescriptorAddress.add(20));

				baseClassDescriptor = createBaseClassDescriptor(baseClassDescriptorAddress);
				if (baseClassDescriptor != null) {
					symbolTable.createLabel(
						baseClassDescriptorAddress, RTTI_BASE_CLASS_DESCRIPTOR_LABEL + "_at_(" +
							num1 + "," + num2 + "," + num3 + "," + num4 + ")",
						classNamespace, SourceType.ANALYSIS);
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

		for (Symbol symbol : baseClassDescriptors) {
			monitor.checkCancelled();
			Address classHierarchyDescriptorAddress = createClassHierarchyDescriptor(
				symbol.getAddress().add(24), symbol.getParentNamespace());

			if (classHierarchyDescriptorAddress != null &&
				!classHierarchyDescriptorAddresses.contains(classHierarchyDescriptorAddress)) {
				classHierarchyDescriptorAddresses.add(classHierarchyDescriptorAddress);
			}

		}

		for (Symbol symbol : completeObjectLocators) {
			monitor.checkCancelled();
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

		//TODO: extendedFlatAPI.getReferencedAddress(address, getIboIf64bit);
		Address classHierarchyDescriptorAddress = getReferencedAddress(address);

		Data classHierarchyStructure = extendedFlatAPI.getDataAt(classHierarchyDescriptorAddress);

		if (classHierarchyStructure != null && classHierarchyStructure.getDataType()
				.getName()
				.equals(RTTI_CLASS_HIERARCHY_DESCRIPTOR_DATA_NAME)) {
			return classHierarchyDescriptorAddress;

		}

		Symbol classHierarchySymbol;

		classHierarchySymbol = symbolTable.createLabel(classHierarchyDescriptorAddress,
			RTTI_CLASS_HIERARCHY_DESCRIPTOR_LABEL, classNamespace, SourceType.ANALYSIS);

		classHierarchyStructure = createClassHierarchyStructure(classHierarchyDescriptorAddress);

		if (classHierarchyStructure == null) {
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
		api.clearListing(classHierarchyDescriptorAddress,
			classHierarchyDescriptorAddress.add(sizeOfDt));

		Data classHierarchyStructure =
			extendedFlatAPI.createData(classHierarchyDescriptorAddress, classHDatatype);
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

		for (Address classHierarchyDescriptorAddress : classHierarchyDescriptors) {

			monitor.checkCancelled();

			Symbol classHierarchyDescriptorSymbol =
				symbolTable.getPrimarySymbol(classHierarchyDescriptorAddress);
			Namespace classNamespace = classHierarchyDescriptorSymbol.getParentNamespace();

			int numBaseClasses = extendedFlatAPI.getInt(classHierarchyDescriptorAddress.add(8));

			//TODO: extendedFlatAPI.getReferencedAddress(address, getIboIf64bit);
			Address baseClassArrayAddress =
				getReferencedAddress(classHierarchyDescriptorAddress.add(12));

			Data baseClassDescArray = extendedFlatAPI.getDataAt(baseClassArrayAddress);

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

			Msg.debug(this, "Failed to create a baseClassDescArray structure at " +
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

		api.clearListing(baseClassArrayAddress,
			baseClassArrayAddress.add(numBaseClasses * sizeOfDt));
		Data baseClassDescArray =
			extendedFlatAPI.createData(baseClassArrayAddress, baseClassDescArrayDT);

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

		for (Symbol completeObjectLocatorSymbol : completeObjectLocatorSymbols) {
			monitor.checkCancelled();
			Address completeObjectLocatorAddress = completeObjectLocatorSymbol.getAddress();

			Namespace classNamespace = completeObjectLocatorSymbol.getParentNamespace();
			if (classNamespace.equals(globalNamespace)) {
				Msg.debug(this,
					"No class namespace for " + completeObjectLocatorAddress.toString());
				continue;
			}

			Reference[] referencesTo =
				extendedFlatAPI.getReferencesTo(completeObjectLocatorAddress);
			if (referencesTo.length == 0) {
				Msg.debug(this, "No refs to " + completeObjectLocatorAddress.toString());
				continue;
			}

			for (Reference refTo : referencesTo) {
				Address vftableMetaPointer = refTo.getFromAddress();
				if (vftableMetaPointer == null) {
					continue;
				}
				Address vftableAddress = vftableMetaPointer.add(defaultPointerSize);
				if (vftableAddress == null) {
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
			monitor.checkCancelled();
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
			long offset = extendedFlatAPI.getInt(address);

			return address.getNewAddress(offset);
		}

		// this currently will workn only if there is a created reference
		// TODO: get ibo bytes and figure out what the ibo ref address would be
		if (addressSize == 64) {
			Reference refs[] = extendedFlatAPI.getReferencesFrom(address);
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
		MemoryBlock[] blocks = program.getMemory().getBlocks();

		for (MemoryBlock block : blocks) {
			monitor.checkCancelled();

			if (block.isInitialized()) {
				dataAddresses.add(block.getStart(), block.getEnd());
			}
		}
		return dataAddresses;
	}

	/**
	 * Method to fix up the current program so that script will be more successful by finding
	 * missing vftable referencing functions and missing RTTI data structures. 
	 * manually create some of them
	 * @throws CancelledException when cancelled
	 * @throws Exception when data cannot be created
	 */
	private void createMissingFunctions(List<Symbol> vftableSymbols)
			throws CancelledException, Exception {

		List<Address> unusedVftableReferences = findVftableReferencesNotInFunction(vftableSymbols);

		if (unusedVftableReferences.size() > 0) {
			extendedFlatAPI.createUndefinedFunctions(unusedVftableReferences);
		}

		// create these automatically if found
		findFunctionsUsingAtexit();
	}

	/**
	 * Method to recover the class information for each vftable symbol on the list
	 * * For each virtual function table:
	 * 1. get vftable's existing class
	 * 2. create matching data type category folder in dt manager
	 * 3. get list of virtual functions
	 * 4. create RecoveredClass object for the vftable class
	 * 5. add mapping from vftableAddress to class
	 * 6. add list of const/dest functions to RecoveredClass object
	 * 7. update list of all const/dest functions in currenetProgram
	 * 8. set RecoveredClass indeterminate list to const/dest list 
	 * 9. update list of all indeterminate const/dest
	 * @param vftableSymbols List of vftable symbols
	 * @return List of RecoveredClass objects created corresponding to the vftable symbols
	 * @throws CancelledException if cancelled
	 * @throws Exception if issue creating data
	 */
	private List<RecoveredClass> recoverClassesFromClassHierarchyDescriptors(
			List<Symbol> vftableSymbols) throws CancelledException, Exception {

		List<RecoveredClass> recoveredClasses = new ArrayList<RecoveredClass>();

		List<Symbol> classHierarchyDescriptorList = getListOfClassHierarchyDescriptors();

		for (Symbol classHierarchyDescriptorSymbol : classHierarchyDescriptorList) {
			monitor.checkCancelled();
			Address classHierarchyDescriptorAddress = classHierarchyDescriptorSymbol.getAddress();

			// Get class name from class vftable is in
			Namespace classNamespace = classHierarchyDescriptorSymbol.getParentNamespace();
			if (classNamespace.isGlobal()) {
				Msg.warn(this, "ClassHierarchyDescriptor at " + classHierarchyDescriptorAddress +
					" is unexpectedly in the Global namespace so processing cannot continue for " +
					"this class");
				continue;
			}
			// get the data type category associated with the given class namespace
			Category category = getDataTypeCategory(classNamespace);

			// if it already exists, continue since this class has already been recovered
			if (category != null) {
				continue;
			}

			if (classNamespace.getSymbol().getSymbolType() != SymbolType.CLASS) {
				classNamespace = promoteToClassNamespace(classNamespace);
				if (classNamespace.getSymbol().getSymbolType() != SymbolType.CLASS) {
					Msg.debug(this,
						classHierarchyDescriptorAddress.toString() + " Could not promote " +
							classNamespace.getName(true) + " to a class namespace.");
					continue;
				}
			}

			List<Symbol> vftableSymbolsInNamespace = getClassVftableSymbols(classNamespace);

			//if there are no vftables in this class then create a new class object and make it 
			// non-vftable class
			if (vftableSymbolsInNamespace.size() == 0) {
				String className = classNamespace.getName();

				// Make a CategoryPath for given class
				CategoryPath classPath = extendedFlatAPI
						.createDataTypeCategoryPath(classDataTypesCategoryPath, classNamespace);

				RecoveredClass nonVftableClass =
					new RecoveredClass(className, classPath, classNamespace, dataTypeManager);
				nonVftableClass.setHasVftable(false);
				// add recovered class to map
				if (getClass(classNamespace) == null) {
					updateNamespaceToClassMap(classNamespace, nonVftableClass);

					// add it to the running list of RecoveredClass objects
					recoveredClasses.add(nonVftableClass);
				}
			}
			// if there are vftables in the class, call the method to make
			// a new class object using the vftable info 
			else {
				List<RecoveredClass> classesWithVftablesInNamespace =
					recoverClassesFromVftables(vftableSymbolsInNamespace, false, false);
				if (classesWithVftablesInNamespace.size() == 0) {
					Msg.debug(this, "No class recovered for namespace " + classNamespace.getName());
					continue;
				}
				if (classesWithVftablesInNamespace.size() > 1) {
					Msg.debug(this, "Unexpected multiple classes recovered for namespace " +
						classNamespace.getName());
					continue;
				}

				recoveredClasses.add(classesWithVftablesInNamespace.get(0));

			}

		}

		return recoveredClasses;
	}

	/**
	 * Method to get a list of RTTI_Base_Class_Descriptor symbols
	 * @return List of Symbols named "RTTI_Class_Hierarchy_Descriptor"
	 * @throws CancelledException if cancelled
	 */
	private List<Symbol> getListOfClassHierarchyDescriptors() throws CancelledException {

		List<Symbol> classHierarchyDescriptorList = extendedFlatAPI.getListOfSymbolsInAddressSet(
			getInitializedMemory(), RTTI_CLASS_HIERARCHY_DESCRIPTOR_LABEL, false);

		return classHierarchyDescriptorList;
	}

	/**
	 * Method to create map for each class containing offset in class structure for each class vftable using information
	 * found in the class's complete object locator structure(s)
	 * @param recoveredClasses List of classes
	 * @throws Exception when cancelled
	 */
	private void determineVftableOffsetsfromRTTI(List<RecoveredClass> recoveredClasses)
			throws AddressOutOfBoundsException, Exception {

		PointerDataType pointerDataType = new PointerDataType();

		for (RecoveredClass recoveredClass : recoveredClasses) {
			monitor.checkCancelled();
			List<Address> vftableAddresses = recoveredClass.getVftableAddresses();
			for (Address vftableAddress : vftableAddresses) {
				monitor.checkCancelled();
				Address ptrToColAddress = vftableAddress.subtract(defaultPointerSize);

				Data pointerToCompleteObjLocator = extendedFlatAPI.getDataAt(vftableAddress);
				if (pointerToCompleteObjLocator == null) {
					pointerToCompleteObjLocator =
						extendedFlatAPI.createData(ptrToColAddress, pointerDataType);
				}

				Address colAddress = extendedFlatAPI.getReferencedAddress(ptrToColAddress, false);

				if (colAddress == null) {
					Msg.debug(this, recoveredClass.getName() +
						" couldn't get referenced col from " + ptrToColAddress.toString());
					continue;
				}

				Address addressOfOffset = colAddress.add(4);

				int offset = extendedFlatAPI.getInt(addressOfOffset);

				recoveredClass.addClassOffsetToVftableMapping(offset, vftableAddress);
			}

		}

	}

	/**
	 * Method to figure out the class hierarchies either with RTTI if it is present or with vftable 
	 * references
	 * @param recoveredClasses List of classes to process
	 * @throws Exception various exceptions
	 */
	private void assignClassInheritanceAndHierarchies(List<RecoveredClass> recoveredClasses)
			throws Exception {

		// Use RTTI information to determine inheritance type and 
		// class hierarchy
		Iterator<RecoveredClass> recoveredClassesIterator = recoveredClasses.iterator();
		while (recoveredClassesIterator.hasNext()) {
			monitor.checkCancelled();

			RecoveredClass recoveredClass = recoveredClassesIterator.next();

			int inheritanceFlag = getClassInheritanceFlag(recoveredClass.getClassNamespace());
			if (inheritanceFlag == NONE) {
				Msg.debug(this,
					"Could not get inheritance attribute from class hierarchy structure for " +
						"class " + recoveredClass.getName());
				recoveredClassesIterator.remove();
				continue;
			}
			setClassInheritanceType(recoveredClass, inheritanceFlag);

		}
		getClassHierarchyFromRTTI(recoveredClasses);
	}

	/**
	 * Use information from RTTI Base class Arrays to create class hierarchy lists and maps
	 * @param recoveredClasses list of classes to process
	 * @throws CancelledException if cancelled
	 */
	//TODO: split into two methods so I can reuse last part for gcc too
	private void getClassHierarchyFromRTTI(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		// go through first collecting the class hierarchy lists from the RTTI
		// determine inheritance type
		// add parents if single inheritance
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			List<RecoveredClass> classHierarchyFromRTTI = getClassHierarchyFromRTTI(recoveredClass);

			if (classHierarchyFromRTTI.size() == 0) {
				throw new IllegalArgumentException("Unexpected empty class hierarchy for " +
					recoveredClass.getClassNamespace().getName(true));
			}

			if (classHierarchyFromRTTI.size() > 0) {
				recoveredClass.setClassHierarchy(classHierarchyFromRTTI);

				// if single inheritance flag either no parent or one parent
				if (recoveredClass.hasSingleInheritance()) {

					// update class accordingly with a parent or no parent
					assignSingleInheritanceAncestorsUsingHierarchyList(classHierarchyFromRTTI);

					// if a parent, update class hierarchy map
					List<RecoveredClass> parentList = recoveredClass.getParentList();
					if (parentList.size() == 1) {

						RecoveredClass parentClass = parentList.get(0);
						recoveredClass.addClassHierarchyMapping(parentClass,
							parentClass.getClassHierarchy());
					}

				}
			}

		}

		// Now that all hierarchy lists are collected iterate again and process the multi-inherited 
		// ones using the single hierarchy lists to help determine direct parents
		recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			if (recoveredClass.hasMultipleInheritance()) {

				List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();

				if (classHierarchy.size() <= 1) {
					throw new IllegalArgumentException(
						"Class hierarchy for class should be more than 1 since it has multiple inheritance" +
							recoveredClass.getClassNamespace().getName(true));
				}
				int index = 1;
				while (index < classHierarchy.size()) {
					monitor.checkCancelled();
					RecoveredClass parentClass = classHierarchy.get(index);
					List<RecoveredClass> parentClassHierarchy = parentClass.getClassHierarchy();
					if (parentClassHierarchy.size() < 1) {
						// shouldn't get here since the first loop should have removed all classes
						// with incorrect class hierarchy
						throw new IllegalArgumentException(
							"Parent class has empty class hierarchy " +
								parentClass.getClassNamespace().getName(true));
					}
					recoveredClass.addClassHierarchyMapping(parentClass, parentClassHierarchy);
					updateClassWithParent(parentClass, recoveredClass);
					index += parentClassHierarchy.size();
				}
			}

		}

	}

	/**
	 * Method to assign parent classes given an ordered list of hierarchy
	 * child, parent, grandparent, ... for single inheritance case
	 * @param hierarchyList ordered list of class hierarchy starting with child
	 * @throws CancelledException if cancelled
	 */
	private void assignSingleInheritanceAncestorsUsingHierarchyList(
			List<RecoveredClass> hierarchyList) throws CancelledException {

		RecoveredClass currentClass = hierarchyList.get(0);

		ListIterator<RecoveredClass> listIterator = hierarchyList.listIterator(1);
		while (listIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass parentClass = listIterator.next();

			if (!currentClass.hasParentClass()) {
				updateClassWithParent(parentClass, currentClass);
			}

			currentClass = parentClass;
		}

	}

	/**
	 * Determine class hierarchies using RTTI Base Class Array info
	 * @param recoveredClass current class
	 * @return List of classes representing current class's hierarchy
	 * @throws CancelledException if cancelled
	 */
	private List<RecoveredClass> getClassHierarchyFromRTTI(RecoveredClass recoveredClass)
			throws CancelledException {

		List<RecoveredClass> classHierarchy = new ArrayList<RecoveredClass>();

		List<Symbol> symbols = extendedFlatAPI.getListOfSymbolsByNameInNamespace(
			RTTI_BASE_CLASS_ARRAY_LABEL, recoveredClass.getClassNamespace(), false);

		if (symbols.size() == 1) {
			Symbol rttiBaseClassSymbol = symbols.get(0);
			Address rttiBaseClassAddress = rttiBaseClassSymbol.getAddress();
			Data rttiBaseClassDescriptorArray = api.getDataAt(rttiBaseClassAddress);
			int numPointers = rttiBaseClassDescriptorArray.getNumComponents();

			for (int i = 0; i < numPointers; ++i) {
				monitor.checkCancelled();

				// Get the  it is pointing to
				Address pointerAddress = rttiBaseClassDescriptorArray.getComponent(i).getAddress();

				Address baseClassDescriptorAddress =
					extendedFlatAPI.getSingleReferencedAddress(pointerAddress);

				if (baseClassDescriptorAddress == null) {
					throw new IllegalArgumentException(
						"Missing expected pointer at " + pointerAddress.toString());
					//return classHierarchy;
				}

				Symbol primarySymbol = symbolTable.getPrimarySymbol(baseClassDescriptorAddress);
				if (primarySymbol == null) {
					throw new IllegalArgumentException(
						"Missing expected BaseClassDescriptor symbol at " +
							baseClassDescriptorAddress.toString());
					//return classHierarchy;
				}

				Namespace pointedToNamespace = primarySymbol.getParentNamespace();
				if (pointedToNamespace == null) {
					throw new IllegalArgumentException("Missing expected class namesapce at " +
						baseClassDescriptorAddress.toString());
					//return classHierarchy;
				}

				// if the namespace isn't in the map then it is a class 
				// without a vftable and a new RecoveredClass object needs to be created
				if (getClass(pointedToNamespace) == null) {
					createNewClass(pointedToNamespace, false);
				}

				RecoveredClass pointedToClass = getClass(pointedToNamespace);

				if (classHierarchy.size() > 0 &&
					classHierarchy.get(classHierarchy.size() - 1).equals(pointedToClass)) {
					continue;
				}

				classHierarchy.add(pointedToClass);

			}
		}
		else if (symbols.size() > 1) {
			throw new IllegalArgumentException("More than one Base Class Array for " +
				recoveredClass.getClassNamespace().getName(true));
		}
		return classHierarchy;
	}

	/**
	 * Method to get class inheritance flag from the RTTIClassHierarchyDescriptor structure
	 * @param classNamespace the given class namespace
	 * @return the class inheritance flag or NONE if there isn't one
	 * @throws CancelledException if cancelled
	 * @throws MemoryAccessException if memory cannot be read
	 * @throws AddressOutOfBoundsException if try reading memory out of bounds
	 */
	private int getClassInheritanceFlag(Namespace classNamespace)
			throws CancelledException, MemoryAccessException, AddressOutOfBoundsException {

		List<Symbol> symbols = extendedFlatAPI.getListOfSymbolsByNameInNamespace(
			RTTI_CLASS_HIERARCHY_DESCRIPTOR_LABEL, classNamespace, false);

		if (symbols.size() >= 1) {
			return (extendedFlatAPI.getInt(symbols.get(0).getAddress().add(4)));
		}

		return NONE;
	}

	/**
	 * Method to set the class inheritance type based on Class Hierarchy Descriptor inheritance
	 * attribute flag: 
	 * bit 0: 0 = single inheritance/ 1 = multiple inheritance
	 * bit 1: 0 = non-virtual inheritance / 1 = virtual inheritance
	 * bit 2: 0 = non-ambiguous case / 1 = ambiguous (ie multiple inheritance with repeated base classes)
	 * @param recoveredClass the given class
	 * @param inheritanceType the inheritance type to set in the class object
	 */
	private void setClassInheritanceType(RecoveredClass recoveredClass, int inheritanceType) {

		// TODO: add multi-repeated base inh flag? 

		if ((inheritanceType & CHD_MULTINH) == 0) {
			recoveredClass.setHasSingleInheritance(true);
			recoveredClass.setHasMultipleInheritance(false);

			if ((inheritanceType & CHD_VIRTINH) == 0) {
				recoveredClass.setInheritsVirtualAncestor(false);
			}
			// Flag indicates single inheritance virtual ancestor for class " +
			//	recoveredClass.getName());
			else {
				recoveredClass.setInheritsVirtualAncestor(true);
			}
		}
		else {
			recoveredClass.setHasSingleInheritance(false);
			recoveredClass.setHasMultipleInheritance(true);
			if ((inheritanceType & CHD_VIRTINH) == 0) {
				recoveredClass.setHasMultipleVirtualInheritance(false);
			}

			// Flag indicates multiple inheritance virtual ancestor for class " +
			// recoveredClass.getName());
			else {
				recoveredClass.setHasMultipleVirtualInheritance(true);
			}
		}

		//TODO: update class to handle this type 
		if ((inheritanceType & CHD_AMBIGUOUS) == CHD_AMBIGUOUS) {
			recoveredClass.setHasSingleInheritance(false);
			recoveredClass.setHasMultipleInheritance(true);
			Msg.debug(this, recoveredClass.getName() + " has ambiguous inh type");
		}

	}

	/**
	 * Method to call the various methods to determine whether the functions that make references to
	 * the vftables are constructors, destructors, deleting destructors, clones, or vbase functions
	 * @param recoveredClasses List of classes
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting function return
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @Exception if issues making labels
	 */
	private void processConstructorAndDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException, Exception {

		List<Address> allVftables = getAllVftables();

		// update the class lists to narrow the class objects possible cd lists and indeterminate 
		// lists to remove functions that are also on vfunction lists
		trimConstructorDestructorLists(recoveredClasses, allVftables);

		determineOperatorDeleteAndNewFunctions(allVftables);

		// find deleting destructors 
		findDeletingDestructors(recoveredClasses, allVftables);

		// use atexit param list to find more destructors
		findDestructorsUsingAtexitCalledFunctions(recoveredClasses);

		// figure out which are inlined and put on separate list to be processed later
		separateInlinedConstructorDestructors(recoveredClasses);

		// figure out which member functions are constructors and which are destructors
		// using the order their parents are called		
		processRegularConstructorsAndDestructorsUsingCallOrder(recoveredClasses);

		// determine which of the inlines are constructors and which are destructors
		processInlinedConstructorsAndDestructors(recoveredClasses);

		findConstructorsAndDestructorsUsingAncestorClassFunctions(recoveredClasses);

		findInlineConstructorsAndDestructorsUsingRelatedClassFunctions(recoveredClasses);

		// use the load/store information from decompiler to figure out as many of the 
		// ones that could not be determined in earlier stages
		processRemainingIndeterminateConstructorsAndDestructors(recoveredClasses);

		// use the known constructors and known vfunctions to figure out basic clone functions
		findBasicCloneFunctions(recoveredClasses);

		// This has to be here. It needs all the info from the previously run methods to do this.
		// Finds the constructors that have multiple basic blocks, reference the vftable not in the 
		// first block, and call non-parent constructors and non operator new before the vftable ref
		findMoreInlinedConstructors(recoveredClasses);

		findDestructorsWithNoParamsOrReturn(recoveredClasses);

		// use vftables with references to all the same function (except possibly one deleting 
		// destructor)to find the purecall function
		identifyPureVirtualFunction(recoveredClasses);

		findRealVBaseFunctions(recoveredClasses);

		// make constructors and destructors _thiscalls 
		makeConstructorsAndDestructorsThiscalls(recoveredClasses);

	}

	/**
	 * Method to recover parent information, including class offsets, vbase structure and its offset and address if applicable, and whether
	 * the parent is regularly or virtually inherited
	 * @param recoveredClasses List of classes to process
	 * @throws Exception when cancelled
	 */
	private void determineParentClassInfoFromBaseClassArray(List<RecoveredClass> recoveredClasses)
			throws Exception {

		for (RecoveredClass recoveredClass : recoveredClasses) {
			monitor.checkCancelled();

			boolean hasVirtualAncestor = false;
			int vbaseOffset = NONE;

			// iterate over base class array and for each parent class of the given recovered class 
			// get the mdisp, pdisp, vdisp info
			List<Symbol> baseClassArray = extendedFlatAPI.getListOfSymbolsByNameInNamespace(
				RTTI_BASE_CLASS_ARRAY_LABEL, recoveredClass.getClassNamespace(), false);

			// this should never happen
			if (baseClassArray.size() != 1) {
				throw new Exception(
					recoveredClass.getName() + " has more than one RTTI base class array");
			}

			Address baseClassArrayAddress = baseClassArray.get(0).getAddress();
			Data baseClassArrayData = api.getDataAt(baseClassArrayAddress);

			if (!baseClassArrayData.isArray()) {
				throw new Exception(
					recoveredClass.getName() + " RTTI base class array is not an array data type " +
						baseClassArrayAddress.toString());

			}

			StructureDataType vbaseStructure = new StructureDataType(recoveredClass.getClassPath(),
				recoveredClass.getName() + CLASS_VTABLE_STRUCT_NAME, 0, dataTypeManager);

			IntegerDataType integerDataType = new IntegerDataType();

			int numPointers = baseClassArrayData.getNumComponents();

			for (int i = 0; i < numPointers; ++i) {
				monitor.checkCancelled();

				// Get the address it is pointing to
				Address pointerAddress = baseClassArrayData.getComponent(i).getAddress();

				Address baseClassDescriptorAddress =
					extendedFlatAPI.getReferencedAddress(pointerAddress, true);
				if (baseClassArrayAddress == null) {
					continue;
				}
				Symbol baseClassDescSymbol =
					symbolTable.getPrimarySymbol(baseClassDescriptorAddress);
				if (baseClassDescSymbol == null) {
					continue;
				}
				Namespace namespace = baseClassDescSymbol.getParentNamespace();
				if (namespace.equals(globalNamespace)) {
					continue;
				}
				RecoveredClass baseClass = getClass(namespace);

				// update parent map based on pdisp (-1 means not virtual base, otherwise it is a 
				// virtual base
				// set the has vbtable if any of them are a virtual base
				// update the vbstruct if any of them are a virtual base
				int pdisp = api.getInt(baseClassDescriptorAddress.add(12));
				int vdisp = api.getInt(baseClassDescriptorAddress.add(16));

				if (vbaseStructure.getComponentAt(vdisp) == null) {
					String classFieldName = new String();
					if (USE_SHORT_TEMPLATE_NAMES_IN_STRUCTURE_FIELDS &&
						!baseClass.getShortenedTemplateName().isEmpty()) {
						classFieldName = baseClass.getShortenedTemplateName();
					}
					else {
						classFieldName = baseClass.getName();
					}
					vbaseStructure.insertAtOffset(vdisp, integerDataType,
						integerDataType.getLength(), classFieldName + "_offset", null);
				}

				// skip the rest for the given class
				if (baseClass == recoveredClass) {
					continue;
				}

				if (pdisp == -1) {
					recoveredClass.addParentToBaseTypeMapping(baseClass, false);
				}
				else {
					if (vbaseOffset == NONE) {
						vbaseOffset = pdisp;
					}
					else if (vbaseOffset != pdisp) {
						throw new Exception(
							recoveredClass.getName() + " vbaseOffset values do not match");
					}

					hasVirtualAncestor = true;
					recoveredClass.addParentToBaseTypeMapping(baseClass, true);
				}

				// after the loop check if vbstruct/flag and if so figure out the vbaseTable address 
				if (hasVirtualAncestor) {
					if (vbaseOffset != UNKNOWN) {
						Address vbtableAddress = getVbaseTableAddress(recoveredClass, vbaseOffset);
						if (vbtableAddress != null) {
							recoveredClass.setVbtableAddress(vbtableAddress);
						}
					}
					recoveredClass.setVbtableStructure(vbaseStructure);
					recoveredClass.setInheritsVirtualAncestor(true);
					recoveredClass.setVbtableOffset(vbaseOffset);
				}
			}
		}
	}

	/**
	 * Method to retrieve the address of the vbtable given the vbtableOffset from the baseClassDescriptor
	 * and the address referenced by the target address in the storedPcodeOp at the vbtableOffset 
	 * @param recoveredClass the given class
	 * @param vbtableOffset the offset of the vbtable in the given class
	 * @return the address in the current program's memory of the given class's vbtable
	 * @throws CancelledException if cancelled
	 */
	private Address getVbaseTableAddress(RecoveredClass recoveredClass, int vbtableOffset)
			throws CancelledException {

		List<Function> constructorList = recoveredClass.getConstructorList();
		if (constructorList.isEmpty()) {
			constructorList.addAll(recoveredClass.getInlinedConstructorList());
			if (constructorList.isEmpty()) {
				return null;
			}
		}

		FillOutStructureHelper fillStructHelper = new FillOutStructureHelper(program, monitor);

		for (Function constructor : constructorList) {

			monitor.checkCancelled();
			HighFunction highFunction = decompilerUtils.getHighFunction(constructor);

			if (highFunction == null) {
				continue;
			}

			Address vbtableAddress = getVbtableAddressFromDecompiledFunction(fillStructHelper,
				highFunction, recoveredClass, constructor, vbtableOffset);

			if (vbtableAddress != null) {
				return vbtableAddress;
			}
		}

		List<Function> indeterminateList = recoveredClass.getIndeterminateList();
		if (indeterminateList.isEmpty()) {
			indeterminateList.addAll(recoveredClass.getIndeterminateInlineList());
			if (indeterminateList.isEmpty()) {
				return null;
			}
		}

		for (Function constructor : indeterminateList) {

			monitor.checkCancelled();
			HighFunction highFunction = decompilerUtils.getHighFunction(constructor);

			if (highFunction == null) {
				continue;
			}

			Address vbtableAddress = getVbtableAddressFromDecompiledFunction(fillStructHelper,
				highFunction, recoveredClass, constructor, vbtableOffset);

			if (vbtableAddress != null) {
				return vbtableAddress;
			}
		}

		return null;

	}

	/**
	 * Method to find the address of the vbtable referenced at the given offset in the given function
	 * @param fillStructHelper a reusable {@link FillOutStructureHelper} instance to be used
	 * with decompiler for a particular variable
	 * @param highFunction the high function for the given function
	 * @param recoveredClass the given class
	 * @param function the given function
	 * @param offset the offset in the filled out structure where the vbtable address must be
	 * @return the address of the found vbtable or null if none is found
	 * @throws CancelledException if cancelled
	 */
	private Address getVbtableAddressFromDecompiledFunction(FillOutStructureHelper fillStructHelper,
			HighFunction highFunction, RecoveredClass recoveredClass, Function function, int offset)
			throws CancelledException {

		List<HighVariable> highVariables = new ArrayList<HighVariable>();

		// if there are params add the first or the "this" param to the list to be checked first 
		// It is the most likely to store the vftablePtr

		int numParams = highFunction.getFunctionPrototype().getNumParams();
		if (numParams > 0) {

			for (int i = 0; i < numParams; i++) {
				monitor.checkCancelled();
				HighVariable param =
					highFunction.getFunctionPrototype().getParam(i).getHighVariable();
				if (param != null) {
					highVariables.add(param);
				}
			}
		}

		for (HighVariable highVariable : highVariables) {

			monitor.checkCancelled();

			fillStructHelper.processStructure(highVariable, function, true, false, null);
			List<OffsetPcodeOpPair> stores = fillStructHelper.getStorePcodeOps();
			stores = removePcodeOpsNotInFunction(function, stores);

			for (OffsetPcodeOpPair offsetPcodeOpPair : stores) {
				monitor.checkCancelled();
				int pcodeOffset = offsetPcodeOpPair.getOffset().intValue();
				if (pcodeOffset == offset) {

					Address listingAddress =
						getTargetAddressFromPcodeOp(offsetPcodeOpPair.getPcodeOp());

					Address vbtableAddress =
						extendedFlatAPI.getSingleReferencedAddress(listingAddress);

					if (vbtableAddress == null) {
						continue;
					}
					return vbtableAddress;

				}
			}

		}
		return null;
	}

	/**
	 * Method to create vftable address and parent class map for each class object
	 * @param recoveredClasses list of class objects
	 * @throws Exception when cancelled
	 */
	private void assignParentClassToVftables(List<RecoveredClass> recoveredClasses)
			throws Exception {

		for (RecoveredClass recoveredClass : recoveredClasses) {
			monitor.checkCancelled();
			if (!recoveredClass.hasVftable()) {
				continue;
			}

			List<Address> vftableAddresses = recoveredClass.getVftableAddresses();
			if (vftableAddresses.size() == 0) {
				continue;
			}

			List<RecoveredClass> parentsWithVirtualFunctions =
				getParentsWithVirtualFunctions(recoveredClass);
			if (parentsWithVirtualFunctions.size() == 0) {
				continue;
			}

			List<RecoveredClass> ancestorsAllowedToMap = new ArrayList<RecoveredClass>();

			List<RecoveredClass> ancestorsWithoutVfunctions =
				getAncestorsWithoutVfunctions(recoveredClass);

			// case where more than one parent with virtual functions and class has multiple 
			// virtual inheritance, ie the diamond case, need to remove parents with common
			// ancestors from parent list and replace with the common ancestor
			if (recoveredClass.hasMultipleVirtualInheritance()) {
				// need to find common ancestor inherited in the diamond shape and replace
				// the parents that use it with the ancestor. The resulting list should 
				// equal the number of vftables
				ancestorsAllowedToMap = replaceParentsWithCommonAncestor(recoveredClass);
				ancestorsAllowedToMap.removeAll(ancestorsWithoutVfunctions);
				mapVftablesToParents(recoveredClass, ancestorsAllowedToMap);
				continue;
			}

			// case where class has multiple inheritance flag because an ancestor has mult inheritance but
			// TODO: pull into separate method
			if (recoveredClass.hasMultipleInheritance() &&
				recoveredClass.getClassHierarchyMap().size() == 1 &&
				recoveredClass.getVftableAddresses().size() > 1) {

				List<RecoveredClass> parents =
					new ArrayList<RecoveredClass>(recoveredClass.getClassHierarchyMap().keySet());
				RecoveredClass singleParent = parents.get(0);
				List<RecoveredClass> grandParents = getParentsWithVirtualFunctions(singleParent);
				// check that they both have vftables 
				// get their order from the class hierarchy list
				// first see if it has a parent order map and just make it the same one 

				if (grandParents.size() == recoveredClass.getVftableAddresses().size()) {
					// get the sorted order of vftables
					Map<Integer, Address> orderToVftableMap = recoveredClass.getOrderToVftableMap();
					List<Integer> sortedOrder = new ArrayList<Integer>(orderToVftableMap.keySet());
					Collections.sort(sortedOrder);

					int order = 0;
					// iterate over the hierarchy list and use it to get the order of the parentsParents and assign
					// to correct vftable
					List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();
					for (RecoveredClass ancestor : classHierarchy) {
						monitor.checkCancelled();
						if (grandParents.contains(ancestor)) {
							Integer index = sortedOrder.get(order);
							Address vftableAddress = orderToVftableMap.get(index);
							recoveredClass.addVftableToBaseClassMapping(vftableAddress, ancestor);
							order++;
						}
					}

				}

				continue;
			}

			if (recoveredClass.hasSingleInheritance() &&
				recoveredClass.getParentList().size() == 1 &&
				recoveredClass.getVftableAddresses().size() == 2) {

				// case 1: class's direct parent is virtually inherited and has vtable
				// first Vftable is mapped to null parent because it is used in class struct by current class
				// second is mapped to first virtual ancestor with vftable  

				// case 2: class's direct parent is non-virt with vtable, it has ancestor that is virtual with vftable
				// use the mapping function to map correct parent to correct vftable

				// case multiple vftables and there is only one parent that is virtually inherited
				// one vftable is used for current class and one for the virt in
				RecoveredClass virtualAncestorWithVfunctions =
					getFirstVirtuallyInheritedAncestorWithVfunctions(recoveredClass);

				if (virtualAncestorWithVfunctions != null) {

					//RecoveredClass parentClass = recoveredClass.getParentClass();

					RecoveredClass parentClass = recoveredClass.getParentList().get(0);

					if (virtualAncestorWithVfunctions.equals(parentClass)) {

						// map the current class to the first vftable
						recoveredClass.addVftableToBaseClassMapping(
							recoveredClass.getVftableAddresses().get(0), recoveredClass);
						// map the virtual parent to the second vftable
						recoveredClass.addVftableToBaseClassMapping(
							recoveredClass.getVftableAddresses().get(1), parentClass);
						continue;
					}

					// map the non-virtual parent to the first vftable
					recoveredClass.addVftableToBaseClassMapping(
						recoveredClass.getVftableAddresses().get(0), parentClass);
					// map the first virtual ancestor to the second vftable 
					recoveredClass.addVftableToBaseClassMapping(
						recoveredClass.getVftableAddresses().get(1), virtualAncestorWithVfunctions);
					continue;

				}

			}

			// the rest should work for both single and regular multiple inheritance 			
			ancestorsAllowedToMap = parentsWithVirtualFunctions;

			// when only one direct parent with virtual functions, map the vftable to that parent 
			if (ancestorsAllowedToMap.size() == 1 && vftableAddresses.size() == 1) {
				recoveredClass.addVftableToBaseClassMapping(
					recoveredClass.getVftableAddresses().get(0), ancestorsAllowedToMap.get(0));
				continue;
			}

			// All other cases where the number of vftables should equal the number of 
			// parents (virtual or otherwise) 
			mapVftablesToParents(recoveredClass, ancestorsAllowedToMap);

		}

	}

	/**
	 * Method to determine if the given class inherits any ancestors virtually
	 * @param recoveredClass the given class
	 * @return true if any of the given class's ancestors are inherited virtually, false otherwise
	 * @throws CancelledException if cancelled
	 */
	private RecoveredClass getFirstVirtuallyInheritedAncestorWithVfunctions(
			RecoveredClass recoveredClass) throws CancelledException {

		List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();

		for (RecoveredClass ancestorClass : classHierarchy) {
			monitor.checkCancelled();
			RecoveredClass firstVirtuallyInheritedAncestorWithVfunctions =
				getVirtuallyInheritedParentWithVfunctions(ancestorClass);
			if (firstVirtuallyInheritedAncestorWithVfunctions != null) {
				return firstVirtuallyInheritedAncestorWithVfunctions;

			}

		}

		return null;
	}

	/**
	 * Method to retrieve the virtually inherited parent that has vfunctions for the given class if there is one
	 * @param recoveredClass the given class
	 * @return the virtually inherited parent that has vfunctions for the given class if there is one, or null if there isn't
	 * @throws CancelledException if cancelled
	 */
	private RecoveredClass getVirtuallyInheritedParentWithVfunctions(RecoveredClass recoveredClass)
			throws CancelledException {

		if (!recoveredClass.hasVftable()) {
			return null;
		}

		Map<RecoveredClass, List<RecoveredClass>> classHierarchyMap =
			recoveredClass.getClassHierarchyMap();
		if (classHierarchyMap == null) {
			return null;
		}

		Map<RecoveredClass, Boolean> parentToBaseTypeMap = recoveredClass.getParentToBaseTypeMap();

		List<RecoveredClass> parents = new ArrayList<RecoveredClass>(classHierarchyMap.keySet());
		for (RecoveredClass parent : parents) {
			monitor.checkCancelled();
			Boolean isVirtuallyInherited = parentToBaseTypeMap.get(parent);

			if (isVirtuallyInherited != null && isVirtuallyInherited && parent.hasVftable()) {
				return parent;
			}

		}
		return null;

	}

	/**
	 * Using their address order in constructor/destructor functions, map the given class's vftables to their 
	 * respective parent (or in some cases, ancestor) classes
	 * @param recoveredClass the given class
	 * @param ancestorsAllowedToMap List of parent/ancestors allowed to map to vftables (ie, in multi-virt case, the parents won't get mapped but a common ancestor will)
	 * @throws CancelledException if cancelled
	 */
	private void mapVftablesToParents(RecoveredClass recoveredClass,
			List<RecoveredClass> ancestorsAllowedToMap) throws CancelledException {

		Map<Integer, Address> orderToVftableMap = recoveredClass.getOrderToVftableMap();
		List<Integer> sortedOrder = new ArrayList<Integer>(orderToVftableMap.keySet());
		Collections.sort(sortedOrder);

		Map<Integer, RecoveredClass> parentOrderMap =
			getParentOrderMap(recoveredClass, ancestorsAllowedToMap);

		if (sortedOrder.size() != parentOrderMap.size()) {
			Msg.debug(this,
				recoveredClass.getName() +
					" has mismatch between vftable and parent order map sizes " +
					sortedOrder.size() + " vs " + parentOrderMap.size());
			return;
		}

		for (Integer order : sortedOrder) {
			monitor.checkCancelled();
			Address vftableAddress = orderToVftableMap.get(order);
			RecoveredClass parentClass = parentOrderMap.get(order);
			recoveredClass.addVftableToBaseClassMapping(vftableAddress, parentClass);
		}

	}

	/**
	 * Method to create a map containing order/parent mappings for the given class, using order they are used in constructor/destructors
	 * @param recoveredClass the given class
	 * @return a map containing order/parent mappings for the given class
	 * @throws CancelledException if cancelled
	 */
	private Map<Integer, RecoveredClass> getParentOrderMap(RecoveredClass recoveredClass,
			List<RecoveredClass> parentsWithVfunctions) throws CancelledException {

		Map<Integer, RecoveredClass> parentOrderMap = new HashMap<Integer, RecoveredClass>();

		if (recoveredClass.getConstructorOrDestructorFunctions().isEmpty()) {
			return parentOrderMap;
		}

		// try to get parent order map using constructors/inline constructors
		parentOrderMap = getParentOrderMap(recoveredClass, parentsWithVfunctions, true);
		if (!parentOrderMap.isEmpty()) {
			return parentOrderMap;
		}

		// otherwise try to get the map using destructors/inline destructors
		parentOrderMap = getParentOrderMap(recoveredClass, parentsWithVfunctions, false);
		if (!parentOrderMap.isEmpty()) {
			return parentOrderMap;
		}

		return parentOrderMap;
	}

	/**
	 * Method to create an order/ancestor map for the given class (usually will be parents but in some cases will be ancestors)
	 * @param recoveredClass the given class
	 * @param allowedAncestors List of ancestors (usually parents) that can be added to the map
	 * @param useConstructors if true, use constructor functions to determine order, if false, use destructor functions
	 * @return the order/ancestor map of the same size as the number of vftables in the class or an empty map if the correctly sized map cannot be determined
	 * @throws CancelledException if cancelled
	 */
	private Map<Integer, RecoveredClass> getParentOrderMap(RecoveredClass recoveredClass,
			List<RecoveredClass> allowedAncestors, boolean useConstructors)
			throws CancelledException {

		Map<Integer, RecoveredClass> parentOrderMap = new HashMap<Integer, RecoveredClass>();

		int numVftables = recoveredClass.getVftableAddresses().size();

		List<Function> functionList = new ArrayList<Function>();
		if (useConstructors) {
			functionList.addAll(recoveredClass.getConstructorList());
			functionList.addAll(recoveredClass.getInlinedConstructorList());
		}
		else {
			functionList.addAll(recoveredClass.getDestructorList());
			functionList.addAll(recoveredClass.getInlinedDestructorList());
		}

		// return empty map
		if (functionList.isEmpty()) {
			return parentOrderMap;
		}

		for (Function function : functionList) {

			monitor.checkCancelled();

			parentOrderMap = new HashMap<Integer, RecoveredClass>();

			Map<Address, RecoveredClass> referenceToParentMap =
				getReferenceToClassMap(recoveredClass, function);

			Map<Address, RecoveredClass> allowedReferncesToParentMap =
				new HashMap<Address, RecoveredClass>();

			List<Address> classReferences = new ArrayList<Address>(referenceToParentMap.keySet());
			for (Address classReferenceAddress : classReferences) {

				monitor.checkCancelled();
				// if the address refers to a vftable and that vftable is in the current class then it is not a parent class so do not add to map
				Address possibleVftable = getVftableAddress(classReferenceAddress);

				// if not a vftable then it is a function call
				if (possibleVftable == null) {

					Function referencedFunction =
						extendedFlatAPI.getReferencedFunction(classReferenceAddress, true);

					if (referencedFunction == null) {
						continue;
					}

				}
				if (possibleVftable != null &&
					recoveredClass.getVftableAddresses().contains(possibleVftable)) {
					continue;
				}

				RecoveredClass ancestorClass = referenceToParentMap.get(classReferenceAddress);
				if (allowedAncestors.contains(ancestorClass)) {
					allowedReferncesToParentMap.put(classReferenceAddress, ancestorClass);
				}
			}

			// now order the addresses in the map one direction for constructors and the other for destructors
			int order = 0;
			List<Address> parentReferences =
				new ArrayList<Address>(allowedReferncesToParentMap.keySet());

			if (useConstructors) {
				Collections.sort(parentReferences);
			}
			else {
				Collections.sort(parentReferences, Collections.reverseOrder());
			}

			// iterate over the ordered parents and add the order to the parent map
			for (Address refAddress : parentReferences) {
				monitor.checkCancelled();
				RecoveredClass parentClass = referenceToParentMap.get(refAddress);
				parentOrderMap.put(order, parentClass);
				order++;
			}

			// the size of the resulting ref to parent map should equal the number of vftables in the class
			// if not, continue to iterate over more functions 
			// if so, return the map
			if (parentOrderMap.size() == numVftables) {
				return parentOrderMap;
			}
		}

		// return empty map if none of the construtor/destructor functions create the correctly sized map
		return parentOrderMap;
	}

	/**
	 * Method to find common inherited ancestors in the given class's parent list
	 * and replace the parents with that common ancestor with the ancestor
	 * @param recoveredClass the given class
	 * @return List containing lowest common ancestor and the removal of the parents with the common ancestor but leaving parents with no common ancestors
	 * @throws Exception if class has empty class hierarchy list
	 */
	private List<RecoveredClass> replaceParentsWithCommonAncestor(RecoveredClass recoveredClass)
			throws Exception {

		Map<RecoveredClass, List<RecoveredClass>> classHierarchyMap =
			recoveredClass.getClassHierarchyMap();

		Map<RecoveredClass, List<RecoveredClass>> ancestorToCommonChild =
			new HashMap<RecoveredClass, List<RecoveredClass>>();

		List<RecoveredClass> parentClasses =
			new ArrayList<RecoveredClass>(classHierarchyMap.keySet());
		parentClasses = getClassesWithVFunctions(parentClasses);

		List<RecoveredClass> updatedParentClasses = new ArrayList<RecoveredClass>(parentClasses);

		// now iterate over the direct parents and map that parent to each ancestor on the ancestor with vfunction list 
		for (RecoveredClass parentClass : parentClasses) {
			monitor.checkCancelled();

			List<RecoveredClass> ancestors =
				new ArrayList<RecoveredClass>(parentClass.getClassHierarchy());
			ancestors.remove(parentClass);
			ancestors = getClassesWithVFunctions(ancestors);

			if (ancestors.isEmpty()) {
				continue;
			}

			for (RecoveredClass ancestor : ancestors) {
				monitor.checkCancelled();

				List<RecoveredClass> descendantList = ancestorToCommonChild.get(ancestor);
				if (descendantList == null) {
					List<RecoveredClass> newDescendantList = new ArrayList<RecoveredClass>();
					newDescendantList.add(parentClass);
					ancestorToCommonChild.put(ancestor, newDescendantList);
				}
				else {
					if (!descendantList.contains(parentClass)) {
						descendantList.add(parentClass);
						ancestorToCommonChild.replace(ancestor, descendantList);
					}
				}
			}

		}

		// if the map is empty, return the updated list of parents which contains only
		// parents with vfunctions
		Set<RecoveredClass> keySet = ancestorToCommonChild.keySet();
		if (keySet.isEmpty()) {
			return updatedParentClasses;
		}

		// now iterate over the ancestor map and update the parent list by adding any ancestor
		// that has common parents and removing those parents from the list
		for (RecoveredClass ancestor : keySet) {
			monitor.checkCancelled();
			List<RecoveredClass> commonChildList = ancestorToCommonChild.get(ancestor);
			if (commonChildList != null && commonChildList.size() >= 2) {
				if (!updatedParentClasses.contains(ancestor)) {

					updatedParentClasses.add(ancestor);

				}
				updatedParentClasses.removeAll(commonChildList);
			}
		}

		if (updatedParentClasses.isEmpty()) {
			return updatedParentClasses;
		}

		Iterator<RecoveredClass> updatedParentsIterator = updatedParentClasses.iterator();
		while (updatedParentsIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass ancestor = updatedParentsIterator.next();

			// remove if ancestor is an ancestor of any of the others
			if (isClassAnAncestorOfAnyOnList(updatedParentClasses, ancestor)) {
				updatedParentsIterator.remove();
			}
		}

		return updatedParentClasses;

	}

	/**
	 * Method to call create and apply class structures method starting with top parent classes
	 * and non-virtual classes then the children and their children until all classes are processed.
	 * @param recoveredClasses List of classes
	 * @throws CancelledException when cancelled
	 * @throws Exception if issue creating data
	 */
	private void createAndApplyClassStructures(List<RecoveredClass> recoveredClasses)
			throws CancelledException, Exception {

		List<RecoveredClass> listOfClasses = new ArrayList<RecoveredClass>(recoveredClasses);

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		// first process all the classes with no parents
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCancelled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

			if (recoveredClass.hasMultipleInheritance()) {
				continue;
			}

			if (recoveredClass.hasParentClass()) {
				continue;
			}

			if (!recoveredClass.hasVftable()) {
				createClassStructureWhenNoParentOrVftable(recoveredClass);
				listOfClasses.remove(recoveredClass);
				continue;
			}

			processDataTypes(recoveredClass);
			listOfClasses.remove(recoveredClass);

		}

		// now process the classes that have all parents processed
		// continue looping until all classes are processed
		int numLoops = 0;

		while (!listOfClasses.isEmpty()) {
			monitor.checkCancelled();

			// put in stop gap measure in case some classes never get all
			// parents processed for some reason
			if (numLoops == 100) {
				return;
			}
			numLoops++;

			recoveredClassIterator = recoveredClasses.iterator();
			while (recoveredClassIterator.hasNext()) {

				RecoveredClass recoveredClass = recoveredClassIterator.next();

				monitor.checkCancelled();
				if (!listOfClasses.contains(recoveredClass)) {
					continue;
				}

				if (!allAncestorDataHasBeenCreated(recoveredClass)) {
					continue;
				}

				processDataTypes(recoveredClass);
				listOfClasses.remove(recoveredClass);

			}
		}
	}

	/**
	 * Method to create all the class data types for the current class, name all the class functions, and put them all into the class namespace
	 * @param recoveredClass current class
	 * @throws CancelledException when cancelled
	 * @throws Exception naming exception
	 */
	private void processDataTypes(RecoveredClass recoveredClass)
			throws CancelledException, Exception {

		if (!recoveredClass.hasVftable()) {
			Structure classStruct = createClassStructureUsingRTTI(recoveredClass, null);

			if (classStruct != null) {
				updateClassFunctionsNotUsingNewClassStructure(recoveredClass, classStruct);
			}
			// return in this case because if there is no vftable for a class the script cannot
			// identify any member functions so there is no need to process the rest of this method
			return;
		}

		// create pointers to empty vftable structs so they can be added to the class data type
		// then filled in later
		Map<Address, DataType> vfPointerDataTypes = createEmptyVfTableStructs(recoveredClass);

		// create current class structure and add pointer to vftable, all parent member data strutures, and class member data structure
		Structure classStruct = null;

		classStruct = createClassStructureUsingRTTI(recoveredClass, vfPointerDataTypes);

		applyVbtableStructure(recoveredClass);

		// Now that we have a class data type
		// name constructor and destructor functions and put into the class namespace
		// checks are internal for hasDebugSymbols since there
		// are also replace methods that need to be called either way
		addConstructorsToClassNamespace(recoveredClass, classStruct);
		addDestructorsToClassNamespace(recoveredClass, classStruct);
		addVbaseDestructorsToClassNamespace(recoveredClass, classStruct);

		if (!hasDebugSymbols) {
			addNonThisDestructorsToClassNamespace(recoveredClass);

			addVbtableToClassNamespace(recoveredClass);

			// add secondary label on functions with inlined constructors or destructors
			createInlinedConstructorComments(recoveredClass);
			createInlinedDestructorComments(recoveredClass);
			createIndeterminateInlineComments(recoveredClass);
		}

		// add label on constructor destructor functions that could not be determined which were which
		createIndeterminateLabels(recoveredClass, classStruct);

		// This is done after the class structure is created and added to the dtmanager
		// because if done before the class structures are created 
		// then empty classes will get auto-created in the wrong place
		// when the vfunctions are put in the class
		fillInAndApplyVftableStructAndNameVfunctions(recoveredClass, vfPointerDataTypes,
			classStruct);

		if (classStruct != null) {
			updateClassFunctionsNotUsingNewClassStructure(recoveredClass, classStruct);
		}

	}

	/**
	 * Method to create a class structure using information in program RTTI structures
	 * @param recoveredClass the given class
	 * @param vfPointerDataTypes map of address/vftable pointer structs
	 * @return the created class structure data type
	 * @throws Exception if invalid data creation
	 */
	private Structure createClassStructureUsingRTTI(RecoveredClass recoveredClass,
			Map<Address, DataType> vfPointerDataTypes) throws Exception {

		String className = recoveredClass.getName();

		CategoryPath classPath = recoveredClass.getClassPath();

		// get either existing structure if prog has a structure created by pdb or computed structure
		// from decompiled construtor(s) info
		Structure classStructure;
		if (recoveredClass.hasExistingClassStructure()) {
			classStructure = recoveredClass.getExistingClassStructure();
		}
		else {
			classStructure = recoveredClass.getComputedClassStructure();
		}

		int structLen = 0;
		if (classStructure != null) {
			structLen = addAlignment(classStructure.getLength());
		}

		Structure classStructureDataType =
			new StructureDataType(classPath, className, structLen, dataTypeManager);

		Data baseClassArrayData = getBaseClassArray(recoveredClass);

		// if cannot recover the base class array return the existing or computed one instead
		// so user will at least have some information like correct size and some members
		if (baseClassArrayData == null) {
			classStructureDataType.replaceWith(classStructure);

			classStructureDataType = (Structure) dataTypeManager.addDataType(classStructureDataType,
				DataTypeConflictHandler.DEFAULT_HANDLER);
			return classStructureDataType;
		}

		// if lowest level multi-v (not just inherits a multi-v), need to add this first so it isn't overwritten by base class structures
		// at same offset
		if (recoveredClass.getClassHierarchyMap().size() > 1 &&
			recoveredClass.hasMultipleVirtualInheritance()) {
			classStructureDataType =
				addVbtableToClassStructure(recoveredClass, classStructureDataType, false);
		}

		int baseClassOffset = 0;
		int numPointers = baseClassArrayData.getNumComponents();

		for (int i = 0; i < numPointers; ++i) {
			monitor.checkCancelled();

			// Get the base class it is pointing to
			Address pointerAddress = baseClassArrayData.getComponent(i).getAddress();

			Address baseClassDescriptorAddress =
				extendedFlatAPI.getReferencedAddress(pointerAddress, true);
			if (baseClassDescriptorAddress == null) {
				continue;
			}

			RecoveredClass baseClass = getClassFromBaseClassDescriptor(baseClassDescriptorAddress);
			if (i > 0 && baseClass == null) {
				continue;
			}

			int mdisp = api.getInt(baseClassDescriptorAddress.add(8));
			int pdisp = api.getInt(baseClassDescriptorAddress.add(12));
			int vdisp = api.getInt(baseClassDescriptorAddress.add(16));

			// skip main class - will fill in its vftable ptr later
			if (pdisp == -1 && i == 0) {
				continue;
			}

			// get the baseClassStructure (ie self or ancestor class) and its displacement values
			Structure baseClassStructure = getClassStructureFromDataTypeManager(baseClass);
			if (baseClassStructure == null) {
				Msg.debug(this, "****recovered Class = " + recoveredClass.getName() +
					"'s base Class " + baseClass.getName() + " class struct is null");
				continue;
			}

			// Continue if the class has mult inh but base class is not on the parent list
			if (recoveredClass.hasMultipleInheritance() &&
				!recoveredClass.getParentList().contains(baseClass)) {
				continue;
			}

			// process the non-virtually inherited ones 
			if (pdisp == -1) {

				baseClassOffset = mdisp;

				if (recoveredClass.hasMultipleInheritance() &&
					!recoveredClass.getParentList().contains(baseClass)) {
					continue;
				}

				// if it is a direct parent and the structure exists add it to the structure in the mdisp offset					
				// if class has virtual inheritance then copy individual members from the non-virtual parent struct
				// into the struct 	
				if (recoveredClass.hasSingleInheritance() &&
					recoveredClass.getVftableAddresses().size() > 1 &&
					recoveredClass.inheritsVirtualAncestor()) {

					Integer virtParentOffset = getSingleVirtualParentOffset(baseClass);

					int dataLength;
					if (virtParentOffset == null || virtParentOffset == NONE) {
						dataLength = baseClassStructure.getLength();
					}
					else {
						int virtParentLength = baseClassStructure.getLength() - virtParentOffset;
						dataLength = baseClassStructure.getLength() - virtParentLength;
					}

					// if there is room add the individual parts of the base class from the top of the 
					// structure up to but not including the single virtual parent offset within 
					// the class structure
					addIndividualComponentsToStructure(classStructureDataType, baseClassStructure,
						baseClassOffset, dataLength);
					continue;
				}

				// if it fits at offset or is at the end and class structure can be grown, 
				// copy the whole baseClass structure to the class Structure at the given offset
				EditStructureUtils.addDataTypeToStructure(classStructureDataType, baseClassOffset,
					baseClassStructure, baseClassStructure.getName(), monitor);

			}
			else {
				// else need to fill in the virtually inherited ones 
				// get the offset of this base class in the class using the vbtable				
				Address vbtableAddress = recoveredClass.getVbtableAddress();
				if (vbtableAddress == null) {
					continue;
				}

				baseClassOffset = api.getInt(recoveredClass.getVbtableAddress().add(vdisp)) + pdisp;

				// if it fits at offset or is at the end and class structure can be grown, 
				// copy the whole baseClass structure to the class Structure at the given offset
				EditStructureUtils.addDataTypeToStructure(classStructureDataType, baseClassOffset,
					baseClassStructure, baseClassStructure.getName(), monitor);

			}

		}// end of base class array

		if (vfPointerDataTypes != null) {
			if (!isClassOffsetToVftableMapComplete(recoveredClass)) {
				Msg.debug(this, "class vftable offset map for " + recoveredClass.getName() +
					" is not complete");
			}

			// iterate over the set of offsets to vftables for the class and if nothing
			// is already at the offset, add the vftables
			Map<Integer, Address> classOffsetToVftableMap =
				recoveredClass.getClassOffsetToVftableMap();
			Set<Integer> classVftableOffsets = classOffsetToVftableMap.keySet();
			List<Integer> sortedOffsets = new ArrayList<Integer>(classVftableOffsets);
			Collections.sort(sortedOffsets);

			Integer offset = sortedOffsets.get(0);

			Address vftableAddress = classOffsetToVftableMap.get(offset);

			DataType classVftablePointer = vfPointerDataTypes.get(vftableAddress);

			// if it fits at offset or is at the end and class structure can be grown, 
			// copy the whole baseClass structure to the class Structure at the given offset
			EditStructureUtils.addDataTypeToStructure(classStructureDataType, offset.intValue(),
				classVftablePointer, CLASS_VTABLE_PTR_FIELD_EXT, monitor);
		}

		// add the vbtable structure for single inheritance/virt parent case
		if (recoveredClass.hasSingleInheritance() && recoveredClass.inheritsVirtualAncestor()) {
			classStructureDataType =
				addVbtableToClassStructure(recoveredClass, classStructureDataType, false);
		}

		int dataOffset = getDataOffset(recoveredClass, classStructureDataType);
		int dataLen = UNKNOWN;
		if (dataOffset != NONE) {
			dataLen = EditStructureUtils.getNumberOfUndefinedsStartingAtOffset(
				classStructureDataType, dataOffset, monitor);
		}

		if (dataLen != UNKNOWN && dataLen > 0) {

			Structure recoveredClassDataStruct = createClassMemberDataStructure(recoveredClass,
				classStructureDataType, dataLen, dataOffset);

			if (recoveredClassDataStruct != null) {
				// if it fits at offset or is at the end and class structure can be grown, 
				// copy the whole baseClass structure to the class Structure at the given offset
				EditStructureUtils.addDataTypeToStructure(classStructureDataType, dataOffset,
					recoveredClassDataStruct, classStructureDataType.getName() + "_data", monitor);
			}

		}

		classStructureDataType =
			addClassVftables(classStructureDataType, recoveredClass, vfPointerDataTypes);

		classStructureDataType =
			addVbtableToClassStructure(recoveredClass, classStructureDataType, true);

		if (classStructureDataType.getNumComponents() == classStructureDataType
				.getNumDefinedComponents()) {
			classStructureDataType.setPackingEnabled(true);
		}

		classStructureDataType.setDescription(createParentStringBuffer(recoveredClass).toString());

		classStructureDataType = (Structure) dataTypeManager.addDataType(classStructureDataType,
			DataTypeConflictHandler.DEFAULT_HANDLER);

		return classStructureDataType;
	}

	/**
	 * Method to return the offset of the given class's single virtual parent
	 * @param recoveredClass the given class
	 * @return the offset in the given class structure of the classes single virtual parent or NONE 
	 * if cannot retrieve an offset value or if there is not a single virtual parent for the given
	 * class. Return null if cannot retrieve the offset for the single virtual parent. 
	 * @throws CancelledException if cancelled
	 * @throws AddressOutOfBoundsException if trying to access an address that does not exist in program
	 * @throws MemoryAccessException  if trying to access memory that can't be accessed
	 */
	public Integer getSingleVirtualParentOffset(RecoveredClass recoveredClass)
			throws CancelledException, MemoryAccessException, AddressOutOfBoundsException {

		List<RecoveredClass> virtualParentClasses = getVirtualParentClasses(recoveredClass);
		if (virtualParentClasses.size() != 1) {
			return NONE;
		}

		Map<RecoveredClass, Integer> parentOffsetMap = getBaseClassOffsetMap(recoveredClass);

		if (parentOffsetMap != null) {
			return parentOffsetMap.get(virtualParentClasses.get(0));
		}

		return null;

	}

	private Map<RecoveredClass, Integer> getBaseClassOffsetMap(RecoveredClass recoveredClass)
			throws CancelledException, MemoryAccessException, AddressOutOfBoundsException {

		Map<RecoveredClass, Integer> baseClassOffsetMap = new HashMap<>();

		Data baseClassArrayData = getBaseClassArray(recoveredClass);

		int baseClassOffset = 0;
		int numPointers = baseClassArrayData.getNumComponents();

		for (int i = 0; i < numPointers; ++i) {
			monitor.checkCancelled();

			// Get the base class it is pointing to
			Address pointerAddress = baseClassArrayData.getComponent(i).getAddress();

			Address baseClassDescriptorAddress =
				extendedFlatAPI.getReferencedAddress(pointerAddress, true);
			if (baseClassDescriptorAddress == null) {
				continue;
			}

			RecoveredClass baseClass = getClassFromBaseClassDescriptor(baseClassDescriptorAddress);
			if (baseClass == null) {
				// TODO: return null?
				Msg.debug(this, "Could not get base class from baseClassDescriptor " +
					baseClassDescriptorAddress.toString());
				continue;
			}

			// Continue if the class has mult inh but base class is not on the parent list
			if (!recoveredClass.getParentList().contains(baseClass)) {
				continue;
			}

			int mdisp = api.getInt(baseClassDescriptorAddress.add(8));
			int pdisp = api.getInt(baseClassDescriptorAddress.add(12));
			int vdisp = api.getInt(baseClassDescriptorAddress.add(16));
			if (pdisp == -1) {
				baseClassOffset = mdisp;
			}
			else {
				// else need to fill in the virtually inherited ones 
				// get the offset of this base class in the class using the vbtable				
				Address vbtableAddress = recoveredClass.getVbtableAddress();
				if (vbtableAddress == null) {
					Msg.error(this,
						"Cannot retrieve vbtable address so cannot create base class offset map for class " +
							recoveredClass.getName());
					return null;
				}
				baseClassOffset = api.getInt(recoveredClass.getVbtableAddress().add(vdisp)) + pdisp;
			}
			baseClassOffsetMap.put(baseClass, baseClassOffset);
		}
		return baseClassOffsetMap;
	}

	/**
	 * Method to retrieve the given class's base class array data type from the RTTI data
	 * @param recoveredClass the given class
	 * @return the base class array data type or null 
	 * @throws CancelledException when cancelled
	 */
	private Data getBaseClassArray(RecoveredClass recoveredClass) throws CancelledException {

		List<Symbol> baseClassArray = extendedFlatAPI.getListOfSymbolsByNameInNamespace(
			RTTI_BASE_CLASS_ARRAY_LABEL, recoveredClass.getClassNamespace(), false);

		if (baseClassArray.size() != 1) {
			return null;
		}

		Address baseClassArrayAddress = baseClassArray.get(0).getAddress();
		Data baseClassArrayData = api.getDataAt(baseClassArrayAddress);
		if (!baseClassArrayData.isArray()) {
			return null;
		}

		return baseClassArrayData;
	}

	/**
	 * Retrieve the RecoveredClass object that corresponds to the one in the same namespace as the given RTTIBaseClassDescriptor address
	 * @param baseClassDescriptorAddress the address of the pointer to the RTTIBaseClassDescriptor structure
	 * @return the corresponding RecoveredClass object or null if it cannot be retrieved
	 * @throws MemoryAccessException if memory cannot be read
	 */
	private RecoveredClass getClassFromBaseClassDescriptor(Address baseClassDescriptorAddress)
			throws MemoryAccessException {

		Symbol baseClassDescSymbol = symbolTable.getPrimarySymbol(baseClassDescriptorAddress);
		if (baseClassDescSymbol == null) {
			return null;
		}
		Namespace namespace = baseClassDescSymbol.getParentNamespace();
		if (namespace.equals(globalNamespace)) {
			return null;
		}
		RecoveredClass baseClass = getClass(namespace);

		return baseClass;
	}

	/**
	 * Method to apply the given class's vbtable structure
	 * @param recoveredClass the given RecoveredClass object which, if applicable, contains the address and structure to apply
	 * @throws AddressOutOfBoundsException if try clear listing at address out of bounds
	 * @throws CancelledException if cancelled
	 * @throws Exception if issue creating data
	 */
	private void applyVbtableStructure(RecoveredClass recoveredClass)
			throws CancelledException, AddressOutOfBoundsException, Exception {

		Address vbtableAddress = recoveredClass.getVbtableAddress();
		if (vbtableAddress == null) {
			return;
		}

		Structure vbtableStructure = recoveredClass.getVbtableStructure();

		api.clearListing(vbtableAddress, vbtableAddress.add(vbtableStructure.getLength()));
		api.createData(vbtableAddress, vbtableStructure);

		api.setPlateComment(vbtableAddress,
			recoveredClass.getClassNamespace().getName(true) + "::vbtable");
	}

	/**
	 * Method to update the labels of vftables that belong to classes with multiple vftables in 
	 * order to distinguish which base class the vftable is for.
	 * @param recoveredClasses the list of RecoveredClass objects
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if bad chars trying to label
	 * @throws DuplicateNameException if duplicate name
	 */
	private void updateMultiVftableLabels(List<RecoveredClass> recoveredClasses)
			throws CancelledException, DuplicateNameException, InvalidInputException {

		if (recoveredClasses.isEmpty()) {
			return;
		}
		for (RecoveredClass recoveredClass : recoveredClasses) {
			monitor.checkCancelled();

			// if there are no vftables or only one vftable in this class then there is no need to 
			// distinguish with a new label and can keep the generic one 
			List<Address> vftableAddresses = recoveredClass.getVftableAddresses();
			if (vftableAddresses.size() < 2) {
				continue;
			}

			for (Address vftableAddress : vftableAddresses) {
				RecoveredClass vftableBaseClass =
					recoveredClass.getVftableBaseClass(vftableAddress);
				if (vftableBaseClass != null) {
					Symbol primarySymbol = symbolTable.getPrimarySymbol(vftableAddress);

					String baseClassName = vftableBaseClass.getName();
					// get simplified name by removing template 
					String shortenedTemplateName = vftableBaseClass.getShortenedTemplateName();
					if (!shortenedTemplateName.isBlank()) {
						baseClassName = shortenedTemplateName;
					}

					primarySymbol.setName("vftable_for_" + baseClassName,
						primarySymbol.getSource());
				}
			}
		}
	}

	/**
	 * Method to fixup previously found deleting destructors's symbols to determine if they are
	 * scalar or vector ones and name appropriately. In the non-contiguous case, split into two
	 * functions and name accordingly.
	 * @param recoveredClasses the list of classes to processes
	 * @throws CancelledException if cancelled
	 */
	private void fixUpDeletingDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		List<Function> processedFunctions = new ArrayList<>();

		for (RecoveredClass recoveredClass : recoveredClasses) {
			monitor.checkCancelled();

			List<Function> deletingDestructors = recoveredClass.getDeletingDestructors();

			if (deletingDestructors.isEmpty()) {
				continue;
			}

			for (Function function : deletingDestructors) {
				monitor.checkCancelled();

				if (processedFunctions.contains(function)) {
					continue;
				}

				AddressSetView body = function.getBody();
				int numAddressRanges = body.getNumAddressRanges();

				// fixup contigous dd function
				if (numAddressRanges == 1) {
					fixupContiguousDeletingDestructorSymbols(function);
					processedFunctions.add(function);
					continue;
				}
				if (numAddressRanges == 2) {
					// else fixup split dd function 
					Function scalarDeletingDestructor = createSplitDeletingDestructorFunction(body);
					if (scalarDeletingDestructor == null) {
						Msg.debug(this, "Could not fixup split deleting destructor function: " +
							function.getEntryPoint());
						continue;
					}
					fixupSplitDeletingDestructorSymbols(function, scalarDeletingDestructor);
					processedFunctions.add(function);
				}
				// if > 2 do nothing - not sure how to handle or even if they exist
			}
		}
	}

	/**
	 * Method to fixup the given functoin as a contiguous deleting destructor which means it is 
	 * both a scalar and vector deleting destructor and needs both names. Some functions are deleting
	 * destructors for multiple classes so all of the symbols need to be updated.
	 * @param function the given function
	 * @throws CancelledException if cancelled
	 */
	private void fixupContiguousDeletingDestructorSymbols(Function function)
			throws CancelledException {

		Symbol[] functionSymbols = symbolTable.getSymbols(function.getEntryPoint());

		Address functionAddress = function.getEntryPoint();

		api.createBookmark(functionAddress, "Deleting Destructor Fixup",
			"Scalar and Vector Deleting Destructor");

		try {
			for (Symbol functionSymbol : functionSymbols) {
				monitor.checkCancelled();

				// skip any symbols at function that are not dds ie fid mangled names
				if (!functionSymbol.getName().contains(DELETING_DESTRUCTOR)) {
					continue;
				}

				functionSymbol.setName(SCALAR_DELETING_DESCTRUCTOR, functionSymbol.getSource());

				Symbol secondaryLabel = symbolTable.createLabel(functionAddress,
					VECTOR_DELETING_DESCTRUCTOR, SourceType.ANALYSIS);
				secondaryLabel.setNamespace(functionSymbol.getParentNamespace());

			}
		}
		catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			Msg.debug(this,
				"Could not fixup one or more deleting destructor symbols for function: " +
					functionAddress);
		}
	}

	/**
	 * Method to create a second function in the case where a deleting destructor is of the type
	 * vector dd function jumps to scalar dd function and fixup the jump to be a call return flow
	 * override
	 * @param body the given function body
	 * @return the newly created jumped to function or null if it cannot be created
	 */
	private Function createSplitDeletingDestructorFunction(AddressSetView body) {

		if (body.getNumAddressRanges() != 2) {
			return null;
		}
		AddressRange firstRange = body.getFirstRange();
		Address maxAddressofFirstRange = firstRange.getMaxAddress();
		Instruction instructionContaining = api.getInstructionContaining(maxAddressofFirstRange);
		if (!instructionContaining.getFlowType().isJump()) {
			return null;
		}
		AddressRange lastRange = body.getLastRange();
		Address minAddressOfLastRange = lastRange.getMinAddress();
		Reference reference = api.getReference(instructionContaining, minAddressOfLastRange);
		if (reference == null) {
			return null;
		}
		instructionContaining.setFlowOverride(FlowOverride.CALL_RETURN);
		Function newFunction = api.createFunction(minAddressOfLastRange, null);
		return newFunction;
	}

	/**
	 * Method to fixup the deleting destructor symbols in a split deleting destructor case given 
	 * the two functions split earlier from the original function. Some functions are deleting
	 * destructors for multiple classes so all of the symbols need to be updated.
	 * @param vectorDDFunction the vector deleting destructor function
	 * @param scalarDDFunction the scalar deleting destructor function
	 * @throws CancelledException if cancelled
	 */
	private void fixupSplitDeletingDestructorSymbols(Function vectorDDFunction,
			Function scalarDDFunction) throws CancelledException {

		Symbol[] functionSymbols = symbolTable.getSymbols(vectorDDFunction.getEntryPoint());

		try {
			for (Symbol functionSymbol : functionSymbols) {
				monitor.checkCancelled();

				// skip any symbols at function that are not dds ie fid mangled names
				if (!functionSymbol.getName().contains(DELETING_DESTRUCTOR)) {
					continue;
				}

				functionSymbol.setName(VECTOR_DELETING_DESCTRUCTOR, functionSymbol.getSource());

				Symbol secondaryLabel = symbolTable.createLabel(scalarDDFunction.getEntryPoint(),
					SCALAR_DELETING_DESCTRUCTOR, SourceType.ANALYSIS);
				secondaryLabel.setNamespace(functionSymbol.getParentNamespace());

			}
		}
		catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			Msg.debug(this,
				"Could not fixup one or more deleting destructor symbols for split functions: " +
					vectorDDFunction.getEntryPoint() + " and " + scalarDDFunction.getEntryPoint());
		}

		api.createBookmark(scalarDDFunction.getEntryPoint(), "Deleting Destructor Fixup",
			"Scalar Deleting Destructor");
		api.createBookmark(vectorDDFunction.getEntryPoint(), "Deleting Destructor Fixup",
			"Vector Deleting Destructor");

	}

}
