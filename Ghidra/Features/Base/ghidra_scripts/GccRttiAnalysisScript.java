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
// Script to create gcc RTTI vtables and structures 
//@category C++

import java.util.*;

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

public class GccRttiAnalysisScript extends GhidraScript {

	private static final String VTABLE_LABEL = "vtable";
	private static final String VFTABLE_LABEL = "vftable";
	private static final String DTM_CLASS_DATA_FOLDER_NAME = "ClassDataTypes";

	// specific to gcc globals
	Address class_type_info_vtable = null;
	Address si_class_type_info_vtable = null;
	Address vmi_class_type_info_vtable = null;
	Address class_type_info = null;
	Address si_class_type_info = null;
	Address vmi_class_type_info = null;

	boolean isGcc = false;

	DataTypeManager dataTypeManager = null;
	SymbolTable symbolTable = null;
	int defaultPointerSize = 0;
	GlobalNamespace globalNamespace = null;
	CategoryPath classDataTypesCategoryPath = null;

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("There is no open program");
			return;
		}

		setIsGcc();

		if (!isGcc) {
			println("This script only handles gcc programs");
			return;
		}

		defaultPointerSize = currentProgram.getDefaultPointerSize();
		if (defaultPointerSize != 4 && defaultPointerSize != 8) {
			println("This script only works on 32 or 64 bit programs");
			return;
		}

		dataTypeManager = currentProgram.getDataTypeManager();
		symbolTable = currentProgram.getSymbolTable();

		globalNamespace = (GlobalNamespace) currentProgram.getGlobalNamespace();
		
		// create the path for the data type manager root/ClassDataTypes folder
		classDataTypesCategoryPath =
			createDataTypeCategoryPath(CategoryPath.ROOT, DTM_CLASS_DATA_FOLDER_NAME);

		createGccRttiData();
	}

	/**
	 * Create data type manager path that will be used when data types are created to place them in the correct folder
	 * @param parent parent CategoryPath
	 * @param categoryName name of the new category in the parent path
	 * @return CategoryPath for new categoryName 
	 * @throws CancelledException if cancelled
	 */
	private CategoryPath createDataTypeCategoryPath(CategoryPath parent, String categoryName)
			throws CancelledException {

		CategoryPath dataTypePath;

		// if single namespace no parsing necessary, just create using given categoryName
		if (!categoryName.contains("::")) {
			dataTypePath = new CategoryPath(parent, categoryName);
			return dataTypePath;
		}

		// if category name contains :: but not valid template info then just 
		// replace ::'s with /'s to form multi level path
		if (!containsTemplate(categoryName)) {
			categoryName = categoryName.replace("::", "/");
		}

		// if category name contains both :: and matched template brackets then only replace the 
		// :: that are not contained inside template brackets
		else {
			boolean insideBrackets = false;
			int numOpenedBrackets = 0;
			int index = 0;
			String newCategoryName = new String();
			while (index < categoryName.length()) {
				monitor.checkCanceled();

				if (categoryName.substring(index).startsWith("::") && !insideBrackets) {
					newCategoryName = newCategoryName.concat("/");
					index += 2;
					continue;
				}

				String character = categoryName.substring(index, index + 1);

				newCategoryName = newCategoryName.concat(character);
				index++;

				if (character.equals("<")) {
					insideBrackets = true;
					numOpenedBrackets++;
				}
				if (character.equals(">")) {
					numOpenedBrackets--;
				}
				if (numOpenedBrackets == 0) {
					insideBrackets = false;
				}
			}
			categoryName = newCategoryName;
		}

		String path;
		if (parent.getName().equals("")) {
			path = "/" + categoryName;
		}
		else {
			path = "/" + parent.getName() + "/" + categoryName;
		}
		dataTypePath = new CategoryPath(path);

		return dataTypePath;

	}

	/**
	 * Method to check the given string to see if it contains valid template(s)
	 * @param name the given name to check
	 * @return true if name contains valid template(s), false otherwise
	 */
	private boolean containsTemplate(String name) {

		if (!name.contains("<")) {
			return false;
		}

		int numOpenLips = getNumSubstrings(name, "<");
		int numClosedLips = getNumSubstrings(name, ">");

		if (numOpenLips > 0 && numClosedLips > 0 && numOpenLips == numClosedLips) {
			return true;
		}
		return false;
	}

	/**
	 * Method to return the number of the given substrings contained in the given string
	 * @param string the given string
	 * @param substring the given substring
	 * @return the number of the given substrings in the given string
	 */
	private int getNumSubstrings(String string, String substring) {

		int num = 0;

		int indexOf = string.indexOf(substring);
		while (indexOf >= 0) {
			num++;
			string = string.substring(indexOf + 1);
			indexOf = string.indexOf(substring);
		}
		return num;
	}

	private void createGccRttiData() throws CancelledException, Exception {

		// find the three special vtables and replace the incorrectly made array with 
		// data types found in vtable
		boolean continueProcessing = createSpecialVtables();
		if(!continueProcessing) {
			return;
		}
		// find all typeinfo symbols and get their class namespace and create RecoveredClass object
		List<Symbol> typeinfoSymbols = getListOfSymbolsInAddressSet(
			currentProgram.getAddressFactory().getAddressSet(), "typeinfo", true);

		// create the appropriate type of type info struct at the various typeinfo symbol locations
		createTypeinfoStructs(typeinfoSymbols);

		// process vtables and create classes for the vtables that have no typeinfo
		processVtables();
	}

	/**
	 * Method to find the (up to three) special gcc vtables and replace the incorrectly made array with the
	 * correct data types. Also creates a type info symbol at the correct offset in the table.
	 * @return true if all found tables have a typeinfo symbol created successfully
	 * @throws CancelledException if cancelled
	 */
	private boolean createSpecialVtables() throws CancelledException {

		class_type_info_vtable = findSpecialVtable("__cxxabiv1", "__class_type_info");
		class_type_info = null;
		if (class_type_info_vtable == null) {
			println("__class_type_info vtable not found --> no classes without parents");
		}
		else {
			class_type_info = createSpecialVtable(class_type_info_vtable);
			if (class_type_info == null) {
				println(
					"__class_type_info typeinfo not found -- cannot continue gcc rtti processing");
				return false;
			}
		}

		si_class_type_info = null;
		si_class_type_info_vtable = findSpecialVtable("__cxxabiv1", "__si_class_type_info");
		if (si_class_type_info_vtable == null) {
			println("__si_class_type_info vtable not found --> no single parent classes");
		}
		else {
			si_class_type_info = createSpecialVtable(si_class_type_info_vtable);
			if (si_class_type_info == null) {
				println(
					"__si_class_type_info typeinfo not found -- cannot continue gcc rtti processing");
				return false;
			}
		}

		vmi_class_type_info_vtable = findSpecialVtable("__cxxabiv1", "__vmi_class_type_info");
		vmi_class_type_info = null;
		if (vmi_class_type_info_vtable == null) {
			println("__vmi_class_type_info vtable not found --> no multi-parent classes");
		}
		else {
			vmi_class_type_info = createSpecialVtable(vmi_class_type_info_vtable);
			if (vmi_class_type_info == null) {
				println(
					"__vmi_class_type_info typeinfo not found -- cannot continue gcc rtti processing");
				return false;
			}
		}
		
		if(class_type_info_vtable == null && si_class_type_info_vtable == null && vmi_class_type_info_vtable == null) {
			println("Since there are no class typeinfo tables this program does not appear to have RTTI.");
			return false;
		}
		return true;
	}

	private Address findSpecialVtable(String namespace, String name) throws CancelledException {

		Address vtableAddress = null;

		Symbol symbolInNamespaces = getSymbolInNamespaces(namespace, name, VTABLE_LABEL);

		if (symbolInNamespaces != null) {
			if (!symbolInNamespaces.isPrimary()) {
				symbolInNamespaces.setPrimary();
			}
			vtableAddress = symbolInNamespaces.getAddress();

			return vtableAddress;
		}

		// if there is just one address that has symbols containing both strings then it suggests
		// mangled symbol since the above didn't find it
		Address addressContainingBothStrings =
			getSingleAddressOfSymbolContainingBothStrings(namespace, name);
		if (addressContainingBothStrings == null) {
			return null;
		}

		// try demangling all the symbols at this address	
		Symbol[] vtableSymbols = symbolTable.getSymbols(addressContainingBothStrings);
		for (Symbol vtableSymbol : vtableSymbols) {
			DemanglerCmd cmd =
				new DemanglerCmd(addressContainingBothStrings, vtableSymbol.getName());
			cmd.applyTo(currentProgram, monitor);

		}

		// now check again to see if we can find the namespace/name
		symbolInNamespaces = getSymbolInNamespaces(namespace, name, VTABLE_LABEL);

		if (symbolInNamespaces != null) {
			if (!symbolInNamespaces.isPrimary()) {
				symbolInNamespaces.setPrimary();
			}
			vtableAddress = symbolInNamespaces.getAddress();

			return vtableAddress;
		}

		println(namespace + "::" + name + " table not found");
		return null;

	}

	/**
	 * Method to replace the array incorrectly placed at special vftable with longs followed by 
	 * typeinfo label
	 * @param vtableAddress the given special vtable address
	 * @return the address of the typeinfo in the vtable if replace was successful, null otherwise
	 * @throws CancelledException if cancelled
	 */
	private Address createSpecialVtable(Address vtableAddress) throws CancelledException {

		Symbol vtableSymbol = symbolTable.getPrimarySymbol(vtableAddress);

		clearListing(vtableAddress);
		try {
			int vtableLongs = createVtableLongs(vtableAddress);

			if (vtableLongs > 0) {

				Address typeinfoAddress = vtableAddress.add(vtableLongs * defaultPointerSize);
				symbolTable.createLabel(typeinfoAddress, "typeinfo",
					vtableSymbol.getParentNamespace(), SourceType.ANALYSIS);
				return typeinfoAddress;
			}
			return null;
		}

		catch (AddressOutOfBoundsException e) {
			return null;
		}
		catch (IllegalArgumentException e) {
			return null;
		}
		catch (InvalidInputException e) {
			return null;
		}

	}

	/**
	 * Method to create long data type at the given vtable address and return the number created OR
	 * if they are already created, just return how many there are
	 * @param vtableAddress the address of the given vtable
	 * @return the number of long data types at vtableAddress
	 */
	private int createVtableLongs(Address vtableAddress) {

		AddressSetView programAddressSet = currentProgram.getMemory().getAllInitializedAddressSet();
		DataType pointer = dataTypeManager.getPointer(null);
		LongDataType longDT = new LongDataType();

		int offset = 0;
		int numLongs = 0;
		while (true) {

			Address address = vtableAddress.add(offset);

			// Except for the first one which should have a symbol, if there is a symbol at the 
			// address, stop making longs because it there are no references into the vtable longs
			if (offset > 0 && symbolTable.getSymbols(address).length > 0) {
				return numLongs;
			}

			// create a pointer and check to see if it is a reference to a valid memory location
			try {
				createData(address, pointer);
				Address referencedAddress = getSingleReferencedAddress(address);

				// if it isn't valid, clear what we just created and increment to offset so
				// the next can be checked
				if (referencedAddress == null || !programAddressSet.contains(referencedAddress)) {
					clearListing(address);
					createData(address, longDT);
					offset += defaultPointerSize;
					numLongs++;
				}
				// if it is valid, leave the pointer created and get out of the loop
				else {
					return numLongs;
				}
			}
			catch (Exception e) {
				return numLongs;
			}

		}
	}

	/**
	 * Method to retrieve a single referenced address from the given address
	 * @param address the given address to look for a single referenced address
	 * @return the address referred to or null if none or more than one referenced
	 */
	private Address getSingleReferencedAddress(Address address) {

		List<Address> refFromAddresses = getReferenceFromAddresses(address);

		if (refFromAddresses.size() != 1) {
			return null;
		}

		return refFromAddresses.get(0);
	}

	/**
	 * Method to get a list of addressses that are references from the given address
	 * @param address the given address
	 * @return a list of addresses that are references from the given address
	 */
	private List<Address> getReferenceFromAddresses(Address address) {

		Reference[] referencesFrom = getReferencesFrom(address);

		// get only the address references at the given address (ie no stack refs, ...)
		List<Address> refFromAddresses = new ArrayList<Address>();
		for (Reference referenceFrom : referencesFrom) {
			if (referenceFrom.isMemoryReference()) {
				refFromAddresses.add(referenceFrom.getToAddress());
			}
		}

		return refFromAddresses;
	}

	private Address getSingleAddressOfSymbolContainingBothStrings(String string1, String string2)
			throws CancelledException {

		List<Address> symbolAddressList = new ArrayList<Address>();

		SymbolIterator symbols = symbolTable.getSymbolIterator("*" + string1 + "*", true);

		while (symbols.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = symbols.next();
			Address symbolAddress = symbol.getAddress();

			if (symbol.getName().contains(string2)) {
				if (!symbolAddressList.contains(symbolAddress)) {
					symbolAddressList.add(symbolAddress);
				}
			}
		}
		if (symbolAddressList.size() == 1) {
			return symbolAddressList.get(0);
		}
		return null;
	}

	/**
	 * Method to return a symbol with the given name in the given namespace which is in the given
	 * parent namespace or null if one is not found
	 * @param parentNamespaceName name of parent namespace
	 * @param namespaceName name of symbol namespace
	 * @param symbolName name of symbol
	 * @return Symbol with given name, namespace and parent namespace or null if doesn't exist
	 * @throws CancelledException if cancelled
	 */
	private Symbol getSymbolInNamespaces(String parentNamespaceName, String namespaceName,
			String symbolName) throws CancelledException {

		SymbolIterator symbols = symbolTable.getSymbols(symbolName);
		while (symbols.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = symbols.next();
			if (symbol.getParentNamespace().getName().equals(namespaceName)) {
				Namespace namespace = symbol.getParentNamespace();
				if (namespace.getParentNamespace().getName().equals(parentNamespaceName)) {
					return symbol;
				}
			}
		}
		return null;
	}

	/**
	 * Method to set the global variable isGcc
	 */
	private void setIsGcc() {

		isGcc =
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().equalsIgnoreCase(
				"gcc");
	}

	private void createTypeinfoStructs(List<Symbol> typeinfoSymbols) throws CancelledException {

		StructureDataType classTypeInfoStructure = createClassTypeInfoStructure();
		StructureDataType siClassTypeInfoStructure =
			createSiClassTypeInfoStructure(classTypeInfoStructure);
		StructureDataType baseClassTypeInfoStructure =
			createBaseClassTypeInfoStructure(classTypeInfoStructure);

		Iterator<Symbol> typeinfoIterator = typeinfoSymbols.iterator();
		while (typeinfoIterator.hasNext()) {

			monitor.checkCanceled();

			Symbol typeinfoSymbol = typeinfoIterator.next();
			Address typeinfoAddress = typeinfoSymbol.getAddress();

			// skip the typeinfo symbols from the three special typeinfos 
			if (isSpecialTypeinfo(typeinfoAddress)) {
				continue;
			}

			Address specialTypeinfoRef = getSingleReferencedAddress(typeinfoAddress);
			if (specialTypeinfoRef == null) {
				println("No special typeinfo reference found. Cannot process typeinfo struct at " +
					typeinfoAddress.toString());
				continue;
			}

			if (!isSpecialTypeinfo(specialTypeinfoRef)) {
				continue;
			}

			try {
				// create a "no inheritance" struct here
				if (specialTypeinfoRef.equals(class_type_info)) {
					clearListing(typeinfoAddress,
						typeinfoAddress.add(classTypeInfoStructure.getLength()));
					createData(typeinfoAddress, classTypeInfoStructure);
					continue;
				}

				// create a "single inheritance" struct here
				if (specialTypeinfoRef.equals(si_class_type_info)) {
					clearListing(typeinfoAddress,
						typeinfoAddress.add(siClassTypeInfoStructure.getLength() - 1));
					createData(typeinfoAddress, siClassTypeInfoStructure);
					continue;
				}

				// create a "virtual multip inheritance" struct here
				if (specialTypeinfoRef.equals(vmi_class_type_info)) {

					// get num base classes
					int offsetOfNumBases = 2 * defaultPointerSize + 4;
					int numBases = getInt(typeinfoAddress.add(offsetOfNumBases));

					// get or create the vmiClassTypeInfoStruct
					Structure vmiClassTypeinfoStructure =
						(Structure) dataTypeManager.getDataType(classDataTypesCategoryPath,
							"VmiClassTypeInfoStructure" + numBases);
					if (vmiClassTypeinfoStructure == null) {
						vmiClassTypeinfoStructure =
							createVmiClassTypeInfoStructure(baseClassTypeInfoStructure, numBases);
					}
					clearListing(typeinfoAddress,
						typeinfoAddress.add(vmiClassTypeinfoStructure.getLength() - 1));
					createData(typeinfoAddress, vmiClassTypeinfoStructure);

				}
			}
			catch (Exception e) {
				println("ERROR: Could not apply structure to " + typeinfoAddress);
			}
		}

	}

	/**
	 * Method to check if given typeinfo is one of the three special ones
	 * @param typeinfoAddress the given typeinfo address
	 * @return true if it is a special one, false otherwise
	 */
	private boolean isSpecialTypeinfo(Address typeinfoAddress) {
		if (typeinfoAddress.equals(class_type_info) || typeinfoAddress.equals(si_class_type_info) ||
			typeinfoAddress.equals(vmi_class_type_info)) {
			return true;
		}
		return false;
	}

	private StructureDataType createClassTypeInfoStructure() {

		StructureDataType classTypeInfoStructure = new StructureDataType(classDataTypesCategoryPath,
			"ClassTypeInfoStructure", 0, dataTypeManager);

		CharDataType characterDT = new CharDataType();
		DataType pointer = dataTypeManager.getPointer(null);
		DataType charPointer = dataTypeManager.getPointer(characterDT);
		classTypeInfoStructure.add(pointer, "classTypeinfoPtr", null);
		classTypeInfoStructure.add(charPointer, "typeinfoName", null);

		classTypeInfoStructure.setPackingEnabled(true);

		return classTypeInfoStructure;
	}

	private StructureDataType createSiClassTypeInfoStructure(
			StructureDataType classTypeInfoStructure) {

		StructureDataType siClassTypeInfoStructure = new StructureDataType(
			classDataTypesCategoryPath, "SiClassTypeInfoStructure", 0, dataTypeManager);

		CharDataType characterDT = new CharDataType();
		DataType pointer = dataTypeManager.getPointer(null);
		DataType charPointer = dataTypeManager.getPointer(characterDT);
		//TODO: ?? replace with classTypeInfoStruct?
		siClassTypeInfoStructure.add(pointer, "classTypeinfoPtr", null);
		siClassTypeInfoStructure.add(charPointer, "typeinfoName", null);

		DataType pointerToClassTypeInfoStruct = dataTypeManager.getPointer(classTypeInfoStructure);
		siClassTypeInfoStructure.add(pointerToClassTypeInfoStruct, "baseClassTypeInfoPtr", null);

		siClassTypeInfoStructure.setPackingEnabled(true);

		return siClassTypeInfoStructure;
	}

	private StructureDataType createBaseClassTypeInfoStructure(
			StructureDataType classTypeInfoStructure) {

		StructureDataType baseclassTypeInfoStructure = new StructureDataType(
			classDataTypesCategoryPath, "BaseClassTypeInfoStructure", 0, dataTypeManager);

		DataType classTypeInfoPointer = dataTypeManager.getPointer(classTypeInfoStructure);

		LongDataType longDT = new LongDataType();

		baseclassTypeInfoStructure.add(classTypeInfoPointer, "classTypeinfoPtr", null);
		baseclassTypeInfoStructure.add(longDT, "offsetFlags", null);

		baseclassTypeInfoStructure.setPackingEnabled(true);

		return baseclassTypeInfoStructure;

	}

	private StructureDataType createVmiClassTypeInfoStructure(
			StructureDataType baseClassTypeInfoStructure, int numBaseClasses) {

		StructureDataType vmiClassTypeInfoStructure =
			new StructureDataType(classDataTypesCategoryPath,
				"VmiClassTypeInfoStructure" + numBaseClasses, 0, dataTypeManager);

		CharDataType characterDT = new CharDataType();
		UnsignedIntegerDataType unsignedIntDT = new UnsignedIntegerDataType();

		DataType pointer = dataTypeManager.getPointer(null);
		DataType charPointer = dataTypeManager.getPointer(characterDT);

		//TODO: ?? replace with classTypeInfoStruct?
		vmiClassTypeInfoStructure.add(pointer, "classTypeinfoPtr", null);
		vmiClassTypeInfoStructure.add(charPointer, "typeinfoName", null);
		vmiClassTypeInfoStructure.add(unsignedIntDT, "flags", null);
		vmiClassTypeInfoStructure.add(unsignedIntDT, "numBaseClasses", null);

		// make array of base class type info structs
		ArrayDataType baseClassArray = new ArrayDataType(baseClassTypeInfoStructure, numBaseClasses,
			baseClassTypeInfoStructure.getLength());
		vmiClassTypeInfoStructure.add(baseClassArray, "baseClassPtrArray", null);

		vmiClassTypeInfoStructure.setPackingEnabled(true);

		return vmiClassTypeInfoStructure;
	}

	/**
	 * Method to process the primary vtable for each "vtable" label
	 * @throws Exception if Data cannot be created
	 */
	private void processVtables() throws Exception {


		// find all vtable symbols
		List<Symbol> listOfVtableSymbols = getListOfSymbolsInAddressSet(
			currentProgram.getAddressFactory().getAddressSet(), VTABLE_LABEL, false);

		Iterator<Symbol> vtableIterator = listOfVtableSymbols.iterator();
		while (vtableIterator.hasNext()) {

			monitor.checkCanceled();

			Symbol vtableSymbol = vtableIterator.next();
			Namespace vtableNamespace = vtableSymbol.getParentNamespace();
			Address vtableAddress = vtableSymbol.getAddress();

			processVtable(vtableAddress, vtableNamespace, true);


		}
		return;
	}

	private void processVtable(Address vtableAddress, Namespace vtableNamespace, boolean isPrimary)
			throws CancelledException {

		// skip the special tables			
		if (vtableAddress.equals(class_type_info_vtable) ||
			vtableAddress.equals(si_class_type_info_vtable) ||
			vtableAddress.equals(vmi_class_type_info_vtable)) {
			return;
		}

		Data dataAt = getDataAt(vtableAddress);

		// first check to see it is an erroneous vtable that has been made a byte array
		// if so, clear it and start looking for the typeinfo reference
		if (dataAt != null && dataAt.isArray()) {
			clearListing(vtableAddress);

		}
		if (dataAt != null && !dataAt.getDataType().getName().equals("long")) {
			clearListing(vtableAddress);
		}

		// find the special type info ref
		Address typeinfoAddress = findNextTypeinfoRef(vtableAddress);
		if (typeinfoAddress == null) {
			println(vtableNamespace.getName() + " vtable has no typeinfo ref after vtable at " +
				vtableAddress.toString());
			return;
		}

		// create the typeinfo pointer if there isn't already one
		Data typeinfoPtr = getDataAt(typeinfoAddress);
		if (typeinfoPtr == null) {
			DataType nullPointer = dataTypeManager.getPointer(null);
			try {
				createData(typeinfoAddress, nullPointer);
			}
			catch (Exception e) {
				println("Could not create typeinfo pointer at " + typeinfoAddress.toString());
			}
		}

		// create longs from top of vtable to the typeinfoAddress
		createLongs(vtableAddress, typeinfoAddress);

		Address vftableAddress = getAddress(typeinfoAddress, defaultPointerSize);

		if (vftableAddress == null) {
			return;
		}


		int numFunctionPointers = getNumFunctionPointers(vftableAddress, true, true);

		// if at least one function pointer make vftable label - the createVftable method will
		// create the table later
		if (numFunctionPointers > 0) {

			String vftableLabel = VFTABLE_LABEL;
			if (!isPrimary) {
				vftableLabel = "internal_" + vftableLabel;
			}

			try {
				Symbol vftableSymbol = symbolTable.createLabel(vftableAddress, vftableLabel,
					vtableNamespace, SourceType.ANALYSIS);

				createVftableArray(vftableAddress, numFunctionPointers);
			}
			catch (IllegalArgumentException e) {
				println("Could not label vftable at " + vftableAddress.toString());

			}
			catch (InvalidInputException e) {
				println("Could not label vftable at " + vftableAddress.toString());

			}
			catch (CancelledException e) {
				return;
			}
			catch (AddressOutOfBoundsException e) {
				println("Couldn't create vftable due to Address out of bounds issue");
				return;
			}
		}


		// check for an internal vtable and make a symbol there if there is one
		// will process them later
		Address possibleInternalVtableAddress =
			getAddress(vftableAddress, defaultPointerSize * numFunctionPointers);
		// if there is no symbol or a non-default symbol then the nextAddress is an internal
		// vtable
		if (possibleInternalVtableAddress == null) {
			return;
		}
		Symbol possibleInternalVtableSymbol =
			symbolTable.getPrimarySymbol(possibleInternalVtableAddress);
		if (possibleInternalVtableSymbol != null &&
			possibleInternalVtableSymbol.getSource() != SourceType.DEFAULT &&
			(!possibleInternalVtableSymbol.getParentNamespace().equals(vtableNamespace) ||
				!possibleInternalVtableSymbol.getName().contains("vtable"))) {
			return;
		}

		if (possibleInternalVtableSymbol == null ||
			(possibleInternalVtableSymbol.getSource() == SourceType.DEFAULT &&
				(isValidVtableStart(possibleInternalVtableAddress) ||
					isValidVftableStart(possibleInternalVtableAddress)))) {
			try {
				symbolTable.createLabel(possibleInternalVtableAddress,
					"internal_vtable_" + possibleInternalVtableAddress.toString(),
					vtableNamespace, SourceType.ANALYSIS);
				processVtable(possibleInternalVtableAddress, vtableNamespace, false);
			}
			catch (IllegalArgumentException e) {
				println("Could not label internal vtable at " +
					possibleInternalVtableAddress.toString());
			}
			catch (InvalidInputException e) {
				println("Could not label internal vtable at " +
					possibleInternalVtableAddress.toString());
			}

		}

	}

	private Data createVftableArray(Address vftableAddress, int numFunctionPointers)
			throws CancelledException, AddressOutOfBoundsException {

		clearListing(vftableAddress,
			vftableAddress.add((numFunctionPointers * defaultPointerSize - 1)));

		DataType pointerDataType = dataTypeManager.getPointer(null);
		ArrayDataType vftableArrayDataType =
			new ArrayDataType(pointerDataType, numFunctionPointers, defaultPointerSize);
		try {
			Data vftableArrayData = createData(vftableAddress, vftableArrayDataType);
			return vftableArrayData;
		}
		catch (Exception e) {
			return null;
		}

	}

	/**
	 * Method to check for a valid vtable at the given address
	 * @param vtableAddress the given address
	 * @return true if there is a valid vtable at the given address, false otherwise
	 */
	private boolean isValidVtableStart(Address vtableAddress) {

		// check that no refs into the first 2*defaultptr bytes
		// skip top of table since that will have references to it
		Address address = getAddress(vtableAddress, 1);
		if (address == null) {
			return false;
		}
		if (!areNoReferencesInto(address, 2 * defaultPointerSize - 1)) {
			return false;
		}

		// check that no pointers
		if (!areNoReferencesFrom(vtableAddress, 2 * defaultPointerSize)) {
			return false;
		}

		// check that no other data exept possibly longs at correct offsets
		if (!isNoDataCreatedExceptMaybeLongs(vtableAddress, 2 * defaultPointerSize)) {
			return false;
		}

		// TODO: maybe print a warning if the first item is not all zeros bc usually they are -- but pass
		// it even then

		return true;
	}

	private boolean isValidVftableStart(Address vftableAddress) throws CancelledException {

		// no refs into first defaaultPointerSize bytes
		Address address = getAddress(vftableAddress, 1);
		if (address == null) {
			return false;
		}

		if (!areNoReferencesInto(address, defaultPointerSize - 1)) {
			return false;
		}

		if (hasNumZeros(vftableAddress, defaultPointerSize)) {
			return true;
		}

		Data data = getDataAt(vftableAddress);
		if (data != null) {
			if (!data.isPointer()) {
				return false;
			}
			Address referencedAddress = getSingleReferencedAddress(vftableAddress);
			if (referencedAddress == null) {
				return false;
			}
			Function functionAt = getFunctionAt(referencedAddress);
			if (functionAt != null) {
				return true;
			}
		}
		else {
			try {
				Long longValue = getLong(address);
				Address functionAddress = address.getNewAddress(longValue);
				Function functionAt = getFunctionAt(functionAddress);
				if (functionAt != null) {
					return true;
				}
			}
			catch (MemoryAccessException e) {
				return false;
			}
			catch (AddressOutOfBoundsException e) {
				return false;
			}

		}

		return false;
	}

	/**
	 * Method to check for num zeros at the given address
	 * @param address the given address
	 * @param numZeros the number of zeros to check for
	 * @return true if there are numZero zeros at the given address
	 * @throws CancelledException if cancelled
	 */
	private boolean hasNumZeros(Address address, int numZeros) throws CancelledException {

		int index = 0;
		try {
			while (index < numZeros) {
				monitor.checkCanceled();
				if (getByte(address.add(index)) != 0x00) {
					return false;
				}
				index++;
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		return true;
	}

	private boolean areNoReferencesInto(Address topAddress, int length) {

		int offset = 0;

		MemoryBlock currentMemoryBlock = currentProgram.getMemory().getBlock(topAddress);

		while (offset < length) {

			Address address = getAddress(topAddress, offset);

			if (address == null) {
				return false;
			}

			if (!currentMemoryBlock.contains(address)) {
				return false;
			}

			Reference[] referencesTo = getReferencesTo(address);
			if (referencesTo.length > 0) {
				return false;
			}

			offset++;

		}
		return true;
	}

	private boolean areNoReferencesFrom(Address topAddress, int length) {

		int offset = 0;

		MemoryBlock currentMemoryBlock = currentProgram.getMemory().getBlock(topAddress);

		while (offset < length) {

			Address address = getAddress(topAddress, offset);

			if (address == null) {
				return false;
			}

			if (!currentMemoryBlock.contains(address)) {
				return false;
			}

			List<Address> referenceFromAddresses = getReferenceFromAddresses(address);

			if (referenceFromAddresses.size() > 0) {
				return false;
			}

			offset++;

		}

		return true;

	}

	private boolean isNoDataCreatedExceptMaybeLongs(Address startAddress, int length) {

		int offset = 0;

		MemoryBlock currentMemoryBlock = currentProgram.getMemory().getBlock(startAddress);

		while (offset < length) {

			Address address = getAddress(startAddress, offset);

			if (address == null) {
				return false;
			}

			if (!currentMemoryBlock.contains(address)) {
				return false;
			}

			Data data = getDataAt(address);

			// if there is data and it isn't on a pointer size boundary then return null
			// if there is data and it is on a pointer size boundary but isn't a long then
			// return null
			// otherwise, continue
			if (data != null) {
				if (offset % defaultPointerSize == 0 &&
					data.getBaseDataType().getName().equals("long")) {
					offset += defaultPointerSize;
					continue;
				}
				return false;
			}
			offset++;
		}

		return true;

	}

	private int getNumFunctionPointers(Address topAddress, boolean allowNullFunctionPtrs,
			boolean allowDefaultRefsInMiddle) throws CancelledException {

		int numFunctionPointers = 0;
		Address address = topAddress;
		MemoryBlock currentBlock = currentProgram.getMemory().getBlock(topAddress);

		boolean stillInCurrentTable = true;
		while (address != null && currentBlock.contains(address) && stillInCurrentTable &&
			(isPossibleFunctionPointer(address) ||
				(allowNullFunctionPtrs && isPossibleNullPointer(address)))) {

			numFunctionPointers++;
			address = address.add(defaultPointerSize);
			Symbol symbol = getSymbolAt(address);
			if (symbol == null) {
				continue;
			}
			// never let non-default refs in middle
			if (symbol.getSource() != SourceType.DEFAULT) {
				stillInCurrentTable = false;
			}

			// if it gets here it is default
			if (!allowDefaultRefsInMiddle) {
				stillInCurrentTable = false;
			}
		}

		return numFunctionPointers;

	}

	/**
	 * Method to determine if there are enough zeros to make a null poihnter and no references into
	 * or out of the middle 
	 * @param address the given address
	 * @return true if the given address could be a valid null pointer, false if not
	 */
	private boolean isPossibleNullPointer(Address address) throws CancelledException {
		if (!hasNumZeros(address, defaultPointerSize)) {
			return false;
		}
		return true;
	}

	/**
	 * Method to determine if the given address contains a possible function pointer
	 * @param address the given address
	 * @return true if the given address contains a possible function pointer or false otherwise
	 */
	private boolean isPossibleFunctionPointer(Address address) {

		Address possibleFunctionPointer = getPointer(address);
		if (possibleFunctionPointer == null) {
			return false;
		}

		Function function = getFunctionAt(possibleFunctionPointer);
		if (function != null) {
			return true;
		}
		return false;
	}

	/**
	 * Method to get the pointer formed by the bytes at the current address
	 * @param address the given address
	 * @return the pointer formed by the bytes at the current address
	 */
	private Address getPointer(Address address) {

		try {
			long offset = 0;

			if (defaultPointerSize == 4) {
				offset = getInt(address);
			}
			if (defaultPointerSize == 8) {
				offset = getLong(address);
			}
			if (offset == 0) {
				return null;
			}
			Address possibleFunctionPointer = currentAddress.getNewAddress(offset);
			return possibleFunctionPointer;

		}
		catch (MemoryAccessException e) {
			return null;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}


	private Address findNextTypeinfoRef(Address startAddress) {

		int offset = 0;

		Address address = getAddress(startAddress, offset);

		MemoryBlock currentMemoryBlock = currentProgram.getMemory().getBlock(startAddress);

		while (address != null && currentMemoryBlock.contains(address)) {

			//TODO: consider just returning once any symbol is found since I have 
			// never seen a ref to the longs or the typeinfo -- that way if there 
			// ever is a case where there is no typeinfo ref in primary vtable but there is in 
			// a secondary - don't think that is ever supposed to happen though -- it will get
			// stopped by the symbols at vftable or internal vtable or next primary vtable
			Symbol symbol = symbolTable.getPrimarySymbol(address);
			// if the symbol we find is not a default symbol 
			// because we have reached the end of the item we are searching
			if (!address.equals(startAddress) && symbol != null &&
				symbol.getSource() != SourceType.DEFAULT) {
				return null;
			}

			Address possibleTypeinfo = getPointer(address);
			if (possibleTypeinfo == null) {
				offset += defaultPointerSize;
				address = getAddress(startAddress, offset);
				continue;
			}

			Symbol possibleTypeinfoSymbol = symbolTable.getPrimarySymbol(possibleTypeinfo);
			if (possibleTypeinfoSymbol != null &&
				possibleTypeinfoSymbol.getName().equals("typeinfo")) {
				return address;
			}
			offset += defaultPointerSize;
			address = getAddress(startAddress, offset);

		}

		return null;
	}

	/**
	 * Method to get a list of symbols either matching exactly (if exact flag is true) or containing (if exact flag is false) the given symbol name
	 * @param addressSet the address set to find matching symbols in
	 * @param symbolName the symbol name to match
	 * @param exact flag used to determine whether to return only exact symbol name matches or ones that contain the given symbol
	 * @return list of symbols in the address set with the given symbol name, only exact ones if exact flag is true or ones that contain the symbol if exact is false
	 * @throws CancelledException if cancelled
	 */
	private List<Symbol> getListOfSymbolsInAddressSet(AddressSet addressSet, String symbolName,
			boolean exact) throws CancelledException {

		List<Symbol> symbolsInSet = new ArrayList<Symbol>();

		SymbolIterator symbols = symbolTable.getSymbols(addressSet, SymbolType.LABEL, true);

		while (symbols.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = symbols.next();
			if (exact && symbol.getName().equals(symbolName)) {
				symbolsInSet.add(symbol);
				continue;
			}
			if (!exact && symbol.getName().contains(symbolName)) {
				symbolsInSet.add(symbol);
			}
		}
		return symbolsInSet;
	}

	/**
	 * Method to create a series of long data types from the given start address to the given end 
	 * address
	 * @param start the starting address
	 * @param end the ending address
	 */
	private void createLongs(Address start, Address end) {

		LongDataType longDT = new LongDataType();
		int offset = 0;
		Address address = start;
		while (address != null && !address.equals(end)) {
			try {
				clearListing(address);
				createData(address, longDT);
				offset += defaultPointerSize;
				address = getAddress(start, offset);
			}
			catch (Exception e) {
				return;
			}
		}

	}

	/**
	 * Method to get address at address + offset
	 * @param address the given address
	 * @param offset the given offset
	 * @return the address at address + offset or null if it doesn't exist
	 */
	private Address getAddress(Address address, int offset) {
		try {
			Address newAddress = address.add(offset);
			return newAddress;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

}

