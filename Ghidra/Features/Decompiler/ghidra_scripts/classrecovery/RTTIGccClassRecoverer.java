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
package classrecovery;
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
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class RTTIGccClassRecoverer extends RTTIClassRecoverer {

	private static final String VTABLE_LABEL = "vtable";
	private static final String CLASS_VTABLE_PTR_FIELD_EXT = "vftablePtr";
	private static final int NONE = -1;
	private static final int UNKNOWN = -2;
	private static final boolean DEBUG = false;

	Map<RecoveredClass, Address> classToTypeinfoMap = new HashMap<RecoveredClass, Address>();
	Address class_type_info_vtable = null;
	Address si_class_type_info_vtable = null;
	Address vmi_class_type_info_vtable = null;
	Address class_type_info = null;
	Address si_class_type_info = null;
	Address vmi_class_type_info = null;

	List<RecoveredClass> nonInheritedGccClasses = new ArrayList<RecoveredClass>();
	List<RecoveredClass> singleInheritedGccClasses = new ArrayList<RecoveredClass>();
	List<RecoveredClass> multiInheritedGccClasses = new ArrayList<RecoveredClass>();

	public RTTIGccClassRecoverer(Program program, ProgramLocation location, PluginTool tool,
			FlatProgramAPI api, boolean createBookmarks, boolean useShortTemplates,
			boolean nameVfunctions,
			TaskMonitor monitor) {

		super(program, location, tool, api, createBookmarks, useShortTemplates, nameVfunctions,
			monitor);
	}

	@Override
	public boolean containsRTTI() throws CancelledException {

		if (!hasSpecialVtable()) {
			return false;
		}

		return true;
	}

	@Override
	public boolean isValidProgramType() {
		if (!isGcc()) {
			return false;
		}
		return true;
	}

	@Override
	public List<RecoveredClass> createRecoveredClasses() {


		try {

			List<RecoveredClass> recoveredClasses = processGccRTTI();
			if (recoveredClasses == null) {
				Msg.debug(this, "Could not recover gcc rtti classes");
				return null;
			}

			createCalledFunctionMap(recoveredClasses);

			createClassHierarchyListAndMapForGcc(recoveredClasses);

			assignConstructorsAndDestructorsUsingExistingName(recoveredClasses);

			createVftableOrderMap(recoveredClasses);

			retrieveExistingClassStructures(recoveredClasses);

			figureOutClassDataMembers(recoveredClasses);

			createAndApplyClassStructures(recoveredClasses);

			return recoveredClasses;
		}
		catch (CancelledException e) {
			e.printStackTrace();
			return null;
		}
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}



	}

	private boolean isGcc() {

		boolean isELF = program.getExecutableFormat().contains("ELF");
		if (!isELF) {
			return false;
		}

		boolean isCompilerSpecGcc =
			program.getCompilerSpec().getCompilerSpecID().getIdAsString().equalsIgnoreCase("gcc");
		if (isCompilerSpecGcc) {
			return true;
		}

		MemoryBlock commentBlock = program.getMemory().getBlock(".comment");
		if (commentBlock == null) {
			return false;
		}

		if (!commentBlock.isLoaded()) {
			return false;
		}

		// check memory bytes in block for GCC: bytes
		byte[] gccBytes = { (byte) 0x47, (byte) 0x43, (byte) 0x43, (byte) 0x3a };
		byte[] maskBytes = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

		Address found = program.getMemory().findBytes(commentBlock.getStart(),
			commentBlock.getEnd(),
			gccBytes, maskBytes, true, monitor);
		if (found == null) {
			return false;
		}
		return true;

	}

	/**
	 * Method to check for at least one special RTTI vtable
	 * @return true if the program has at least one special vtable, false if none
	 * @throws CancelledException if cancelled
	 */
	private boolean hasSpecialVtable() throws CancelledException {

		boolean hasSpecialVtable = createSpecialVtables();
		return hasSpecialVtable;

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
			cmd.applyTo(program, monitor);

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

		return null;

	}

	private List<RecoveredClass> processGccRTTI() throws CancelledException, Exception {


		// create rtti vtables and typeinfo structs
		// find the three special vtables and replace the incorrectly made array with 
		// data types found in vtable
		createGccRttiData();

		// find all typeinfo symbols and get their class namespace and create RecoveredClass object
		List<Symbol> typeinfoSymbols = extraUtils.getListOfSymbolsInAddressSet(
			program.getAddressFactory().getAddressSet(), "typeinfo", true);

		// create class objects for each typeinfo struct and make a class to typeinfo mapping for each		
		List<RecoveredClass> nonVftableRecoveredClasses =
			createClassesFromTypeinfoSymbols(typeinfoSymbols);

		// process vtables and create classes for the vtables that have no typeinfo
		List<Symbol> vftableSymbols = findVftablesFromVtables();
		if (DEBUG) {
			Msg.debug(this, "Found " + vftableSymbols.size() + "vftableSymbols");
		}

		List<RecoveredClass> recoveredClasses =
			recoverClassesFromVftables(vftableSymbols, true, true);

		if (!nonVftableRecoveredClasses.isEmpty()) {
			for (RecoveredClass nonVClass : nonVftableRecoveredClasses) {
				monitor.checkCanceled();
				if (!recoveredClasses.contains(nonVClass)) {
					recoveredClasses.add(nonVClass);
				}
			}
		}

		// TODO: are all recovered classes in the map?

		// update the recoveredClass list with the typeinfo classes that do not have vtables
		Set<RecoveredClass> typeinfoClasses = classToTypeinfoMap.keySet();
		Iterator<RecoveredClass> typeinfoClassIterator = typeinfoClasses.iterator();
		while (typeinfoClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass typeinfoClass = typeinfoClassIterator.next();
			if (!recoveredClasses.contains(typeinfoClass)) {
				recoveredClasses.add(typeinfoClass);
			}
		}

		// add properties and parents to each class 
		if (DEBUG) {
			Msg.debug(this, "Found " + typeinfoSymbols.size() + " typeinfo symbols");
		}
		Iterator<Symbol> typeinfoIterator = typeinfoSymbols.iterator();
		while (typeinfoIterator.hasNext()) {

			monitor.checkCanceled();

			Symbol typeinfoSymbol = typeinfoIterator.next();
			Address typeinfoAddress = typeinfoSymbol.getAddress();

			// skip the typeinfo symbols from the three special typeinfos 
			if (typeinfoAddress.equals(class_type_info) ||
				typeinfoAddress.equals(si_class_type_info) ||
				typeinfoAddress.equals(vmi_class_type_info)) {
				continue;
			}

			Namespace classNamespace = typeinfoSymbol.getParentNamespace();

			RecoveredClass recoveredClass = getClass(classNamespace);

			// we don't know yet if this class has vftable so just add without for now
			if (recoveredClass == null) {
				// this shoudln't be null at this point
				if (DEBUG) {
					Msg.debug(this, "Shouldn't be a null class here: " + classNamespace.getName());
				}
				recoveredClass = addNoVftableClass(classNamespace);
				recoveredClasses.add(recoveredClass);
			}

			Address specialTypeinfoRef = extraUtils.getSingleReferencedAddress(typeinfoAddress);
			if (specialTypeinfoRef == null) {
				if (DEBUG) {
					Msg.debug(this,
						"No special typeinfo reference found. Cannot process typeinfo struct at " +
							typeinfoAddress.toString());
				}
				continue;
			}

			if (!isSpecialTypeinfo(specialTypeinfoRef)) {
				// check for EXTERNAL block and look for specialTypeinfoRef there
				// if fix works, put external block error message and to contact us
				if (!hasExternalBlock()) {
					if (DEBUG) {
						Msg.debug(this,
							"Special typeinfo reference is not equal to one of the three special type infos. Cannot process typeinfo struct at " +
								typeinfoAddress.toString());
					}
					continue;
				}
				// use referenced vtable symbol name instead since when in EXTERNAL block
				// since can't get at the typeinfo ref in that block
				if (!isSpecialVtable(specialTypeinfoRef)) {
					if (DEBUG) {
						Msg.debug(this,
							"Special typeinfo reference is not equal to one of the three special type infos. Cannot process typeinfo struct at " +
								typeinfoAddress.toString());
					}
					continue;
				}

			}

			if (specialTypeinfoRef.equals(class_type_info) ||
				specialTypeinfoRef.equals(class_type_info_vtable)) {
				nonInheritedGccClasses.add(recoveredClass);
				continue;
			}

			// per docs those on this list are
			// classes containing only a single, public, non-virtual base at offset zero
			if (specialTypeinfoRef.equals(si_class_type_info) ||
				specialTypeinfoRef.equals(si_class_type_info_vtable)) {
				singleInheritedGccClasses.add(recoveredClass);

				RecoveredClass parentClass = getSiClassParent(typeinfoAddress);
				if (parentClass != null) {
					if (DEBUG) {
						Msg.debug(this,
							recoveredClass.getName() + " adding parent " + parentClass.getName());
					}
					updateClassWithParent(parentClass, recoveredClass);

					if (!recoveredClasses.contains(parentClass)) {
						if (DEBUG) {
							Msg.debug(this, recoveredClass.getName() +
								" adding an unknown parent " + parentClass.getName());
						}
						recoveredClasses.add(parentClass);
					}

				}
				else {
					if (DEBUG) {
						Msg.debug(this, "Could not get si parent from typeinfoAddress " +
							typeinfoAddress.toString());
					}
				}

				continue;
			}

			if (specialTypeinfoRef.equals(vmi_class_type_info) ||
				specialTypeinfoRef.equals(vmi_class_type_info_vtable)) {

				multiInheritedGccClasses.add(recoveredClass);

				recoveredClass.setHasMultipleInheritance(true);


				if (recoveredClass.inheritsVirtualAncestor()) {
					recoveredClass.setHasMultipleVirtualInheritance(true);
				}

				List<RecoveredClass> parents = addGccClassParents(recoveredClass, typeinfoAddress);

				if (!recoveredClasses.containsAll(parents)) {
					if (DEBUG) {
						Msg.debug(this,
							"missing some parents from " + recoveredClass.getName() + " on list");
					}
				}
//				newNonVftableClasses =
//					addMissingClasses(parents, newNonVftableClasses, recoveredClasses);
			}
		}

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {

			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

			Msg.debug(this, "Processing class " + recoveredClass.getName());

			List<Address> vftableAddresses = recoveredClass.getVftableAddresses();

			Iterator<Address> vftableAddressIterator = vftableAddresses.iterator();
			while (vftableAddressIterator.hasNext()) {
				monitor.checkCanceled();
				Address vftableAddress = vftableAddressIterator.next();

				Address offsetAddress = vftableAddress.subtract(2 * defaultPointerSize);
				int offsetValue = (int) api.getLong(offsetAddress);
				recoveredClass.addClassOffsetToVftableMapping(offsetValue, vftableAddress);
			}

		}

		createCalledFunctionMap(recoveredClasses);

		assignConstructorsAndDestructorsUsingExistingName(recoveredClasses);

		return recoveredClasses;

	}

	private void createGccRttiData() throws CancelledException, Exception {

		// TODO: find typeinfo's using other means besides their names since in static case they 
		// aren't named
		// TODO: either check for DWARF and do below if dwarf and another method to find them first
		// if not dwarf or combine and either way they are found - immediately call the create typeinfo struct
		// but for one at a time.
		// remove the ones in the list that are in the EXTERNAL (space or any non-loaded sapce) 
		// but keep the special ones on symbol list or maybe removet hem here too then  don't have
		// to keep skipping them later

		// find all typeinfo symbols and get their class namespace and create RecoveredClass object
		List<Symbol> typeinfoSymbols = extraUtils.getListOfSymbolsInAddressSet(
			program.getAddressFactory().getAddressSet(), "typeinfo", true);

		// create the appropriate type of type info struct at the various typeinfo symbol locations
		createTypeinfoStructs(typeinfoSymbols);

		// process vtables and create classes for the vtables that have no typeinfo
		processVtables();
	}

	/**
	 * Method to process the primary vtable for each "vtable" label
	 * @throws Exception if Data cannot be created
	 */
	private void processVtables() throws Exception {

		// find all vtable symbols
		List<Symbol> listOfVtableSymbols = extraUtils.getListOfSymbolsInAddressSet(
			program.getAddressFactory().getAddressSet(), VTABLE_LABEL, false);

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

		Data dataAt = api.getDataAt(vtableAddress);

		// first check to see it is an erroneous vtable that has been made a byte array
		// if so, clear it and start looking for the typeinfo reference
		if (dataAt != null && dataAt.isArray()) {
			api.clearListing(vtableAddress);

		}
		if (dataAt != null && !dataAt.getDataType().getName().equals("long")) {
			api.clearListing(vtableAddress);
		}

		// find the special type info ref
		Address typeinfoAddress = findNextTypeinfoRef(vtableAddress);
		if (typeinfoAddress == null) {
			if (DEBUG) {
				Msg.debug(this, vtableNamespace.getName() +
					" vtable has no typeinfo ref after vtable at " + vtableAddress.toString());
			}
			return;
		}

		// create the typeinfo pointer if there isn't already one
		Data typeinfoPtr = api.getDataAt(typeinfoAddress);
		if (typeinfoPtr == null) {
			DataType nullPointer = dataTypeManager.getPointer(null);
			try {
				api.createData(typeinfoAddress, nullPointer);
			}
			catch (Exception e) {
				Msg.debug(this,
					"Could not create typeinfo pointer at " + typeinfoAddress.toString());
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
				Msg.debug(this, "Could not label vftable at " + vftableAddress.toString());

			}
			catch (InvalidInputException e) {
				Msg.debug(this, "Could not label vftable at " + vftableAddress.toString());

			}
			catch (CancelledException e) {
				return;
			}
			catch (AddressOutOfBoundsException e) {
				Msg.debug(this, "Couldn't create vftable due to Address out of bounds issue");
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
					"internal_vtable_" + possibleInternalVtableAddress.toString(), vtableNamespace,
					SourceType.ANALYSIS);
				processVtable(possibleInternalVtableAddress, vtableNamespace, false);
			}
			catch (IllegalArgumentException e) {
				Msg.debug(this, "Could not label internal vtable at " +
					possibleInternalVtableAddress.toString());
			}
			catch (InvalidInputException e) {
				Msg.debug(this, "Could not label internal vtable at " +
					possibleInternalVtableAddress.toString());
			}

		}

	}

	private Data createVftableArray(Address vftableAddress, int numFunctionPointers)
			throws CancelledException, AddressOutOfBoundsException {

		api.clearListing(vftableAddress,
			vftableAddress.add((numFunctionPointers * defaultPointerSize - 1)));

		DataType pointerDataType = dataTypeManager.getPointer(null);
		ArrayDataType vftableArrayDataType =
			new ArrayDataType(pointerDataType, numFunctionPointers, defaultPointerSize);
		try {
			Data vftableArrayData = api.createData(vftableAddress, vftableArrayDataType);
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

	private boolean areNoReferencesInto(Address topAddress, int length) {

		int offset = 0;

		MemoryBlock currentMemoryBlock = program.getMemory().getBlock(topAddress);

		while (offset < length) {

			Address address = getAddress(topAddress, offset);

			if (address == null) {
				return false;
			}

			if (!currentMemoryBlock.contains(address)) {
				return false;
			}

			Reference[] referencesTo = extraUtils.getReferencesTo(address);
			if (referencesTo.length > 0) {
				return false;
			}

			offset++;

		}
		return true;
	}

	private boolean areNoReferencesFrom(Address topAddress, int length) {

		int offset = 0;

		MemoryBlock currentMemoryBlock = program.getMemory().getBlock(topAddress);

		while (offset < length) {

			Address address = getAddress(topAddress, offset);

			if (address == null) {
				return false;
			}

			if (!currentMemoryBlock.contains(address)) {
				return false;
			}

			List<Address> referenceFromAddresses = extraUtils.getReferenceFromAddresses(address);

			if (referenceFromAddresses.size() > 0) {
				return false;
			}

			offset++;

		}

		return true;

	}

	private boolean isNoDataCreatedExceptMaybeLongs(Address startAddress, int length) {

		int offset = 0;

		MemoryBlock currentMemoryBlock = program.getMemory().getBlock(startAddress);

		while (offset < length) {

			Address address = getAddress(startAddress, offset);

			if (address == null) {
				return false;
			}

			if (!currentMemoryBlock.contains(address)) {
				return false;
			}

			Data data = api.getDataAt(address);

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

	private boolean isValidVftableStart(Address vftableAddress) throws CancelledException {

		// no refs into first defaaultPointerSize bytes
		Address address = getAddress(vftableAddress, 1);
		if (address == null) {
			return false;
		}

		if (!areNoReferencesInto(address, defaultPointerSize - 1)) {
			return false;
		}

		if (extraUtils.hasNumZeros(vftableAddress, defaultPointerSize)) {
			return true;
		}

		Data data = api.getDataAt(vftableAddress);
		if (data != null) {
			if (!data.isPointer()) {
				return false;
			}
			Address referencedAddress = extraUtils.getSingleReferencedAddress(vftableAddress);
			if (referencedAddress == null) {
				return false;
			}
			Function functionAt = api.getFunctionAt(referencedAddress);
			if (functionAt != null) {
				return true;
			}
		}
		else {
			try {
				Long longValue = api.getLong(address);
				Address functionAddress = address.getNewAddress(longValue);
				Function functionAt = api.getFunctionAt(functionAddress);
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
	 * Method to replace the array incorrectly placed at special vftable with longs followed by 
	 * typeinfo label
	 * @param vtableAddress the given special vtable address
	 * @return the address of the typeinfo in the vtable if replace was successful, null otherwise
	 * @throws CancelledException if cancelled
	 */
	private Address createSpecialVtable(Address vtableAddress) throws CancelledException {

		Symbol vtableSymbol = symbolTable.getPrimarySymbol(vtableAddress);

		api.clearListing(vtableAddress);
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

		AddressSetView programAddressSet = program.getMemory().getAllInitializedAddressSet();
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
				api.createData(address, pointer);
				Address referencedAddress = extraUtils.getSingleReferencedAddress(address);

				// if it isn't valid, clear what we just created and increment to offset so
				// the next can be checked
				if (referencedAddress == null || !programAddressSet.contains(referencedAddress)) {
					api.clearListing(address);
					api.createData(address, longDT);
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
			// check for EXTERNAL block and look for specialTypeinfoRef there
			// if fix works, put external block error message and to contact us
			if (hasExternalBlock() && isSpecialVtable(typeinfoAddress)) {
				continue;
			}

			Address specialTypeinfoRef = extraUtils.getSingleReferencedAddress(typeinfoAddress);
			if (specialTypeinfoRef == null) {
				if (DEBUG) {
					Msg.debug(this,
						"No special typeinfo reference found. Cannot process typeinfo struct at " +
							typeinfoAddress.toString());
				}
				continue;
			}

			if (!isSpecialTypeinfo(specialTypeinfoRef)) {
				// check for EXTERNAL block and look for specialTypeinfoRef there
				// if fix works, put external block error message and to contact us
				if (!hasExternalBlock()) {
					continue;
				}
				// use referenced vtable symbol name instead since when in EXTERNAL block
				// since can't get at the typeinfo ref in that block
				if (!isSpecialVtable(specialTypeinfoRef)) {
					continue;
				}
			}

			try {
				// create a "no inheritance" struct here
				if (specialTypeinfoRef.equals(class_type_info) ||
					specialTypeinfoRef.equals(class_type_info_vtable)) {
					api.clearListing(typeinfoAddress,
						typeinfoAddress.add(classTypeInfoStructure.getLength()));
					api.createData(typeinfoAddress, classTypeInfoStructure);
					continue;
				}

				// create a "single inheritance" struct here
				if (specialTypeinfoRef.equals(si_class_type_info) ||
					specialTypeinfoRef.equals(si_class_type_info_vtable)) {
					api.clearListing(typeinfoAddress,
						typeinfoAddress.add(siClassTypeInfoStructure.getLength() - 1));
					api.createData(typeinfoAddress, siClassTypeInfoStructure);
					continue;
				}

				// create a "virtual multip inheritance" struct here
				if (specialTypeinfoRef.equals(vmi_class_type_info) ||
					specialTypeinfoRef.equals(vmi_class_type_info_vtable)) {

					// get num base classes
					int offsetOfNumBases = 2 * defaultPointerSize + 4;
					int numBases = api.getInt(typeinfoAddress.add(offsetOfNumBases));

					// get or create the vmiClassTypeInfoStruct
					Structure vmiClassTypeinfoStructure =
						(Structure) dataTypeManager.getDataType(classDataTypesCategoryPath,
							"VmiClassTypeInfoStructure" + numBases);
					if (vmiClassTypeinfoStructure == null) {
						vmiClassTypeinfoStructure =
							createVmiClassTypeInfoStructure(baseClassTypeInfoStructure, numBases);
					}
					api.clearListing(typeinfoAddress,
						typeinfoAddress.add(vmiClassTypeinfoStructure.getLength() - 1));
					api.createData(typeinfoAddress, vmiClassTypeinfoStructure);

				}
			}
			catch (Exception e) {
				Msg.debug(this, "ERROR: Could not apply structure to " + typeinfoAddress);
			}
		}

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
	 * Method to add parents to the given gcc class
	 * @param recoveredClass the given class
	 * @param typeinfoAddress the address of the typeinfo 
	 * @return list of parents for the given class
	 * @throws CancelledException if cancelled
	 */
	private List<RecoveredClass> addGccClassParents(RecoveredClass recoveredClass,
			Address typeinfoAddress) throws CancelledException {

		Data typeinfoStructure = api.getDataAt(typeinfoAddress);
		List<RecoveredClass> parentClassList = new ArrayList<RecoveredClass>();

		// get inheritance shape info flag
		// zero means just normal multi I think
		// 0x01: class has non-diamond repeated inheritance - this just means multiple parents have
		// the same parent
		// 0x02: class is diamond shaped

		int inheritanceTypeFlagOffset = defaultPointerSize * 2;
		Address inheritanceFlagAddress =
			extraUtils.getAddress(typeinfoAddress, inheritanceTypeFlagOffset);
		if (inheritanceFlagAddress == null) {

			if (DEBUG) {
				Msg.debug(this, "ERROR: Could not access address " + typeinfoAddress.toString() +
					" plus offset " + inheritanceTypeFlagOffset);
			}
			return parentClassList;
		}

		// process the multiple inheritance flag
		try {
			int inheritanceFlagValue = api.getInt(inheritanceFlagAddress);
			if (inheritanceFlagValue == 0) {
				recoveredClass.hasMultipleInheritance();
			}
			// TODO: add flags to class for non-diamond repeated and diamond shape types

			if (DEBUG) {
				Msg.debug(this, inheritanceFlagAddress.toString() + " inheritanceFlag = " +
					inheritanceFlagValue);
			}
		}
		catch (MemoryAccessException e) {
			Msg.debug(this, "couldn't get int at address " + inheritanceFlagAddress.toString());
		}


		int baseClassArrayOffset = defaultPointerSize * 3;
		Data baseClassArrayData = typeinfoStructure.getComponentAt(baseClassArrayOffset);

		if (baseClassArrayData == null || !baseClassArrayData.isArray() ||
			!baseClassArrayData.getBaseDataType().getName().startsWith(
				"BaseClassTypeInfoStructure")) {

			if (DEBUG) {
				Msg.debug(this, "Could not acess baseClassArray at " +
					typeinfoStructure.toString() + baseClassArrayOffset);
			}
			return parentClassList;
		}

		int numParents = baseClassArrayData.getNumComponents();

		for (int i = 0; i < numParents; i++) {
			// get parent from pointer to parent typeinfo	
			Address parentRefAddress =
				extraUtils.getAddress(typeinfoAddress,
					baseClassArrayOffset + (i * 2 * defaultPointerSize));
			if (parentRefAddress == null) {
				Msg.debug(this, "Could not access address " + typeinfoAddress.toString() +
					" plus offset " + baseClassArrayOffset);
				continue;
			}

			RecoveredClass parentClass = getParentClassFromParentTypeInfoRef(parentRefAddress);

			if (parentClass != null) {
				if (DEBUG) {
					Msg.debug(this,
						recoveredClass.getName() + " adding vmi parent " + parentClass.getName());
				}

				updateClassWithParent(parentClass, recoveredClass);
				parentClassList.add(parentClass);
			}

			// get long value flag
			Address flagAddress = extraUtils.getAddress(typeinfoAddress,
				baseClassArrayOffset + (i * 2 * defaultPointerSize + defaultPointerSize));
			if (flagAddress == null) {
				Msg.debug(this, "Could not access address " + typeinfoAddress.toString() +
					" plus offset " + baseClassArrayOffset);
				continue;
			}

			// from doc:
			//All but the lower 8 bits of __offset_flags are a signed offset. For a 
			//non-virtual base, this is the offset in the object of the base subobject. 
			//For a virtual base, this is the offset in the virtual table of the 
			//virtual base offset for the virtual base referenced (negative).

			//The low-order byte of __offset_flags contains flags, as given by the masks 
			//from the enumeration __offset_flags_masks:

			//0x1: Base class is virtual
			//0x2: Base class is public
			try {
				long flags = api.getLong(flagAddress);

				// TODO: process flag
				// split out the offset from the virt/public flag
				// offset >> 8 & 0xffffff

			}
			catch (MemoryAccessException e) {
				Msg.debug(this, "couldn't get long at address " + flagAddress.toString());
			}
		}

		if (DEBUG) {
			Msg.debug(this, recoveredClass.getName() + " has " + numParents + " parents");
		}

		return parentClassList;

	}

	/**
	 * Get the parent class given the typeinfo address of an Si class
	 * @param typeinfoAddress the given Si class's typeinfo Address
	 * @return the parent class
	 */
	private RecoveredClass getSiClassParent(Address typeinfoAddress) {

		int offset = defaultPointerSize * 2;

		Address parentTypeinfoRef = extraUtils.getAddress(typeinfoAddress, offset);
		if (parentTypeinfoRef == null) {
			if (DEBUG) {
				Msg.debug(this, "ERROR: Could not access address " + typeinfoAddress.toString() +
					" plus offset " + offset);
			}
			return null;
		}

		RecoveredClass parentClass = getParentClassFromParentTypeInfoRef(parentTypeinfoRef);
		return parentClass;

	}

	/**
	 * Method to return the parent class given a reference to the parent class's typeinfo struct
	 * @param parentTypeinfoRef the given parent typeinfo reference
	 * @return the associated parent class
	 */
	private RecoveredClass getParentClassFromParentTypeInfoRef(Address parentTypeinfoRef) {
		Address parentAddress = extraUtils.getSingleReferencedAddress(parentTypeinfoRef);
		if (parentAddress == null) {
			return null;
		}
		Symbol parentSymbol = symbolTable.getPrimarySymbol(parentAddress);
		if (parentSymbol == null) {
			return null;
		}
		Namespace parentNamespace = parentSymbol.getParentNamespace();
		if (parentNamespace == null) {
			return null;
		}
		RecoveredClass parentClass = getClass(parentNamespace);

		if (parentClass == null) {
			return null;
		}
		return parentClass;
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
			Msg.debug(this, "__class_type_info vtable not found --> no classes without parents");
		}
		else {
			class_type_info = createSpecialVtable(class_type_info_vtable);
			if (class_type_info == null) {
				Msg.debug(this,
					"__class_type_info typeinfo not found -- cannot continue gcc rtti processing");
				return false;
			}
		}

		si_class_type_info = null;
		si_class_type_info_vtable = findSpecialVtable("__cxxabiv1", "__si_class_type_info");
		if (si_class_type_info_vtable == null) {
			Msg.debug(this, "__si_class_type_info vtable not found --> no single parent classes");
		}
		else {
			si_class_type_info = createSpecialVtable(si_class_type_info_vtable);
			if (si_class_type_info == null) {
				Msg.debug(this,
					"__si_class_type_info typeinfo not found -- cannot continue gcc rtti processing");
				return false;
			}
		}

		vmi_class_type_info_vtable = findSpecialVtable("__cxxabiv1", "__vmi_class_type_info");
		vmi_class_type_info = null;
		if (vmi_class_type_info_vtable == null) {
			Msg.debug(this, "__vmi_class_type_info vtable not found --> no multi-parent classes");
		}
		else {
			vmi_class_type_info = createSpecialVtable(vmi_class_type_info_vtable);
			if (vmi_class_type_info == null) {
				Msg.debug(this,
					"__vmi_class_type_info typeinfo not found -- cannot continue gcc rtti processing");
				return false;
			}
		}

		if (class_type_info_vtable == null && si_class_type_info_vtable == null &&
			vmi_class_type_info_vtable == null) {
			Msg.debug(this,
				"Since there are no class typeinfo tables this program does not appear to have RTTI.");
			return false;
		}
		return true;
	}

	// TODO: don't delete - its call is commented out waiting for more work above
	private List<RecoveredClass> addMissingClasses(List<RecoveredClass> subset,
			List<RecoveredClass> newList, List<RecoveredClass> classList)
			throws CancelledException {

		// find classes common to the possible subset and the larger classList
		List<RecoveredClass> commonClasses =
			classList.stream().distinct().filter(subset::contains).collect(Collectors.toList());

		// remove any common classes (i.e. classes already on the classList) from the subset
		if (!commonClasses.isEmpty()) {
			subset.removeAll(commonClasses);
		}

		// if subset is now empty then there are no new classes to add so just return the newList
		if (subset.isEmpty()) {
			return newList;
		}

		// if subset has any new classes on it, add any that are not already on the newList to newList
		Iterator<RecoveredClass> newClassesIterator = subset.iterator();
		while (newClassesIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass newClass = newClassesIterator.next();
			if (!newList.contains(newClass)) {
				newList.add(newClass);
			}
		}

		return newList;
	}

//TODO: repurpose to find first vftable in vtable??
	private List<Address> findVftablesInVtableUsingTypeinfoRefs(Address vtableAddress)
			throws CancelledException {

		List<Address> vftableAddresses = new ArrayList<Address>();

		Address address = vtableAddress;

		MemoryBlock currentMemoryBlock = program.getMemory().getBlock(vtableAddress);

		while (address != null && currentMemoryBlock.contains(address)) {

			Address nextTypeinfoRef = findNextTypeinfoRef(address);
			if (nextTypeinfoRef == null) {
				return vftableAddresses;
			}

			address = extraUtils.getAddress(nextTypeinfoRef, defaultPointerSize);
			if (extraUtils.isFunctionPointer(address, true)) {
				vftableAddresses.add(address);
			}

		}
		return vftableAddresses;

	}

	/**
	 * Method to find the next reference to a typeinfo symbol after the given address
	 * @param startAddress the address to start looking from
	 * @return the address of the next typeinfo address after the given address
	 */
	private Address findNextTypeinfoRef(Address startAddress) {

		int offset = 0;

		Address address = extraUtils.getAddress(startAddress, offset);

		MemoryBlock currentMemoryBlock = program.getMemory().getBlock(startAddress);

		while (address != null && currentMemoryBlock.contains(address)) {

			Symbol symbol = symbolTable.getPrimarySymbol(address);
			// if the symbol we find is not a default symbol 
			// because we have reached the end of the item we are searching
			if (!address.equals(startAddress) && symbol != null &&
				symbol.getSource() != SourceType.DEFAULT) {
				return null;
			}

			Address possibleTypeinfo = extraUtils.getPointer(address);
			if (possibleTypeinfo == null) {
				offset += defaultPointerSize;
				address = extraUtils.getAddress(startAddress, offset);
				continue;
			}

			Symbol possibleTypeinfoSymbol = symbolTable.getPrimarySymbol(possibleTypeinfo);
			if (possibleTypeinfoSymbol != null &&
				possibleTypeinfoSymbol.getName().equals("typeinfo")) {
				return address;
			}
			offset += defaultPointerSize;
			address = extraUtils.getAddress(startAddress, offset);

		}

		return null;
	}

	/**
	 * Method to process the primary vtable for each "vtable" label
	 * @return the vftable Address in the vtable
	 * @throws Exception if Data cannot be created
	 */
	private List<Symbol> findVftablesFromVtables() throws Exception {

		List<Symbol> vftableSymbols = new ArrayList<Symbol>();

		// find all vtable symbols
		List<Symbol> listOfVtableSymbols = extraUtils.getListOfSymbolsInAddressSet(
			program.getAddressFactory().getAddressSet(), VTABLE_LABEL, false);

		Iterator<Symbol> vtableIterator = listOfVtableSymbols.iterator();
		while (vtableIterator.hasNext()) {

			monitor.checkCanceled();

			Symbol vtableSymbol = vtableIterator.next();
			Namespace vtableNamespace = vtableSymbol.getParentNamespace();
			Address vtableAddress = vtableSymbol.getAddress();

			// skip the special tables			
			if (vtableAddress.equals(class_type_info_vtable) ||
				vtableAddress.equals(si_class_type_info_vtable) ||
				vtableAddress.equals(vmi_class_type_info_vtable)) {
				continue;
			}

			// find the classes that have vtable but no typeinfo structure
			// we know this because all classes that have typeinfo were added to the following map
			// previously
			RecoveredClass classWithNoTypeinfoStruct = getClass(vtableNamespace);
			if (classWithNoTypeinfoStruct == null) {
				addNoVftableClass(vtableNamespace);
				continue;
			}

			Data vtableData = api.getDataAt(vtableAddress);
			if (vtableData == null) {
				continue;
			}

			// find the special type info ref
			Address typeinfoAddress = findNextTypeinfoRef(vtableAddress);
			if (typeinfoAddress == null) {
				if (DEBUG) {
					Msg.debug(this, vtableAddress.toString() + " " + vtableNamespace.getName() +
						" vtable has no typeinfo ref");
				}
				continue;
			}

			Address vftableAddress = extraUtils.getAddress(typeinfoAddress, defaultPointerSize);
			// no valid address here so continue
			if (vftableAddress == null) {
				addNoVftableClass(vtableNamespace);
				// if so should also add to no vftable class
				continue;
			}
			Symbol vftableSymbol = symbolTable.getPrimarySymbol(vftableAddress);
			if (vftableSymbol == null) {
				continue;
			}
			if (vftableSymbol.getName().equals(VFTABLE_LABEL)) {
				vftableSymbols.add(vftableSymbol);
			}

		}
		return vftableSymbols;
	}

	/**
	 * Method to check if given typeinfo is one of the three special ones
	 * @param address the given typeinfo address
	 * @return true if it is a special one, false otherwise
	 */
	private boolean isSpecialTypeinfo(Address address) {
		if (address.equals(class_type_info) || address.equals(si_class_type_info) ||
			address.equals(vmi_class_type_info)) {
			return true;
		}
		return false;
	}

	private boolean isSpecialVtable(Address address) {
		if (address.equals(class_type_info_vtable) ||
			address.equals(si_class_type_info_vtable) ||
			address.equals(vmi_class_type_info_vtable)) {
			return true;
		}
		return false;
	}

	private List<RecoveredClass> createClassesFromTypeinfoSymbols(List<Symbol> typeinfoSymbols)
			throws CancelledException {

		List<RecoveredClass> recoveredClasses = new ArrayList<RecoveredClass>();

		Iterator<Symbol> typeinfoIterator = typeinfoSymbols.iterator();
		while (typeinfoIterator.hasNext()) {

			monitor.checkCanceled();

			Symbol typeinfoSymbol = typeinfoIterator.next();
			Address typeinfoAddress = typeinfoSymbol.getAddress();

			// skip the typeinfo symbols from the three special typeinfos 
			if (isSpecialTypeinfo(typeinfoAddress)) {
				continue;
			}
			// check for EXTERNAL block and look for specialTypeinfoRef there
			// if fix works, put external block error message and to contact us
			if (hasExternalBlock() && isSpecialVtable(typeinfoAddress)) {
				continue;
			}

			// TODO: make sure it is a valid typeinfo


			Namespace classNamespace = typeinfoSymbol.getParentNamespace();

			RecoveredClass recoveredClass = getClass(classNamespace);


			// we don't know yet if this class has vftable so just add without for now
			if (recoveredClass == null) {
				recoveredClass = addNoVftableClass(classNamespace);
				recoveredClasses.add(recoveredClass);

				classToTypeinfoMap.put(recoveredClass, typeinfoAddress);
			}

			if (recoveredClass != null && !classToTypeinfoMap.containsKey(recoveredClass)) {
				classToTypeinfoMap.put(recoveredClass, typeinfoAddress);
			}

			if (!recoveredClasses.contains(recoveredClass)) {
				recoveredClasses.add(recoveredClass);
			}

			Address specialTypeinfoRef = extraUtils.getSingleReferencedAddress(typeinfoAddress);
			if (specialTypeinfoRef == null) {
				if (DEBUG) {
					Msg.debug(this,
						"No special typeinfo reference found. Cannot process typeinfo struct at " +
							typeinfoAddress.toString());
				}
				continue;
			}

			if (!isSpecialTypeinfo(specialTypeinfoRef)) {
				// check for EXTERNAL block and look for specialTypeinfoRef there
				// if fix works, put external block error message and to contact us
				if (!hasExternalBlock()) {
					continue;
				}
				// use referenced vtable symbol name instead since when in EXTERNAL block
				// since can't get at the typeinfo ref in that block
				if (!isSpecialVtable(specialTypeinfoRef)) {
					continue;
				}

			}


			// per docs those on this list 
			// have no bases (ie parents), and is also a base type for the other two class type 
			// representations ie (si and vmi)
			// ??? it isn't clear whether these are always public or not
			if (specialTypeinfoRef.equals(class_type_info) ||
				specialTypeinfoRef.equals(class_type_info_vtable)) {
				//	//TODO: make this a method - addGccNoInhClass
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setHasParentClass(false);
				recoveredClass.setInheritsVirtualAncestor(false);
				// TODO: add public ???
				continue;
			}

			// per docs those on this list are
			// classes containing only a single, public, non-virtual base at offset zero
			// update: it isn't clear if never inherit virtual - may have found example
			if (specialTypeinfoRef.equals(si_class_type_info) ||
				specialTypeinfoRef.equals(si_class_type_info_vtable)) {

				// TODO: make this a method and pull the part out of add parents that handles the
				// single parent one
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setInheritsVirtualAncestor(false);
				recoveredClass.setIsPublicClass(true);

				continue;
			}

			if (specialTypeinfoRef.equals(vmi_class_type_info) ||
				specialTypeinfoRef.equals(vmi_class_type_info_vtable)) {

				recoveredClass.setHasMultipleInheritance(true);
			}
		}
		return recoveredClasses;
	}

	/**
	 * Use information from RTTI Base class Arrays to create class hierarchy lists and maps
	 * @param recoveredClasses list of classes to process
	 * @throws CancelledException if cancelled
	 */
	private void createClassHierarchyListAndMapForGcc(List<RecoveredClass> recoveredClasses)
			throws CancelledException, Exception {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();

			// no parent case
			if (nonInheritedGccClasses.contains(recoveredClass)) {
				classHierarchyList = getGccNoClassHierarchy(recoveredClass);
				recoveredClass.setClassHierarchy(classHierarchyList);
				continue;
			}

			// case where there is all single inheritance in a class ancestry chain
			if (singleInheritedGccClasses.contains(recoveredClass)) {
				classHierarchyList = getGccSingleClassHierarchy(recoveredClass);
				recoveredClass.setClassHierarchy(classHierarchyList);
				continue;
			}

		}

		recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();

			// once all the non and single inheritance ones are created, create the multi ones
			// case where there is multi-inheritance somewhere in the chain
			if (multiInheritedGccClasses.contains(recoveredClass)) {
				classHierarchyList = getGccMultiClassHierarchy(recoveredClass);
				recoveredClass.setClassHierarchy(classHierarchyList);
			}
		}

		// create parent class hierarchy maps
		recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<RecoveredClass> parentList = recoveredClass.getParentList();
			Iterator<RecoveredClass> parentIterator = parentList.iterator();
			while (parentIterator.hasNext()) {
				monitor.checkCanceled();
				RecoveredClass parentClass = parentIterator.next();
				recoveredClass.addClassHierarchyMapping(parentClass,
					parentClass.getClassHierarchy());
			}
		}

		// TODO: create base type maps to add if virtual parent or not

	}

	/**
	 * Create the class hierarchy list for a class with no inheritance
	 * @param recoveredClass the given class
	 * @return the class hierarchy list for the given class with no inheritance
	 */
	List<RecoveredClass> getGccNoClassHierarchy(RecoveredClass recoveredClass) {
		List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();
		classHierarchyList.add(recoveredClass);
		return classHierarchyList;
	}

	/**
	 * Create the class hierarchy for a class with only single inheritance parents
	 * @param recoveredClass the given class
	 * @return the class hierarchy for the given class with only single inheritance parents
	 * @throws CancelledException if cancelled
	 */
	List<RecoveredClass> getGccSingleClassHierarchy(RecoveredClass recoveredClass)
			throws CancelledException {

		List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();

		RecoveredClass currentClass = recoveredClass;
		classHierarchyList.add(currentClass);

		while (currentClass.hasParentClass()) {
			monitor.checkCanceled();
			currentClass = currentClass.getParentList().get(0);
			classHierarchyList.add(currentClass);
		}
		return classHierarchyList;
	}

	/**
	 * Create the class hierarchy list for a class with multiple inheritance
	 * @param recoveredClass the given class
	 * @return the class hierarchy list for the given class with multiple inheritance
	 * @throws CancelledException if cancelled
	 */
	List<RecoveredClass> getGccMultiClassHierarchy(RecoveredClass recoveredClass)
			throws CancelledException {

		List<RecoveredClass> classHierarchyList = new ArrayList<RecoveredClass>();

		classHierarchyList.add(recoveredClass);

		List<RecoveredClass> parentList = recoveredClass.getParentList();
		Iterator<RecoveredClass> parentIterator = parentList.iterator();
		while (parentIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass parentClass = parentIterator.next();
			if (nonInheritedGccClasses.contains(parentClass)) {
				classHierarchyList.addAll(parentClass.getClassHierarchy());
				continue;
			}
			if (singleInheritedGccClasses.contains(parentClass)) {
				classHierarchyList.addAll(parentClass.getClassHierarchy());
				continue;
			}
			if (multiInheritedGccClasses.contains(parentClass)) {
				classHierarchyList.addAll(getGccMultiClassHierarchy(parentClass));
			}
		}
		return classHierarchyList;

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
				api.clearListing(address);
				api.createData(address, longDT);
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

	private int getNumFunctionPointers(Address topAddress, boolean allowNullFunctionPtrs,
			boolean allowDefaultRefsInMiddle) throws CancelledException {

		int numFunctionPointers = 0;
		Address address = topAddress;
		MemoryBlock currentBlock = program.getMemory().getBlock(topAddress);

		boolean stillInCurrentTable = true;
		while (address != null && currentBlock.contains(address) && stillInCurrentTable &&
			(isPossibleFunctionPointer(address) ||
				(allowNullFunctionPtrs && isPossibleNullPointer(address)))) {

			numFunctionPointers++;
			address = address.add(defaultPointerSize);
			Symbol symbol = api.getSymbolAt(address);
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
		if (!extraUtils.hasNumZeros(address, defaultPointerSize)) {
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

		Address possibleFunctionPointer = extraUtils.getPointer(address);
		if (possibleFunctionPointer == null) {
			return false;
		}

		Function function = api.getFunctionAt(possibleFunctionPointer);
		if (function != null) {
			return true;
		}
		return false;
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
			monitor.checkCanceled();

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
			monitor.checkCanceled();

			// put in stop gap measure in case some classes never get all
			// parents processed for some reason
			if (numLoops == 100) {
				return;
			}
			numLoops++;

			recoveredClassIterator = recoveredClasses.iterator();
			while (recoveredClassIterator.hasNext()) {

				RecoveredClass recoveredClass = recoveredClassIterator.next();

				monitor.checkCanceled();
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

		// can't handle gcc multi and/or virtual class data types yet
		if (multiInheritedGccClasses.contains(recoveredClass) ||
			recoveredClass.inheritsVirtualAncestor()) {
			return;
		}

		// shouldn't happen if we get to this point since it should be all single or no inherited classes
		// but check anyway
		if (recoveredClass.getVftableAddresses().size() > 1) {
			return;
		}

		if (!recoveredClass.hasVftable()) {
			createSimpleClassStructure(recoveredClass, null);
			// return in this case because if there is no vftable for a class the script cannot
			// identify any member functions so there is no need to process the rest of this method
			return;
		}

		// create pointers to empty vftable structs so they can be added to the class data type
		// then filled in later
		Map<Address, DataType> vfPointerDataTypes = createEmptyVfTableStructs(recoveredClass);

		// create current class structure and add pointer to vftable, all parent member data strutures, and class member data structure
		Structure classStruct = null;

		classStruct = createSimpleClassStructure(recoveredClass, vfPointerDataTypes);

		// TODO: check for DWARF -- if none add c/d/etc to class
//		if (!isDWARFLoaded) {
//
//			// Now that we have a class data type
//			// name constructor and destructor functions and put into the class namespace
//			addConstructorsToClassNamespace(recoveredClass, classStruct);
//			addDestructorsToClassNamespace(recoveredClass);
//			addNonThisDestructorsToClassNamespace(recoveredClass);
//			addVbaseDestructorsToClassNamespace(recoveredClass);
//			addVbtableToClassNamespace(recoveredClass);
//
//			// add secondary label on functions with inlined constructors or destructors
//			createInlinedConstructorComments(recoveredClass);
//			createInlinedDestructorComments(recoveredClass);
//			createIndeterminateInlineComments(recoveredClass);
//
//			// add label on constructor destructor functions that could not be determined which were which
//			createIndeterminateLabels(recoveredClass);
//		}

		// This is done after the class structure is created and added to the dtmanager
		// because if done before the class structures are created 
		// then empty classes will get auto-created in the wrong place
		// when the vfunctions are put in the class

		fillInAndApplyVftableStructAndNameVfunctions(recoveredClass, vfPointerDataTypes);

	}

	private Structure createSimpleClassStructure(RecoveredClass recoveredClass,
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
		
		List<RecoveredClass> parentList = recoveredClass.getParentList();
		// shouldn't happen but check anyway
		if (parentList.size() > 1) {
			return classStructureDataType;
		}

		// if no inheritance - add pointer to class vftable structure
		if (nonInheritedGccClasses.contains(recoveredClass) && vfPointerDataTypes != null) {

			// the size was checked before calling this method so we know there is one and only
			// one for this simple case
			Address vftableAddress = recoveredClass.getVftableAddresses().get(0);
			DataType classVftablePointer = vfPointerDataTypes.get(vftableAddress);

			// simple case the offset for vftablePtr is 0
			if (structUtils.canAdd(classStructureDataType, 0, classVftablePointer.getLength(),
				monitor)) {
				classStructureDataType = structUtils.addDataTypeToStructure(classStructureDataType,
					0, classVftablePointer, CLASS_VTABLE_PTR_FIELD_EXT, monitor);

			}
		}
		// if single inheritance put parent and data
		else if (singleInheritedGccClasses.contains(recoveredClass)) {

			RecoveredClass baseClass = parentList.get(0);
			Structure baseClassStructure = getClassStructureFromDataTypeManager(baseClass);

			// simple case - base class at offset 0
			if (structUtils.canAdd(classStructureDataType, 0, baseClassStructure.getLength(),
				monitor)) {
				classStructureDataType = structUtils.addDataTypeToStructure(classStructureDataType,
					0, baseClassStructure, baseClassStructure.getName(), monitor);
			}
		}
		
		// figure out class data, if any, create it and add to class structure
		int dataOffset = getDataOffset(recoveredClass, classStructureDataType);
		int dataLen = UNKNOWN;
		if (dataOffset != NONE) {
			dataLen = structUtils.getNumberOfUndefinedsStartingAtOffset(classStructureDataType,
				dataOffset, monitor);
		}

		if (dataLen != UNKNOWN && dataLen > 0) {

			Structure recoveredClassDataStruct = createClassMemberDataStructure(recoveredClass,
				classStructureDataType, dataLen, dataOffset);

			if (recoveredClassDataStruct != null) {
				classStructureDataType = structUtils.addDataTypeToStructure(classStructureDataType,
					dataOffset, recoveredClassDataStruct, "data", monitor);
			}

		}

		if (classStructureDataType.getNumComponents() == classStructureDataType.getNumDefinedComponents()) {
			classStructureDataType.setPackingEnabled(true);
		}

		classStructureDataType.setDescription(createParentStringBuffer(recoveredClass).toString());

		classStructureDataType = (Structure) dataTypeManager.addDataType(classStructureDataType,
			DataTypeConflictHandler.DEFAULT_HANDLER);

		return classStructureDataType;
	}

	private boolean hasExternalBlock() {
		MemoryBlock externalBlock = program.getMemory().getBlock("EXTERNAL");
		if (externalBlock == null) {
			return false;
		}
		return true;
	}

}

