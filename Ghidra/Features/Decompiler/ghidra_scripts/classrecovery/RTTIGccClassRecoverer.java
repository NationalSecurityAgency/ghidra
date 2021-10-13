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

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.demangler.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.Msg;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class RTTIGccClassRecoverer extends RTTIClassRecoverer {

	private static final String VMI_CLASS_TYPE_INFO_STRUCTURE = "VmiClassTypeInfoStructure";
	private static final String BASE_CLASS_TYPE_INFO_STRUCTURE = "BaseClassTypeInfoStructure";
	private static final String SI_CLASS_TYPE_INFO_STRUCTURE = "SiClassTypeInfoStructure";
	private static final String CLASS_TYPE_INFO_STRUCTURE = "ClassTypeInfoStructure";
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
	List<RecoveredClass> multiAndOrVirtuallyInheritedGccClasses = new ArrayList<RecoveredClass>();

	List<RecoveredClass> recoveredClasses = new ArrayList<RecoveredClass>();

	private Map<RecoveredClass, Map<Integer, RecoveredClass>> classToParentOrderMap =
		new HashMap<RecoveredClass, Map<Integer, RecoveredClass>>();

	private Map<RecoveredClass, Map<RecoveredClass, Long>> classToParentOffsetMap =
		new HashMap<RecoveredClass, Map<RecoveredClass, Long>>();

	boolean isDwarfLoaded;

	public RTTIGccClassRecoverer(Program program, ProgramLocation location, PluginTool tool,
			FlatProgramAPI api, boolean createBookmarks, boolean useShortTemplates,
			boolean nameVfunctions, boolean isDwarfLoaded, TaskMonitor monitor) {

		super(program, location, tool, api, createBookmarks, useShortTemplates, nameVfunctions,
			isDwarfLoaded,
			monitor);
		this.isDwarfLoaded = isDwarfLoaded;
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

			processGccRTTI();
			if (recoveredClasses == null) {
				Msg.debug(this, "Could not recover gcc rtti classes");
				return null;
			}

			createCalledFunctionMap(recoveredClasses);

			createClassHierarchyListAndMapForGcc();

			if (isDwarfLoaded) {
				retrieveExistingClassStructures(recoveredClasses);
				assignConstructorsAndDestructorsUsingExistingName(recoveredClasses);
			}
			else {
				processConstructorAndDestructors();
			}

			createVftableOrderMap(recoveredClasses);

			figureOutClassDataMembers(recoveredClasses);

			createAndApplyClassStructures();

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

		Address found = program.getMemory()
				.findBytes(commentBlock.getStart(),
					commentBlock.getEnd(), gccBytes, maskBytes, true, monitor);
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

	private void processGccRTTI() throws CancelledException, Exception {

		// create the appropriate type of type info struct at the various typeinfo symbol locations
		createTypeinfoStructs();

		processVtables();

		// process vtables and create classes for the vtables that have no typeinfo
		List<Symbol> vftableSymbols = findVftablesFromVtables();

		recoveredClasses = recoverClassesFromVftables(vftableSymbols, true, true);

		// find all typeinfo symbols and get their class namespace and create RecoveredClass object
		List<Symbol> typeinfoSymbols = extraUtils.getListOfSymbolsInAddressSet(
			program.getAddressFactory().getAddressSet(), "typeinfo", true);

		// create class objects for each typeinfo struct and make a class to typeinfo mapping for each		
		createClassesFromTypeinfoSymbols(typeinfoSymbols);

		updateClassesWithParentsAndFlags(typeinfoSymbols);

		// update the vftable offset map
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {

			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

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
		return;

	}

	private void updateClassesWithParentsAndFlags(List<Symbol> typeinfoSymbols)
			throws Exception {

		// add properties and parents to each class 
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

			if (recoveredClass == null) {
				// this shoudln't be null at this point
				if (DEBUG) {
					Msg.debug(this,
						"***Shouldn't be a null class here: " + classNamespace.getName());
				}
				recoveredClass = createNewClass(classNamespace, false);
				recoveredClasses.add(recoveredClass);
			}
			else {
				if (!recoveredClasses.contains(recoveredClass)) {
					recoveredClasses.add(recoveredClass);
				}
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
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setHasMultipleInheritance(false);
				recoveredClass.setHasMultipleVirtualInheritance(false);
				recoveredClass.setInheritsVirtualAncestor(false);

				// no parents so just add empty order and parent maps to the class maps
				Map<Integer, RecoveredClass> orderToParentMap =
					new HashMap<Integer, RecoveredClass>();

				classToParentOrderMap.put(recoveredClass, orderToParentMap);

				Map<RecoveredClass, Long> parentToOffsetMap = new HashMap<RecoveredClass, Long>();

				classToParentOffsetMap.put(recoveredClass, parentToOffsetMap);
				continue;
			}

			// per docs those on this list are
			// classes containing only a single, public, non-virtual base at offset zero
			if (specialTypeinfoRef.equals(si_class_type_info) ||
				specialTypeinfoRef.equals(si_class_type_info_vtable)) {

				RecoveredClass parentClass = getSiClassParent(typeinfoAddress);
				if (parentClass == null) {
					throw new Exception("Could not get si parent from typeinfoAddress " +
						typeinfoAddress.toString());
				}

				if (DEBUG) {
					Msg.debug(this,
						recoveredClass.getName() + " adding si parent " + parentClass.getName());
				}

				updateClassWithParent(parentClass, recoveredClass);
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setHasMultipleInheritance(false);
				recoveredClass.setHasMultipleVirtualInheritance(false);
				parentClass.setIsPublicClass(true);
				recoveredClass.addParentToBaseTypeMapping(parentClass, false);

				// add order to parent and parent offset
				Map<Integer, RecoveredClass> orderToParentMap =
					new HashMap<Integer, RecoveredClass>();
				orderToParentMap.put(0, parentClass);
				classToParentOrderMap.put(recoveredClass, orderToParentMap);

				Map<RecoveredClass, Long> parentToOffsetMap = new HashMap<RecoveredClass, Long>();
				parentToOffsetMap.put(parentClass, 0L);

				classToParentOffsetMap.put(recoveredClass, parentToOffsetMap);

				if (!recoveredClasses.contains(parentClass)) {
					recoveredClasses.add(parentClass);
				}
				continue;
			}

			if (specialTypeinfoRef.equals(vmi_class_type_info) ||
				specialTypeinfoRef.equals(vmi_class_type_info_vtable)) {

				List<RecoveredClass> parents =
					addGccClassParentsFromVmiStruct(recoveredClass, typeinfoAddress);

				if (parents.isEmpty()) {
					continue;
				}

				for (RecoveredClass parent : parents) {
					monitor.checkCanceled();
					if (!recoveredClasses.contains(parent)) {
						recoveredClasses.add(parent);
					}
				}
			}
		}

		return;

	}

	/**
	 * Method to process the primary vtable for each "vtable" label
	 * @throws Exception if Data cannot be created
	 */
	private void processVtables() throws Exception {

		List<Symbol> listOfVtableSymbols = new ArrayList<Symbol>();

		// if dwarf loaded then get vtables using symbols
		if (!isDwarfLoaded) {
			listOfVtableSymbols = findVtablesUsingTypeinfoRefs();
		}
		else {
			listOfVtableSymbols = extraUtils.getListOfSymbolsInAddressSet(
				program.getAddressFactory().getAddressSet(), VTABLE_LABEL, false);
		}

		List<Symbol> copyListOfVtableSymbols = new ArrayList<Symbol>(listOfVtableSymbols);

		Iterator<Symbol> vtableIterator = listOfVtableSymbols.iterator();

		while (vtableIterator.hasNext()) {

			monitor.checkCanceled();

			Symbol vtableSymbol = vtableIterator.next();
			Namespace vtableNamespace = vtableSymbol.getParentNamespace();
			Address vtableAddress = vtableSymbol.getAddress();

			processVtable(vtableAddress, vtableNamespace, true, copyListOfVtableSymbols);
		}
		return;
	}

	private List<Symbol> findVtablesUsingTypeinfoRefs() throws Exception {

		List<Symbol> vtableSymbols = new ArrayList<Symbol>();

		List<Address> typeinfoAddresses = getTypeinfoAddressesUsingSymbols();
		if (typeinfoAddresses.isEmpty()) {
			return vtableSymbols;
		}

		// find refs to typeinfo's that are not in functions, instructions, or typeinfo structs
		// we only want ones that may be in vtables
		List<Address> typeinfoReferencesNotInTypeinfoStructs =
			findTypeinfoReferencesNotInTypeinfoStructs(typeinfoAddresses);

		if (typeinfoReferencesNotInTypeinfoStructs.isEmpty()) {
			return vtableSymbols;
		}

		for (Address typeinfoRef : typeinfoReferencesNotInTypeinfoStructs) {
			monitor.checkCanceled();

			Address typeinfoAddress = extraUtils.getPointer(typeinfoRef);

			if (typeinfoAddress == null) {
				continue;
			}

			Structure typeinfoStructure = getTypeinfoStructure(typeinfoAddress);

			if (typeinfoStructure == null) {
				continue;
			}

			if (!isValidClassInfoStructure(typeinfoStructure)) {
				continue;
			}

			// get top of vtable
			Address vtableAddress = getPrimaryVtableAddress(typeinfoRef);
			if (vtableAddress == null) {
				continue;
			}

			// create symbol
			Symbol typeinfoSymbol = api.getSymbolAt(typeinfoAddress);
			if (typeinfoSymbol == null) {
				continue;
			}
			if (!typeinfoSymbol.getName().equals("typeinfo")) {
				continue;
			}

			// check for construction table and make new namespace if so
			Namespace classNamespace = typeinfoSymbol.getParentNamespace();

			if (classNamespace.equals(globalNamespace)) {
				throw new Exception("typeinfo has global namespace " + typeinfoAddress);
			}

			try {
				Symbol vtableSymbol = symbolTable.createLabel(vtableAddress, VTABLE_LABEL,
					classNamespace, SourceType.ANALYSIS);
				vtableSymbols.add(vtableSymbol);
			}
			catch (InvalidInputException e) {
				continue;
			}

			api.setPlateComment(vtableAddress, "vtable for " + classNamespace.getName(true));
		}
		return vtableSymbols;

	}

	private Address getPrimaryVtableAddress(Address typeinfoRef) throws CancelledException {

		// check the long just before and if not a zero then continue since the rest
		// are internal vtables and will get processed when the main one does
		Address longBeforeTypeinfoRef = getAddress(typeinfoRef, 0 - defaultPointerSize);

		// if this address doesn't exist then continue since not a valid vtable
		if (longBeforeTypeinfoRef == null) {
			return null;
		}

		// check for appropriately sized long that is value 0 to make sure the 
		// vtable the typeinfo ref is in is the main one and skip otherwise since non-zero
		// ones are internal vtables that will get processed with the main one
		if (!extraUtils.hasNumZeros(longBeforeTypeinfoRef, defaultPointerSize)) {
			return null;
		}

		Address vtableAddress = longBeforeTypeinfoRef;
		MemoryBlock currentBlock = program.getMemory().getBlock(typeinfoRef);

		// stop if top of mem block
		// stop if bytes are an address
		// stop if referenced
		// are they ever zero - not that i have seen so far in the last vftable 
		// if pointer to something or valid address
		// or is in a structure
		Address nextAddress = getAddress(vtableAddress, 0 - defaultPointerSize);
		while (nextAddress != null &&
			program.getMemory().getBlock(nextAddress).equals(currentBlock) &&
			getPointerToDefinedMemory(nextAddress) == null) {
			vtableAddress = nextAddress;
			nextAddress = getAddress(vtableAddress, 0 - defaultPointerSize);
		}

		return vtableAddress;

	}

	private Address getPointerToDefinedMemory(Address address) {

		Address pointer = extraUtils.getPointer(address);
		if (pointer == null) {
			return null;
		}

		if (program.getMemory().getAllInitializedAddressSet().contains(pointer)) {
			return pointer;
		}

		return null;

	}

	private boolean isValidClassInfoStructure(Structure typeinfoStructure) {
		String typeinfoStructureName = typeinfoStructure.getName();

		if (typeinfoStructureName.equals(CLASS_TYPE_INFO_STRUCTURE)) {
			return true;
		}
		if (typeinfoStructureName.equals(SI_CLASS_TYPE_INFO_STRUCTURE)) {
			return true;
		}
		if (typeinfoStructureName.contains(VMI_CLASS_TYPE_INFO_STRUCTURE)) {
			return true;
		}
		return false;
	}

	private Namespace createConstructionNamespace(Symbol vtableSymbol, Symbol vttSymbol)
			throws Exception {

		Namespace vtableNamespace = vtableSymbol.getParentNamespace();

		Namespace inNamespace = vttSymbol.getParentNamespace();
		String name = vtableNamespace.getName() + "-in-" + inNamespace.getName(true);

		List<Namespace> namespacesByPath =
			NamespaceUtils.getNamespaceByPath(program, vtableNamespace, name);

		if (namespacesByPath.isEmpty()) {

			try {
				Namespace newNamespace =
					NamespaceUtils.createNamespaceHierarchy(name, vtableNamespace,
						program, SourceType.ANALYSIS);
				return newNamespace;
			}
			catch (InvalidInputException e) {
				e.printStackTrace();
				return null;
			}
		}
		if (namespacesByPath.size() == 1) {
			return namespacesByPath.get(0);
		}

		throw new Exception(
			"More than one namespace " + vtableNamespace.getName(true) + " " + name);
	}

	private Structure getTypeinfoStructure(Address typeinfoAddress) {

		Data data = api.getDataAt(typeinfoAddress);

		if (!isTypeinfoStruct(data)) {
			return null;
		}

		return (Structure) data.getBaseDataType();

	}

	public List<Address> findTypeinfoReferencesNotInTypeinfoStructs(List<Address> typeinfoAddresses)
			throws CancelledException {

		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Typeinfo References");

		AddressSet searchSet = new AddressSet();
		AddressSetView initializedSet = program.getMemory().getAllInitializedAddressSet();
		AddressRangeIterator addressRanges = initializedSet.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCanceled();
			AddressRange addressRange = addressRanges.next();
			searchSet.add(addressRange.getMinAddress(), addressRange.getMaxAddress());
		}
		List<Address> validTypeinfoRefs = new ArrayList<Address>();

		Iterator<Address> typeinfoIterator = typeinfoAddresses.iterator();
		while (typeinfoIterator.hasNext()) {
			monitor.checkCanceled();
			Address typeinfoAddress = typeinfoIterator.next();
			// check direct refs to see if they are in undefined area or not in function
			byte[] bytes = ProgramMemoryUtil.getDirectAddressBytes(program, typeinfoAddress);

			addByteSearchPattern(searcher, validTypeinfoRefs, typeinfoAddress, bytes,
				monitor);

		}
		searcher.search(program, searchSet, monitor);
		return validTypeinfoRefs;
	}

	/**
	 * Method to add a search pattern, to the searcher, for the set of bytes representing a typeinfo 
	 * address
	 * @param searcher the MemoryBytePatternSearcher
	 * @param typeinfoRefs a list typeinfo reference addresses that are not contained 
	 * in a function, instruction, or a typeinfo structure
	 * @param typeinfoAddress the given typeinfo address
	 * @param bytes the bytes to search for
	 * @param taskMonitor a cancellable monitor
	 */
	private void addByteSearchPattern(MemoryBytePatternSearcher searcher,
			List<Address> typeinfoRefs, Address typeinfoAddress, byte[] bytes,
			TaskMonitor taskMonitor) {

		// no pattern bytes.
		if (bytes == null) {
			return;
		}

		// Each time a match for this byte pattern ...
		GenericMatchAction<Address> action = new GenericMatchAction<Address>(typeinfoAddress) {
			@Override
			public void apply(Program prog, Address addr, Match match) {

				Function functionContainingTypeinfoRef =
					prog.getListing().getFunctionContaining(addr);

				Data dataContainingTypeinfoRef = prog.getListing().getDefinedDataContaining(addr);

				Instruction instructionContainingAddr =
					prog.getListing().getInstructionContaining(addr);

				// check the direct references found with the searcher
				// if not in function but is an instruction then create the function
				// otherwise, add to the list to report to user
				if (functionContainingTypeinfoRef == null && instructionContainingAddr == null &&
					dataContainingTypeinfoRef == null) {
					typeinfoRefs.add(addr);
				}
				else if (dataContainingTypeinfoRef != null &&
					!isTypeinfoStruct(dataContainingTypeinfoRef)) {
					typeinfoRefs.add(addr);
				}

			}

		};

		// create a Pattern of the bytes and the MatchAction to perform upon a match
		GenericByteSequencePattern<Address> genericByteMatchPattern =
			new GenericByteSequencePattern<>(bytes, action);

		searcher.addPattern(genericByteMatchPattern);

	}

	/**
	 * Method to determine if the given data is a typeinfo structure
	 * @param data the given data
	 * @return true if the given data is a typeinfo structure, else return false
	 */
	private boolean isTypeinfoStruct(Data data) {

		if (data == null) {
			return false;
		}

		DataType baseDataType = data.getBaseDataType();

		if (!(baseDataType instanceof Structure)) {
			return false;
		}

		Structure structure = (Structure) baseDataType;
		if (structure.getName().contains(CLASS_TYPE_INFO_STRUCTURE)) {
			return true;
		}
		return false;

	}

	/**
	 * Method to create an appropriate type of vtable (primary, internal, or construction) and 
	 * an associated VTT, if applicable
	 * @param vtableAddress the given vtable address
	 * @param vtableNamespace the namespace of the given vtable
	 * @param isPrimary true if the vtable is the primary one for the class
	 * @param listOfAllVtables list of all vtables
	 */
	private void processVtable(Address vtableAddress, Namespace vtableNamespace, boolean isPrimary,
			List<Symbol> listOfAllVtables)
			throws Exception {

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

		// if not already named a construction-vtable then check to see if it is one so it can
		// be renamed and the new namespace figured out
		// know it isn't null because the of the vtable symbol iterator used to call this method in the first place
		Symbol vtableSymbol = symbolTable.getPrimarySymbol(vtableAddress);
		if (!vtableSymbol.getName().equals("construction-vtable") && listOfAllVtables != null) {
			// get first VTT before this vtable
			Symbol vttSymbolBeforeConstructionVtable = getVTTBefore(vtableSymbol.getAddress());
			if (vttSymbolBeforeConstructionVtable != null) {
				List<Address> subVTTs = getSubVTTs(vttSymbolBeforeConstructionVtable.getAddress());

				if (!subVTTs.isEmpty()) {
					int n = 0;
					for (Address subVTTAddress : subVTTs) {
						monitor.checkCanceled();
						n++;
						Symbol constructionVtableSymbol = getNthSymbolOnListAfterAddress(
							vttSymbolBeforeConstructionVtable.getAddress(), listOfAllVtables, n);
						if (constructionVtableSymbol.equals(vtableSymbol)) {

							// change the namespace and name of the vtable
							Namespace classNamespace = createConstructionNamespace(vtableSymbol,
								vttSymbolBeforeConstructionVtable);

							try {
								vtableSymbol.setNameAndNamespace("construction-vtable",
									classNamespace, SourceType.ANALYSIS);
								vtableNamespace = vtableSymbol.getParentNamespace();
								// label the subVTTaddress
								symbolTable.createLabel(subVTTAddress, "subVTT_" + n,
									vttSymbolBeforeConstructionVtable.getParentNamespace(),
									SourceType.ANALYSIS);

								api.setPlateComment(vtableAddress, "construction vtable " + n +
									" for class " +
									vttSymbolBeforeConstructionVtable.getParentNamespace()
											.getName(
												true));

							}
							catch (InvalidInputException e) {
								Msg.debug(this, e.getMessage());
								continue;
							}
							catch (CircularDependencyException e) {
								Msg.debug(this, e.getMessage());
								continue;
							}
							catch (DuplicateNameException e) {
								continue;
							}
						}
					}

				}

			}

		}

		// create longs from top of vtable to the typeinfoAddress
		createLongs(vtableAddress, typeinfoAddress);

		Address possibleVftableAddress = getAddress(typeinfoAddress, defaultPointerSize);

		if (possibleVftableAddress == null) {
			return;
		}

		int numFunctionPointers = getNumFunctionPointers(possibleVftableAddress, true, true);

		if (numFunctionPointers == 0) {
			// if not a vftable check for an internal vtable
			boolean isInternalVtable =
				createInternalVtable(possibleVftableAddress, vtableNamespace);
			if (isInternalVtable) {
				return;
			}
			// if not an internal vtable check for VTT table
			boolean isVTT = createVTT(vtableNamespace, possibleVftableAddress);
			if (isVTT) {
				return;
			}
			return;
		}

		// if at least one function pointer make vftable label - the createVftable method will
		// create the table late
		String vftableLabel = VFTABLE_LABEL;
		if (!isPrimary) {
			vftableLabel = "internal_" + vftableLabel;
		}

		try {
			symbolTable.createLabel(possibleVftableAddress, vftableLabel, vtableNamespace,
				SourceType.ANALYSIS);

			createVftableArray(possibleVftableAddress, numFunctionPointers);
		}
		catch (IllegalArgumentException e) {
			Msg.debug(this, "Could not label vftable at " + possibleVftableAddress.toString());
		}
		catch (InvalidInputException e) {
			Msg.debug(this, "Could not label vftable at " + possibleVftableAddress.toString());
		}
		catch (CancelledException e) {
			return;
		}
		catch (AddressOutOfBoundsException e) {
			Msg.debug(this, "Couldn't create vftable due to Address out of bounds issue");
			return;
		}

		// check for an internal vtable after the vftable and make a symbol there if there is one
		// will process them later
		Address possibleInternalVtableAddress =
			getAddress(possibleVftableAddress, defaultPointerSize * numFunctionPointers);
		// if there is no symbol or a non-default symbol then the nextAddress is an internal
		// vtable
		if (possibleInternalVtableAddress == null) {
			return;
		}

		// check to see if it is an internal vtable
		boolean isInternalVtable =
			createInternalVtable(possibleInternalVtableAddress, vtableNamespace);
		if (isInternalVtable) {
			return;
		}

		// otherwise check to see if it is a VTT table and create it if so
		boolean isVTT = createVTT(vtableNamespace, possibleInternalVtableAddress);
		if (isVTT) {
			return;
		}
	}

	private Symbol getVTTBefore(Address address) throws CancelledException {

		// get all symbols named VTT and get the one directly before the given address
		List<Symbol> vttSymbols = extraUtils.getListOfSymbolsInAddressSet(
			program.getAddressFactory().getAddressSet(), "VTT", true);

		return getSymbolOnListBeforeAddress(address, vttSymbols);

	}

	private List<Address> getSubVTTs(Address vttAddress) {

		// keep getting next code unit and continue while in the VTT (check for pointers)
		// if there is a reference inside the vtt then count it - it is a subVTT
		int offset = 0;
		List<Address> subVtts = new ArrayList<Address>();
		Address currentAddress = vttAddress;
		while (currentAddress != null && getPointerToDefinedMemory(currentAddress) != null) {
			if (offset > 0) {
				Reference[] referencesTo = api.getReferencesTo(currentAddress);
				if (referencesTo.length > 0) {
					subVtts.add(currentAddress);
				}
			}
			offset++;
			currentAddress = getAddress(vttAddress, defaultPointerSize * offset);
		}

		return subVtts;

	}

	/*
	 * Method to get the address on list that is the first that comes after the given address
	 */
	private Symbol getSymbolOnListBeforeAddress(Address givenAddress, List<Symbol> listOfSymbols)
			throws CancelledException {

		if (listOfSymbols.isEmpty()) {
			return null;
		}

		Symbol symbolBefore = null;

		listOfSymbols.sort((a1, a2) -> a1.getAddress().compareTo(a2.getAddress()));

		for (Symbol symbol : listOfSymbols) {
			monitor.checkCanceled();
			if (symbol.getAddress().getOffset() >= givenAddress.getOffset()) {
				return symbolBefore;
			}
			if (symbolBefore == null) {
				symbolBefore = symbol;
				continue;
			}
			if (symbol.getAddress().getOffset() > symbolBefore.getAddress().getOffset()) {
				symbolBefore = symbol;
			}

		}
		return symbolBefore;
	}

	private Symbol getNthSymbolOnListAfterAddress(Address givenAddress, List<Symbol> listOfSymbols,
			int n) throws CancelledException {

		if (listOfSymbols.isEmpty()) {
			return null;
		}

		int numSymbolsAfter = 0;
		listOfSymbols.sort((a1, a2) -> a1.getAddress().compareTo(a2.getAddress()));

		for (Symbol symbol : listOfSymbols) {
			monitor.checkCanceled();
			if (symbol.getAddress().getOffset() > givenAddress.getOffset()) {

				numSymbolsAfter++;
				if (numSymbolsAfter == n) {
					return symbol;
				}
			}
		}
		return null;
	}

	private boolean createInternalVtable(Address possibleInternalVtableAddress,
			Namespace vtableNamespace) throws CancelledException {
		// check to see if it is a pointer and if so, it cannot be an internal vtable
		// as they contain at least one long
		Address pointer = getPointerToDefinedMemory(possibleInternalVtableAddress);
		if (pointer != null) {
			return false;
		}

		Symbol possibleInternalVtableSymbol =
			symbolTable.getPrimarySymbol(possibleInternalVtableAddress);
		if (possibleInternalVtableSymbol != null &&
			possibleInternalVtableSymbol.getSource() != SourceType.DEFAULT &&
			(!possibleInternalVtableSymbol.getParentNamespace().equals(vtableNamespace) ||
				!possibleInternalVtableSymbol.getName().contains("vtable"))) {
			return false;
		}

		if (possibleInternalVtableSymbol == null ||
			(possibleInternalVtableSymbol.getSource() == SourceType.DEFAULT &&
				(isValidVtableStart(possibleInternalVtableAddress) ||
					isValidVftableStart(possibleInternalVtableAddress)))) {
			try {
				symbolTable.createLabel(possibleInternalVtableAddress,
					"internal_vtable_" + possibleInternalVtableAddress.toString(), vtableNamespace,
					SourceType.ANALYSIS);
				processVtable(possibleInternalVtableAddress, vtableNamespace, false, null);
				return true;
			}
			catch (IllegalArgumentException e) {
				Msg.debug(this, "Could not label internal vtable at " +
					possibleInternalVtableAddress.toString());
				return true; // still created vtable, just couldn't name it
			}
			catch (InvalidInputException e) {
				Msg.debug(this, "Could not label internal vtable at " +
					possibleInternalVtableAddress.toString());
				return true; // still created vtable, just couldn't name it
			}
			catch (Exception e) {
				e.printStackTrace();

			}

		}
		return false;
	}

	/**
	 * Method to create a VTT table label at the given address if it is deemed a valid VTT
	 * @param classNamespace the given namespace
	 * @param address the address of the potential VTT table
	 * @return true if a valid VTT has been discovered and label created
	 */
	private boolean createVTT(Namespace classNamespace, Address address) {

		// get pointer at address
		Address pointer = getPointerToDefinedMemory(address);
		if (pointer == null) {
			return false;
		}
		// check to see if pointer is to the class vftable or to a class internal vtable or to itself
		// if not one of those things it isn't a VTT
		Symbol symbol = symbolTable.getPrimarySymbol(pointer);
		if ((!symbol.getName().equals(VFTABLE_LABEL) ||
			!symbol.getName().contains("internal_vtable")) &&
			!symbol.getParentNamespace().equals(classNamespace) && !pointer.equals(address)) {
			return false;
		}

		// if it is then create the VTT symbol and create pointer there
		try {
			symbolTable.createLabel(address, "VTT", classNamespace, SourceType.ANALYSIS);
		}
		catch (IllegalArgumentException e) {
			Msg.debug(this, "Could not label VTT at " + address.toString());
		}
		catch (InvalidInputException e) {
			Msg.debug(this, "Could not label VTT at " + address.toString());
		}

		DataType nullPointer = dataTypeManager.getPointer(null);
		try {
			api.createData(pointer, nullPointer);
		}
		catch (Exception e) {
			// already data there
		}

		api.setPlateComment(address, "VTT for " + classNamespace.getName(true));

		return true;
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
			if (offset > 0 && symbolTable.getPrimarySymbol(address) != null) {
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

	/**
	 * Method to create and apply typeinfo structs of one of the three types used by rtti classes
	 * @throws CancelledException if cancelled
	 * @throws Exception if could not apply a type info structure
	 */
	private void createTypeinfoStructs() throws CancelledException, Exception {

		StructureDataType classTypeInfoStructure = createClassTypeInfoStructure();
		StructureDataType siClassTypeInfoStructure =
			createSiClassTypeInfoStructure(classTypeInfoStructure);
		StructureDataType baseClassTypeInfoStructure =
			createBaseClassTypeInfoStructure(classTypeInfoStructure);

		List<Address> typeinfoAddresses;

		// if dwarf get using symbols
		if (isDwarfLoaded) {
			typeinfoAddresses = getTypeinfoAddressesUsingSymbols();
		}
		else {
			// if not, get using ref to specials
			if (hasExternalRelocationRefs()) {
				typeinfoAddresses = getTypeinfoAddressesUsingRelocationTable();
			}
			else {
				typeinfoAddresses = getTypeinfoAddressesUsingSpecialTypeinfos();
			}
		}

		if (typeinfoAddresses.isEmpty()) {
			return;
		}

		for (Address typeinfoAddress : typeinfoAddresses) {

			Address specialTypeinfoRef = extraUtils.getSingleReferencedAddress(typeinfoAddress);
			if (specialTypeinfoRef == null) {
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

			Data newStructure = null;

			// create a "no inheritance" struct here
			if (specialTypeinfoRef.equals(class_type_info) ||
				specialTypeinfoRef.equals(class_type_info_vtable)) {

				newStructure = applyTypeinfoStructure(classTypeInfoStructure, typeinfoAddress);
			}

			// create a "single inheritance" struct here
			else if (specialTypeinfoRef.equals(si_class_type_info) ||
				specialTypeinfoRef.equals(si_class_type_info_vtable)) {

				newStructure = applyTypeinfoStructure(siClassTypeInfoStructure, typeinfoAddress);
			}

			// create a "virtual multip inheritance" struct here
			else if (specialTypeinfoRef.equals(vmi_class_type_info) ||
				specialTypeinfoRef.equals(vmi_class_type_info_vtable)) {

				Structure vmiClassTypeinfoStructure =
					getOrCreateVmiTypeinfoStructure(typeinfoAddress, baseClassTypeInfoStructure);
				if (vmiClassTypeinfoStructure != null) {
					newStructure =
						applyTypeinfoStructure(vmiClassTypeinfoStructure, typeinfoAddress);
				}
			}

			if (newStructure == null) {
				throw new Exception(
					"ERROR: Could not apply typeinfo structure to " + typeinfoAddress);
			}

			// check for existing symbol and if none, demangle the name and apply
			Symbol typeinfoSymbol = api.getSymbolAt(typeinfoAddress);
			if (typeinfoSymbol == null || typeinfoSymbol.getSource() == SourceType.DEFAULT) {
				typeinfoSymbol = createDemangledTypeinfoSymbol(typeinfoAddress);
				if (typeinfoSymbol == null) {
					Msg.debug(this, "Could not create demangled typeinfo symbol at " +
						typeinfoAddress.toString());
				}
			}

			if (typeinfoSymbol != null && typeinfoSymbol.getName().equals("typeinfo")) {
				promoteToClassNamespace(typeinfoSymbol.getParentNamespace());
				continue;
			}

		}
	}

	private Data applyTypeinfoStructure(Structure typeInfoStructure, Address typeinfoAddress)
			throws CancelledException, AddressOutOfBoundsException {

		api.clearListing(typeinfoAddress, typeinfoAddress.add(typeInfoStructure.getLength() - 1));
		Data newStructure;
		try {
			newStructure = api.createData(typeinfoAddress, typeInfoStructure);
		}
		catch (Exception e) {
			newStructure = null;
		}
		if (newStructure == null) {
			Msg.debug(this,
				"Could not create " + typeInfoStructure.getName() + " at " + typeinfoAddress);
		}
		return newStructure;
	}

	private Structure getOrCreateVmiTypeinfoStructure(Address typeinfoAddress,
			StructureDataType baseClassTypeInfoStructure) {

		// get num base classes
		int offsetOfNumBases = 2 * defaultPointerSize + 4;
		int numBases;
		try {
			numBases = api.getInt(typeinfoAddress.add(offsetOfNumBases));
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}

		// get or create the vmiClassTypeInfoStruct
		Structure vmiClassTypeinfoStructure =
			(Structure) dataTypeManager.getDataType(classDataTypesCategoryPath,
				VMI_CLASS_TYPE_INFO_STRUCTURE + numBases);
		if (vmiClassTypeinfoStructure == null) {
			vmiClassTypeinfoStructure =
				createVmiClassTypeInfoStructure(baseClassTypeInfoStructure, numBases);
		}
		return vmiClassTypeinfoStructure;
	}

	private Symbol createDemangledTypeinfoSymbol(Address typeinfoAddress) {

		String mangledTypeinfo = getTypeinfoName(typeinfoAddress);
		if (mangledTypeinfo == null) {
			Msg.debug(this, "Could not get typeinfo string from " + typeinfoAddress.toString());
			return null;
		}

		if (mangledTypeinfo.startsWith("*")) {
			mangledTypeinfo = mangledTypeinfo.substring(1);
		}
		mangledTypeinfo = "_Z" + mangledTypeinfo;

		DemanglerOptions options = new DemanglerOptions();
		options.setDemangleOnlyKnownPatterns(false);
		options.setApplySignature(false);
		options.setDoDisassembly(false);

		DemangledObject demangled = DemanglerUtil.demangle(mangledTypeinfo);
		if (demangled == null) {
			Msg.debug(this, "Could not demangle typeinfo string at " + typeinfoAddress.toString());
			return null;
		}

		String namespaceString = demangled.getNamespaceString();

		Namespace classNamespace = createTypeinfoClassNamespace(namespaceString);

		Msg.debug(this, typeinfoAddress.toString() + " " + namespaceString);

		if (classNamespace == null) {
			Msg.debug(this,
				typeinfoAddress.toString() +
					"Could not create a class namespace for demangled namespace string " +
					namespaceString);
			return null;
		}

		// create the new typeinfo symbol in the demangled namespace
		try {
			Symbol newSymbol = symbolTable.createLabel(typeinfoAddress, "typeinfo", classNamespace,
				SourceType.ANALYSIS);
			return newSymbol;
		}
		catch (InvalidInputException e) {
			Msg.error(this,
				typeinfoAddress.toString() + " invalid input exception " + e.getMessage());
			return null;
		}
		catch (IllegalArgumentException e) {
			Msg.debug(this,
				typeinfoAddress.toString() + " illegal argument exception " + e.getMessage());
			return null;
		}

	}

	private Namespace createTypeinfoClassNamespace(String namespaceString) {

		int indexOfColons = namespaceString.indexOf("::");
		Namespace namespace = globalNamespace;
		while (indexOfColons != -1) {
			String namespaceName = namespaceString.substring(0, indexOfColons);
			Namespace newNamespace = getOrCreateNamespace(namespaceName, namespace);
			if (newNamespace == null) {
				return null;
			}
			namespace = newNamespace;
			namespaceString = namespaceString.substring(indexOfColons + 2);
			indexOfColons = namespaceString.indexOf("::");
		}
		// the substring after the last :: is the class namespace we want to return
		Namespace classNamespace = getOrCreateNamespace(namespaceString, namespace);
		if (classNamespace == null) {
			return null;
		}

		if (classNamespace.getSymbol().getSymbolType() != SymbolType.CLASS) {
			classNamespace = promoteToClassNamespace(classNamespace);
		}

		return classNamespace;
	}

	private Namespace getOrCreateNamespace(String namespaceName, Namespace parentNamespace) {

		Namespace namespace = symbolTable.getNamespace(namespaceName, parentNamespace);
		if (namespace == null) {
			try {
				namespace = symbolTable.createNameSpace(parentNamespace, namespaceName,
					SourceType.ANALYSIS);
			}
			catch (DuplicateNameException e) {
				// shouldn't happen since it only gets here if the symbol didn't exist in the first place
			}
			catch (InvalidInputException e) {
				return null;
			}
		}
		return namespace;
	}

	private String getTypeinfoName(Address address) {

		Data dataAt = api.getDataAt(address);
		if (dataAt == null) {
			return null;
		}
		if (!(dataAt.getBaseDataType() instanceof Structure)) {
			return null;
		}

		Structure typeinfoStructure = (Structure) dataAt.getBaseDataType();
		if (!typeinfoStructure.getName().contains(CLASS_TYPE_INFO_STRUCTURE)) {
			return null;
		}
		DataTypeComponent typeinfoNameComponent = typeinfoStructure.getComponent(1);
		DataType typeinfoNameDatatype = typeinfoNameComponent.getDataType();
		if (!(typeinfoNameDatatype instanceof Pointer)) {
			return null;
		}

		Address stringReference =
			extraUtils.getSingleReferencedAddress(address.add(typeinfoNameComponent.getOffset()));

		Data stringData = api.getDataAt(stringReference);
		if (stringData == null) {
			return null;
		}
		int stringLen = stringData.getLength();
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), stringReference);

		StringDataType sdt = new StringDataType();

		String str;
		try {
			str = (String) sdt.getValue(buf, sdt.getDefaultSettings(), stringLen);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
		return str;
	}

	/**
	 * Method to get a list typeinfo addresses using symbols
	 * @return a list of non-special typeinfo addresses that have "typeinfo" symbols
	 * @throws CancelledException if cancelled
	 */
	private List<Address> getTypeinfoAddressesUsingSymbols() throws CancelledException {

		List<Address> typeinfoAddresses = new ArrayList<Address>();

		List<Symbol> typeinfoSymbols = extraUtils.getListOfSymbolsInAddressSet(
			program.getAddressFactory().getAddressSet(), "typeinfo", true);

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

			typeinfoAddresses.add(typeinfoAddress);
		}
		return typeinfoAddresses;
	}

	/**
	 * Method to get a list typeinfo addresses using relocation table info
	 * @return a list of typeinfo addresses
	 * @throws CancelledException if cancelled
	 */
	private List<Address> getTypeinfoAddressesUsingRelocationTable() throws CancelledException {

		List<Address> typeinfoAddresses = new ArrayList<Address>();

		Iterator<Bookmark> bookmarksIterator =
			program.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
		while (bookmarksIterator.hasNext()) {
			monitor.checkCanceled();
			Bookmark bookmark = bookmarksIterator.next();
			if (bookmark.getCategory().equals("EXTERNAL Relocation") &&
				bookmarkContainsSpecialTypeinfoName(bookmark.getComment())) {
				typeinfoAddresses.add(bookmark.getAddress());
			}
		}
		return typeinfoAddresses;
	}

	private boolean bookmarkContainsSpecialTypeinfoName(String bookmarkComment) {

		if (bookmarkComment.contains("class_type_info")) {
			return true;
		}

		if (bookmarkComment.contains("si_class_type_info")) {
			return true;
		}
		if (bookmarkComment.contains("vmi_class_type_info")) {
			return true;
		}
		return false;
	}

	/**
	 * Method to check to see if there are any EXTERNAL block relocations
	 * @return true if there are any EXTERNAL block relocations in the program, false otherwise
	 * @throws CancelledException if cancelled
	 */
	private boolean hasExternalRelocationRefs() throws CancelledException {
		// if no external block then there won't be any refernces to special typeinfos in the external
		// block so return empty list
		if (!hasExternalBlock()) {
			return false;
		}
		Iterator<Bookmark> bookmarksIterator =
			program.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
		while (bookmarksIterator.hasNext()) {
			monitor.checkCanceled();
			Bookmark bookmark = bookmarksIterator.next();
			if (bookmark.getCategory().equals("EXTERNAL Relocation")) {
				return true;
			}
		}
		return false;
	}

	private List<Address> getTypeinfoAddressesUsingSpecialTypeinfos() throws CancelledException {

		List<Address> specialTypeinfoRefs = new ArrayList<Address>();

		Reference[] refsToClassTypeinfo = api.getReferencesTo(class_type_info);
		for (Reference ref : refsToClassTypeinfo) {
			monitor.checkCanceled();
			specialTypeinfoRefs.add(ref.getFromAddress());
		}

		Reference[] refsToSiClassTypeinfo = api.getReferencesTo(si_class_type_info);
		for (Reference ref : refsToSiClassTypeinfo) {
			monitor.checkCanceled();
			specialTypeinfoRefs.add(ref.getFromAddress());
		}

		Reference[] refsToVmiClassTypeinfo = api.getReferencesTo(vmi_class_type_info);
		for (Reference ref : refsToVmiClassTypeinfo) {
			monitor.checkCanceled();
			specialTypeinfoRefs.add(ref.getFromAddress());
		}

		return specialTypeinfoRefs;
	}

	/**
	 * Method to call the various methods to determine whether the functions that make references to
	 * the vftables are constructors, destructors, deleting destructors, clones, or vbase functions
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting function return
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @Exception if issues making labels
	 */
	private void processConstructorAndDestructors()
			throws CancelledException, InvalidInputException, DuplicateNameException, Exception {

		// find deleting destructors using various mechanisms
		//	findDeletingDestructors(recoveredClasses);

		// use atexit param list to find more destructors
		//	findDestructorsUsingAtexitCalledFunctions(recoveredClasses);

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

		// use the known constructors and known vfunctions to figure out 
		// clone functions
		//	findCloneFunctions(recoveredClasses);

		// This has to be here. It needs all the info from the previously run methods to do this.
		// Finds the constructors that have multiple basic blocks, reference the vftable not in the 
		// first block, and call non-parent constructors and non operator new before the vftable ref
		//	findMoreInlinedConstructors(recoveredClasses);

		//	findDestructorsWithNoParamsOrReturn(recoveredClasses);

		// use vftables with references to all the same function (except possibly one deleting 
		// destructor)to find the purecall function
		//	identifyPureVirtualFunction(recoveredClasses);

		//	findRealVBaseFunctions(recoveredClasses);

	}

	private StructureDataType createClassTypeInfoStructure() {

		StructureDataType classTypeInfoStructure = new StructureDataType(classDataTypesCategoryPath,
			CLASS_TYPE_INFO_STRUCTURE, 0, dataTypeManager);

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
			classDataTypesCategoryPath, SI_CLASS_TYPE_INFO_STRUCTURE, 0, dataTypeManager);

		CharDataType characterDT = new CharDataType();
		DataType pointer = dataTypeManager.getPointer(null);
		DataType charPointer = dataTypeManager.getPointer(characterDT);

		siClassTypeInfoStructure.add(pointer, "classTypeinfoPtr", null);
		siClassTypeInfoStructure.add(charPointer, "typeinfoName", null);

		DataType pointerToClassTypeInfoStruct = dataTypeManager.getPointer(classTypeInfoStructure);
		siClassTypeInfoStructure.add(pointerToClassTypeInfoStruct, "baseClassTypeInfoPtr", null);

		siClassTypeInfoStructure.setPackingEnabled(true);

		return siClassTypeInfoStructure;
	}

	private StructureDataType createBaseClassTypeInfoStructure(
			StructureDataType classTypeInfoStructure) throws InvalidDataTypeException {

		StructureDataType baseclassTypeInfoStructure = new StructureDataType(
			classDataTypesCategoryPath, BASE_CLASS_TYPE_INFO_STRUCTURE, 0, dataTypeManager);

		DataType classTypeInfoPointer = dataTypeManager.getPointer(classTypeInfoStructure);

		int offsetBitSize = 24;
		if (defaultPointerSize == 8) {
			offsetBitSize = 56;
		}

		baseclassTypeInfoStructure.add(classTypeInfoPointer, "classTypeinfoPtr", null);

		if (program.getMemory().isBigEndian()) {
			baseclassTypeInfoStructure.addBitField(LongDataType.dataType, offsetBitSize,
				"baseClassOffset", null);
			baseclassTypeInfoStructure.addBitField(BooleanDataType.dataType, 1, "isPublicBase",
				null);
			baseclassTypeInfoStructure.addBitField(BooleanDataType.dataType, 1, "isVirtualBase",
				null);
			baseclassTypeInfoStructure.addBitField(ByteDataType.dataType, 6, "unused", null);
		}
		else {
			baseclassTypeInfoStructure.addBitField(BooleanDataType.dataType, 1, "isVirtualBase",
				null);
			baseclassTypeInfoStructure.addBitField(BooleanDataType.dataType, 1, "isPublicBase",
				null);
			baseclassTypeInfoStructure.addBitField(ByteDataType.dataType, 6, "unused", null);
			baseclassTypeInfoStructure.addBitField(LongDataType.dataType, offsetBitSize,
				"baseClassOffset", null);
		}

		baseclassTypeInfoStructure.setPackingEnabled(true);

		return baseclassTypeInfoStructure;

	}

	private StructureDataType createVmiClassTypeInfoStructure(
			StructureDataType baseClassTypeInfoStructure, int numBaseClasses) {

		StructureDataType vmiClassTypeInfoStructure =
			new StructureDataType(classDataTypesCategoryPath,
				VMI_CLASS_TYPE_INFO_STRUCTURE + numBaseClasses, 0, dataTypeManager);

		CharDataType characterDT = new CharDataType();
		UnsignedIntegerDataType unsignedIntDT = new UnsignedIntegerDataType();

		DataType pointer = dataTypeManager.getPointer(null);
		DataType charPointer = dataTypeManager.getPointer(characterDT);

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
	 * @throws Exception if cannot access the given typeinfo structure, one of its components,  or it is not a vmi structure
	 */
	private List<RecoveredClass> addGccClassParentsFromVmiStruct(RecoveredClass recoveredClass,
			Address typeinfoAddress) throws Exception {

		Structure vmiTypeinfoStructure = getTypeinfoStructure(typeinfoAddress);
		if (vmiTypeinfoStructure == null ||
			!vmiTypeinfoStructure.getName().contains(VMI_CLASS_TYPE_INFO_STRUCTURE)) {
			throw new Exception(
				"Could not get vmi base typeinfo structure at address " + typeinfoAddress);
		}

		// process the inheritance flag
		DataTypeComponent inheritanceFlagComponent = vmiTypeinfoStructure.getComponent(2);
		int flagOffset = inheritanceFlagComponent.getOffset();
		DataType inheritanceFlagDataType = inheritanceFlagComponent.getDataType();
		MemBuffer buf =
			new DumbMemBufferImpl(program.getMemory(), getAddress(typeinfoAddress, flagOffset));
		Scalar scalar = (Scalar) inheritanceFlagDataType.getValue(buf,
			inheritanceFlagDataType.getDefaultSettings(), inheritanceFlagDataType.getLength());
		long inheritanceFlagValue = scalar.getUnsignedValue();

		// 0x01: class has non-diamond repeated inheritance
		// 0x02: class is diamond shaped
		// add flag for non-diamond repeated and diamond shape types
		if (inheritanceFlagValue == 1) {
			if (DEBUG) {
				Msg.debug(this,
					"from typeinfo at address " + typeinfoAddress.toString() + " " +
						recoveredClass.getClassNamespace().getName(true) +
						" has non-diamond repeated inheritance");
			}
		}
		if (inheritanceFlagValue == 2) {
			recoveredClass.setIsDiamondShaped(true);
		}

		// process the base classes
		// create parent maps
		Map<Integer, RecoveredClass> orderToParentMap = new HashMap<Integer, RecoveredClass>();
		Map<RecoveredClass, Long> parentToOffsetMap = new HashMap<RecoveredClass, Long>();

		DataTypeComponent numBaseClassesComponent = vmiTypeinfoStructure.getComponent(3);
		int numBaseClassesOffset = numBaseClassesComponent.getOffset();
		DataType numBaseClassesDataType = numBaseClassesComponent.getDataType();
		buf = new DumbMemBufferImpl(program.getMemory(),
			getAddress(typeinfoAddress, numBaseClassesOffset));
		scalar = (Scalar) numBaseClassesDataType.getValue(buf,
			numBaseClassesDataType.getDefaultSettings(), numBaseClassesDataType.getLength());
		int numBaseClasses = (int) scalar.getUnsignedValue();

		if (numBaseClasses > 1) {
			recoveredClass.setHasMultipleInheritance(true);
			recoveredClass.setHasSingleInheritance(false);
		}
		else {
			recoveredClass.setHasMultipleInheritance(false);
			recoveredClass.setHasSingleInheritance(true);
		}

		// process the base class array
		DataTypeComponent baseClassArrayComponent = vmiTypeinfoStructure.getComponent(4);
		if (baseClassArrayComponent == null) {
			throw new Exception(
				"Could not get base class array in vmi structure at " + typeinfoAddress.toString());
		}
		int baseClassArrayOffset = baseClassArrayComponent.getOffset();

		List<RecoveredClass> parentClassList = new ArrayList<RecoveredClass>();

		int numParents = numBaseClasses;

		for (int i = 0; i < numParents; i++) {

			// get parent from pointer to parent typeinfo
			Address parentRefAddress =
				getAddress(typeinfoAddress, baseClassArrayOffset + (i * 2 * defaultPointerSize));

			RecoveredClass parentClass = getParentClassFromParentTypeInfoRef(parentRefAddress);
			if (parentClass == null) {
				throw new Exception("Could not get parent class number " + (i + 1) +
					" from typeinfo struct at " + typeinfoAddress.toString());
			}

			if (DEBUG) {
				Msg.debug(this,
					recoveredClass.getName() + " adding vmi parent " + parentClass.getName());
			}

			updateClassWithParent(parentClass, recoveredClass);
			parentClassList.add(parentClass);

			LongDataType longDT = new LongDataType();

			// get public/virtual/offset flag
			Address flagAddress = getAddress(typeinfoAddress,
				baseClassArrayOffset + (i * 2 * defaultPointerSize + defaultPointerSize));

			buf = new DumbMemBufferImpl(program.getMemory(), flagAddress);

			Scalar value =
				(Scalar) longDT.getValue(buf, longDT.getDefaultSettings(), defaultPointerSize);

			long publicVirtualOffsetFlag = value.getSignedValue();

			//The low-order byte of __offset_flags contains flags, as given by the masks 
			//from the enumeration __offset_flags_masks:

			//0x1: Base class is virtual
			//0x2: Base class is public

			boolean isVirtual = false;
			boolean isPublic = false;

			long virtualMask = 0x1L;
			long publicMask = 0x2L;
			long offsetMask;
			if (defaultPointerSize == 4) {
				offsetMask = 0xffffff00L;

			}
			else {
				offsetMask = 0xffffffffffffff00L;
			}

			if ((publicVirtualOffsetFlag & virtualMask) == 1) {
				isVirtual = true;
			}

			if (recoveredClass.hasMultipleInheritance()) {
				recoveredClass.setHasMultipleVirtualInheritance(isVirtual);
			}

			recoveredClass.addParentToBaseTypeMapping(parentClass, isVirtual);

			recoveredClass.setInheritsVirtualAncestor(isVirtual);

			if (((publicVirtualOffsetFlag & publicMask) >> 1) == 1) {
				isPublic = true;
			}

			parentClass.setIsPublicClass(isPublic);

			// from doc:
			//All but the lower 8 bits of __offset_flags are a signed offset. For a 
			//non-virtual base, this is the offset in the object of the base subobject. 
			//For a virtual base, this is the offset in the virtual table of the 
			//virtual base offset for the virtual base referenced (negative).
			long offset = (publicVirtualOffsetFlag & offsetMask) >> 8;

			Msg.debug(this, "typeinfo " + typeinfoAddress + " base [" + i + "] isVirtual = " +
				isVirtual + " isPublic = " + isPublic + " offset = " + offset);

			// add order to parent and parent offset
			orderToParentMap.put(i, parentClass);
			parentToOffsetMap.put(parentClass, offset);

			continue;

		}

		if (DEBUG) {
			Msg.debug(this, recoveredClass.getName() + " has " + numParents + " parents");
		}

		classToParentOrderMap.put(recoveredClass, orderToParentMap);
		classToParentOffsetMap.put(recoveredClass, parentToOffsetMap);

		return parentClassList;

	}

	/**
	 * Get the parent class given the typeinfo address of an Si class
	 * @param typeinfoAddress the given Si class's typeinfo Address
	 * @return the parent class
	 * @throws Exception if cannot access parent's type info reference address or if could not get
	 * the parent class
	 */
	private RecoveredClass getSiClassParent(Address typeinfoAddress) throws Exception {

		int offset = defaultPointerSize * 2;

		Address parentTypeinfoRef = getAddress(typeinfoAddress, offset);
		if (parentTypeinfoRef == null) {

			throw new Exception("Could not access address " + typeinfoAddress.toString() +
				" plus offset " + offset);

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
			program.getAddressFactory().getAddressSet(), VTABLE_LABEL, true);

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
				//createNewClass(vtableNamespace, false);
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
		if (address.equals(class_type_info_vtable) || address.equals(si_class_type_info_vtable) ||
			address.equals(vmi_class_type_info_vtable)) {
			return true;
		}
		return false;
	}

	private void createClassesFromTypeinfoSymbols(List<Symbol> typeinfoSymbols)
			throws CancelledException {

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

			Namespace classNamespace = typeinfoSymbol.getParentNamespace();

			RecoveredClass recoveredClass = getClass(classNamespace);

			// we don't know yet if this class has vftable so just add without for now
			if (recoveredClass == null) {
				recoveredClass = createNewClass(classNamespace, false);
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
			if (specialTypeinfoRef.equals(class_type_info) ||
				specialTypeinfoRef.equals(class_type_info_vtable)) {

				nonInheritedGccClasses.add(recoveredClass);
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setHasParentClass(false);
				recoveredClass.setInheritsVirtualAncestor(false);
				continue;
			}

			// per docs those on this list are
			// classes containing only a single, public, non-virtual base at offset zero
			if (specialTypeinfoRef.equals(si_class_type_info) ||
				specialTypeinfoRef.equals(si_class_type_info_vtable)) {

				singleInheritedGccClasses.add(recoveredClass);
				recoveredClass.setHasSingleInheritance(true);
				recoveredClass.setInheritsVirtualAncestor(false);
				continue;
			}

			if (specialTypeinfoRef.equals(vmi_class_type_info) ||
				specialTypeinfoRef.equals(vmi_class_type_info_vtable)) {

				multiAndOrVirtuallyInheritedGccClasses.add(recoveredClass);
				// not necessarily multiple - maybe just a single virtual ancestor or maybe a single 
				// non-public one

			}
		}
	}

	/**
	 * Use information from RTTI Base class Arrays to create class hierarchy lists and maps
	 * @throws CancelledException if cancelled
	 */
	private void createClassHierarchyListAndMapForGcc()
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
			if (multiAndOrVirtuallyInheritedGccClasses.contains(recoveredClass)) {
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

		// update the inherits virtual ancestor flag using ancestors - previously was only done for
		// parents but now have all classes with flag set for direct parent so can get the other ancestors
		// too
		recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

			// if we already know it then skip
			if (recoveredClass.inheritsVirtualAncestor()) {
				continue;
			}

			// if hasn't been set yet - check the other ancestors besides parents
			if (hasVirtualAncestor(recoveredClass)) {
				recoveredClass.setInheritsVirtualAncestor(true);
			}
		}

	}

	private boolean hasVirtualAncestor(RecoveredClass recoveredClass) throws CancelledException {

		List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();
		Iterator<RecoveredClass> classIterator = classHierarchy.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass ancestor = classIterator.next();
			if (ancestor.inheritsVirtualAncestor()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Create the class hierarchy list for a class with no inheritance
	 * @param recoveredClass the given class
	 * @return the class hierarchy list for the given class with no inheritance
	 */
	private List<RecoveredClass> getGccNoClassHierarchy(RecoveredClass recoveredClass) {
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
			if (multiAndOrVirtuallyInheritedGccClasses.contains(parentClass)) {
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
	 * @throws CancelledException when cancelled
	 * @throws Exception if issue creating data
	 */
	private void createAndApplyClassStructures() throws CancelledException, Exception {

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

		// can't handle creating class data types for classes with virtual parents  yet
		if (recoveredClass.inheritsVirtualAncestor()) {
			if (DEBUG) {
				Msg.debug(this, "Cannot create class data type for " +
					recoveredClass.getClassNamespace().getName(true) +
					" because it has virtual ancestors and we don't yet handle that use case.");
			}
			return;
		}

		// can't handle creating class data types for diamond shaped classes yet
		if (recoveredClass.isDiamondShaped()) {
			if (DEBUG) {
				Msg.debug(this,
					"Cannot create class data type for " +
						recoveredClass.getClassNamespace().getName(true) +
						" because it is diamond shaped and we don't yet handle that use case.");
			}
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

		// create current class structure and add pointer to vftable, all parent member data strutures, 
		// and class member data structure
		Structure classStruct = createSimpleClassStructure(recoveredClass, vfPointerDataTypes);

		// check for DWARF -- if none add c/d/etc to class
		if (!isDwarfLoaded) {

			// Now that we have a class data type
			// name constructor and destructor functions and put into the class namespace
			addConstructorsToClassNamespace(recoveredClass, classStruct);
			addDestructorsToClassNamespace(recoveredClass);
//			addNonThisDestructorsToClassNamespace(recoveredClass);
//			addVbaseDestructorsToClassNamespace(recoveredClass);
//			addVbtableToClassNamespace(recoveredClass);
//
//			// add secondary label on functions with inlined constructors or destructors
//			createInlinedConstructorComments(recoveredClass);
//			createInlinedDestructorComments(recoveredClass);
//			createIndeterminateInlineComments(recoveredClass);

			// add label on constructor destructor functions that could not be determined which were which
			createIndeterminateLabels(recoveredClass);
		}

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
		// if single inheritance or multi non-virtual (wouldn't have called this method if
		// it were virtually inherited) put parent struct and data into class struct
		else {

			Map<Integer, RecoveredClass> orderToParentMap =
				classToParentOrderMap.get(recoveredClass);
			if (orderToParentMap.isEmpty()) {
				throw new Exception(
					"Vmi class " + recoveredClass.getClassNamespace().getName(true) +
						" should have a parent in the classToParentOrderMap but doesn't");
			}

			Map<RecoveredClass, Long> parentToOffsetMap =
				classToParentOffsetMap.get(recoveredClass);
			if (parentToOffsetMap.isEmpty()) {
				throw new Exception(
					"Vmi class " + recoveredClass.getClassNamespace().getName(true) +
						" should have a parent in the classToParentOffsetMap but doesn't");
			}

			int numParents = orderToParentMap.keySet().size();
			for (int i = 0; i < numParents; i++) {
				RecoveredClass parent = orderToParentMap.get(i);

				Long parentOffsetLong = parentToOffsetMap.get(parent);
				if (parentOffsetLong == null) {
					throw new Exception(
						"Can't get parent offset for " + parent.getClassNamespace().getName(true));
				}
				int parentOffset = parentOffsetLong.intValue();

				Structure baseClassStructure = getClassStructureFromDataTypeManager(parent);
				// if we can't get the parent throw exception because it shouldn't get here if the parent
				// doesn't exist
				if (baseClassStructure == null) {
					throw new Exception(parent.getClassNamespace().getName(true) +
						" : structure should exist but doesn't.");
				}

				if (structUtils.canAdd(classStructureDataType, parentOffset,
					baseClassStructure.getLength(), monitor)) {
					classStructureDataType =
						structUtils.addDataTypeToStructure(classStructureDataType, parentOffset,
							baseClassStructure, baseClassStructure.getName(), monitor);
				}
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

		if (classStructureDataType.getNumComponents() == classStructureDataType
				.getNumDefinedComponents()) {
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
