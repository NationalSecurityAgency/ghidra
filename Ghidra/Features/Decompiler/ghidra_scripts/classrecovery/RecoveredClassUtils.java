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
import java.util.stream.Collectors;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd;
import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd.OffsetPcodeOpPair;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReference;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.bytesearch.*;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class RecoveredClassUtils {

	public static final String DTM_CLASS_DATA_FOLDER_NAME = "ClassDataTypes";
	private static final String CLASS_DATA_STRUCT_NAME = "_data";
	private static final String DEFAULT_VFUNCTION_PREFIX = "vfunction";
	private static final String VFUNCTION_COMMENT = "virtual function #";
	private static final String CLASS_VFUNCTION_STRUCT_NAME = "_vftable";

	public static final String VFTABLE_LABEL = "vftable";
	private static final String VBASE_DESTRUCTOR_LABEL = "vbase_destructor";
	private static final String VBTABLE_LABEL = "vbtable";
	private static final String CLONE_LABEL = "clone";
	private static final String DELETING_DESTRUCTOR_LABEL = "deleting_destructor";

	private static final String BOOKMARK_CATEGORY = "RECOVERED CLASS";

	private static final String INLINE_CONSTRUCTOR_BOOKMARK = "INLINED CONSTRUCTOR";
	private static final String INLINE_DESTRUCTOR_BOOKMARK = "INLINED DESTRUCTOR";

	private static final String INDETERMINATE_INLINE_BOOKMARK = "INDETERMINATE INLINE";

	private static final int NONE = -1;

	private static int MIN_OPERATOR_NEW_REFS = 10;

	private static final boolean DEBUG = false;

	private Map<Address, RecoveredClass> vftableToClassMap = new HashMap<Address, RecoveredClass>();

	// map from vftable references to the vftables they point to
	private Map<Address, Address> vftableRefToVftableMap = new HashMap<Address, Address>();

	// map from function to its vftable references
	private Map<Function, List<Address>> functionToVftableRefsMap =
		new HashMap<Function, List<Address>>();

	// map from function to class(es) it is in
	private Map<Function, List<RecoveredClass>> functionToClassesMap =
		new HashMap<Function, List<RecoveredClass>>();

	// map from function to all called constructors/destructors ref/addr pairs
	Map<Function, List<ReferenceAddressPair>> functionToCalledConsDestRefAddrPairMap =
		new HashMap<Function, List<ReferenceAddressPair>>();

	// map from class to list of possible parent classes
	Map<RecoveredClass, List<RecoveredClass>> possibleParentMap =
		new HashMap<RecoveredClass, List<RecoveredClass>>();

	// map from namespace to class object
	Map<Namespace, RecoveredClass> namespaceToClassMap = new HashMap<Namespace, RecoveredClass>();

	Map<Function, List<OffsetPcodeOpPair>> functionToStorePcodeOps =
		new HashMap<Function, List<OffsetPcodeOpPair>>();
	Map<Function, List<OffsetPcodeOpPair>> functionToLoadPcodeOps =
		new HashMap<Function, List<OffsetPcodeOpPair>>();

	List<Function> allConstructorsAndDestructors = new ArrayList<Function>();
	List<Function> allConstructors = new ArrayList<Function>();
	List<Function> allDestructors = new ArrayList<Function>();
	List<Function> allInlinedConstructors = new ArrayList<Function>();
	List<Function> allInlinedDestructors = new ArrayList<Function>();

	List<Namespace> badFIDNamespaces = new ArrayList<Namespace>();
	List<Structure> badFIDStructures = new ArrayList<Structure>();

	List<Function> badFIDFunctions = new ArrayList<Function>();
	List<Function> resolvedFIDFunctions = new ArrayList<Function>();
	List<Function> fixedFIDFunctions = new ArrayList<Function>();

	private static Function operator_delete = null;
	private static Function operator_new = null;
	private static Function purecall = null;

	private static Function atexit = null;
	List<Function> atexitCalledFunctions = new ArrayList<Function>();

	List<Function> deletingDestructorsThatCallDestructor = new ArrayList<Function>();

	GlobalNamespace globalNamespace;
	DataTypeManager dataTypeManager;
	int defaultPointerSize;
	SymbolTable symbolTable;

	ExtraScriptUtils extraUtils;
	EditStructureUtils structUtils;

	DecompilerScriptUtils decompilerUtils;
	CategoryPath classDataTypesCategoryPath;

	private TaskMonitor monitor;
	private Program program;
	ProgramLocation location;
	PluginTool tool;
	FlatProgramAPI api;
	boolean createBookmarks;
	boolean useShortTemplates;
	boolean nameVfunctions;

	public RecoveredClassUtils(Program program, ProgramLocation location, PluginTool tool,
			FlatProgramAPI api, boolean createBookmarks, boolean useShortTemplates,
			boolean nameVfunctions, TaskMonitor monitor) {

		this.monitor = monitor;
		this.program = program;
		this.location = location;
		this.tool = tool;
		this.api = api;

		extraUtils = new ExtraScriptUtils(program, monitor);

		this.classDataTypesCategoryPath =
			extraUtils.createDataTypeCategoryPath(CategoryPath.ROOT, DTM_CLASS_DATA_FOLDER_NAME);

		this.createBookmarks = createBookmarks;
		this.useShortTemplates = useShortTemplates;
		this.nameVfunctions = nameVfunctions;

		globalNamespace = (GlobalNamespace) program.getGlobalNamespace();

		decompilerUtils = new DecompilerScriptUtils(program, tool, monitor);
		structUtils = new EditStructureUtils();

		dataTypeManager = program.getDataTypeManager();
		symbolTable = program.getSymbolTable();

		defaultPointerSize = program.getDefaultPointerSize();
	}

	public void updateVftableToClassMap(Address vftableAddress, RecoveredClass recoveredClass) {
		if (vftableToClassMap.get(vftableAddress) == null) {
			vftableToClassMap.put(vftableAddress, recoveredClass);
		}
	}

	public RecoveredClass getVftableClass(Address vftableAddress) {
		return vftableToClassMap.get(vftableAddress);
	}

	/**
	 * Method to create a mappings between the list of vftable references to the vftables they reference
	 * @param referencesToVftable addresses that reference the given vftable address
	 * @param vftableAddress the given vftable address
	 * @throws CancelledException if cancelled
	 */
	public void addReferenceToVtableMapping(List<Address> referencesToVftable,
			Address vftableAddress) throws CancelledException {

		Iterator<Address> referencesIterator = referencesToVftable.iterator();
		while (referencesIterator.hasNext()) {
			Address vtableReference = referencesIterator.next();
			monitor.checkCanceled();
			vftableRefToVftableMap.put(vtableReference, vftableAddress);
		}
	}

	public Address getVftableAddress(Address vftableReference) {
		return vftableRefToVftableMap.get(vftableReference);
	}

	/**
	 * Method to update the functionToVftableListMap with the given input
	 * @param vftableRefToFunctionMapping a mapping of a vftable reference to the function it is in
	 * @throws CancelledException if cancelled
	 */
	public void addFunctionToVftableReferencesMapping(
			Map<Address, Function> vftableRefToFunctionMapping) throws CancelledException {

		Set<Address> keySet = vftableRefToFunctionMapping.keySet();
		Iterator<Address> referencesIterator = keySet.iterator();
		while (referencesIterator.hasNext()) {
			monitor.checkCanceled();
			Address vtableReference = referencesIterator.next();
			Function function = vftableRefToFunctionMapping.get(vtableReference);
			if (functionToVftableRefsMap.containsKey(function)) {
				List<Address> referenceList = functionToVftableRefsMap.get(function);
				if (!referenceList.contains(vtableReference)) {
					List<Address> newReferenceList = new ArrayList<Address>(referenceList);
					newReferenceList.add(vtableReference);
					functionToVftableRefsMap.replace(function, referenceList, newReferenceList);
				}
			}
			else {
				List<Address> referenceList = new ArrayList<Address>();
				referenceList.add(vtableReference);
				functionToVftableRefsMap.put(function, referenceList);
			}
		}
	}

	public List<Address> getVftableReferences(Function function) {
		return functionToVftableRefsMap.get(function);
	}

	/**
	 * Method to add function to map of class it is contained in some functions are in 
	 * multiple classes becuase they have references to multiple class vtables either 
	 * because they have an inlined parent
	 * @param functions the given list of functions
	 * @param recoveredClass the given class
	 * @throws CancelledException if cancelled
	 */
	public void addFunctionsToClassMapping(List<Function> functions, RecoveredClass recoveredClass)
			throws CancelledException {

		Iterator<Function> functionIterator = functions.iterator();
		while (functionIterator.hasNext()) {
			monitor.checkCanceled();
			Function function = functionIterator.next();
			// if the map already contains a mapping for function and if
			// the associated class list doesn't contain the new class, then
			// add the new class and update the mapping
			if (functionToClassesMap.containsKey(function)) {
				List<RecoveredClass> classList = functionToClassesMap.get(function);
				if (!classList.contains(recoveredClass)) {
					List<RecoveredClass> newClassList = new ArrayList<RecoveredClass>(classList);
					newClassList.add(recoveredClass);
					functionToClassesMap.replace(function, classList, newClassList);
				}
			}
			// if the map doesn't contain a mapping for function, then add it
			else {
				List<RecoveredClass> classList = new ArrayList<RecoveredClass>();
				classList.add(recoveredClass);
				functionToClassesMap.put(function, classList);
			}
		}

	}

	public List<RecoveredClass> getClasses(Function function) {
		return functionToClassesMap.get(function);
	}

	/**
	 * Method to find all the vftables in the program 
	 * @return list of all vftable symbols
	 * @throws CancelledException when cancelled
	 */
	public List<Symbol> getListOfVftableSymbols() throws CancelledException {

		// Do with *'s to also get the PDB ones
		SymbolIterator vftableSymbols =
			program.getSymbolTable().getSymbolIterator("*vftable*", true);

		List<Symbol> vftableSymbolList = new ArrayList<Symbol>();
		while (vftableSymbols.hasNext()) {
			monitor.checkCanceled();
			Symbol vftableSymbol = vftableSymbols.next();
			if (vftableSymbol.getName().equals("vftable")) {
				vftableSymbolList.add(vftableSymbol);
			}
			// check for ones that are pdb that start with ' and may or may not end with '
			// can't just get all that contain vftable because that would get some strings
			else {
				String name = vftableSymbol.getName();
				name = name.substring(1, name.length());
				if (name.startsWith("vftable")) {
					vftableSymbolList.add(vftableSymbol);
				}
			}
		}
		return vftableSymbolList;
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
	public Symbol getSymbolInNamespaces(String parentNamespaceName, String namespaceName,
			String symbolName) throws CancelledException {

		SymbolIterator symbols = program.getSymbolTable().getSymbols(symbolName);
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

	public Address getSingleAddressOfSymbolContainingBothStrings(String string1, String string2)
			throws CancelledException {

		List<Address> symbolAddressList = new ArrayList<Address>();

		SymbolIterator symbols =
			program.getSymbolTable().getSymbolIterator("*" + string1 + "*", true);

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
	 * Method to create a map with keyset containing all constructor/destructor functions in the 
	 * given list of classes and associated mapping to list of refAddrPairs for called 
	 * constructor/destructor functions  
	 * @param recoveredClasses the list of classes
	 * @throws CancelledException if cancelled
	 */
	public void createCalledFunctionMap(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<Function> constructorOrDestructorFunctions =
				recoveredClass.getConstructorOrDestructorFunctions();
			Iterator<Function> functionIterator = constructorOrDestructorFunctions.iterator();
			while (functionIterator.hasNext()) {
				monitor.checkCanceled();
				Function function = functionIterator.next();
				createFunctionToCalledConstructorOrDestructorRefAddrPairMapping(function);
			}
		}

	}

	/**
	 * Method to determine and add the mapping of the given function to its called constructor or destructor functions
	 * @param function given function
	 * @throws CancelledException when script is canceled
	 */
	public void createFunctionToCalledConstructorOrDestructorRefAddrPairMapping(Function function)
			throws CancelledException {

		List<ReferenceAddressPair> referenceAddressPairs = new ArrayList<ReferenceAddressPair>();
		Set<Function> calledFunctions = function.getCalledFunctions(monitor);
		Iterator<Function> calledFunctionIterator = calledFunctions.iterator();
		while (calledFunctionIterator.hasNext()) {
			monitor.checkCanceled();
			Function calledFunction = calledFunctionIterator.next();
			Function referencedFunction = calledFunction;
			if (calledFunction.isThunk()) {
				Function thunkFunction = calledFunction.getThunkedFunction(true);
				calledFunction = thunkFunction;
			}
			// if thunk, need to use the thunked function to see if it is on list of cds
			// but always need to use the actual called function to get reference address 
			// need to used the thunked function on the hashmap
			if (allConstructorsAndDestructors.contains(calledFunction)) {
				// get list of refs to this function from the calling function
				List<Address> referencesToFunctionBFromFunctionA =
					extraUtils.getReferencesToFunctionBFromFunctionA(function,
						referencedFunction);
				// add them to list of ref address pairs
				Iterator<Address> iterator = referencesToFunctionBFromFunctionA.iterator();
				while (iterator.hasNext()) {
					monitor.checkCanceled();
					Address sourceRefAddr = iterator.next();
					referenceAddressPairs.add(
						new ReferenceAddressPair(sourceRefAddr, calledFunction.getEntryPoint()));
				}
			}
		}
		// add list to global map
		functionToCalledConsDestRefAddrPairMap.put(function, referenceAddressPairs);

	}

	public List<ReferenceAddressPair> getCalledConstDestRefAddrPairs(Function function) {
		return functionToCalledConsDestRefAddrPairMap.get(function);
	}

	public void updateNamespaceToClassMap(Namespace namespace, RecoveredClass recoveredClass) {
		namespaceToClassMap.put(namespace, recoveredClass);
	}

	public RecoveredClass getClass(Namespace namespace) {
		return namespaceToClassMap.get(namespace);
	}

	public void updateFunctionToStorePcodeOpsMap(Function function,
			List<OffsetPcodeOpPair> offsetPcodeOpPairs) {
		if (functionToStorePcodeOps.get(function) == null) {
			functionToStorePcodeOps.put(function, offsetPcodeOpPairs);
		}
	}

	public List<OffsetPcodeOpPair> getStorePcodeOpPairs(Function function) {
		return functionToStorePcodeOps.get(function);
	}

	public void updateFunctionToLoadPcodeOpsMap(Function function,
			List<OffsetPcodeOpPair> offsetPcodeOpPairs) {
		if (functionToLoadPcodeOps.get(function) == null) {
			functionToLoadPcodeOps.put(function, offsetPcodeOpPairs);
		}
	}

	public List<OffsetPcodeOpPair> getLoadPcodeOpPairs(Function function) {
		return functionToLoadPcodeOps.get(function);
	}

	public void updateAllConstructorsAndDestructorsList(List<Function> functions) {
		allConstructorsAndDestructors.addAll(functions);
	}

	public List<Function> getAllConstructorsAndDestructors() {
		return allConstructorsAndDestructors;
	}

	public void addToAllConstructors(Function function) {
		allConstructors.add(function);
	}

	public void removeFromAllConstructors(Function function) {
		allConstructors.remove(function);
	}

	public List<Function> getAllConstructors() {
		return allConstructors;
	}

	public void addToAllDestructors(Function function) {
		allDestructors.add(function);
	}

	public void removeFromAllDestructors(Function function) {
		allDestructors.remove(function);
	}

	public List<Function> getAllDestructors() {
		return allDestructors;
	}

	public void addToAllInlinedConstructors(Function function) {
		allInlinedConstructors.add(function);
	}

	public void removeFromAllInlinedConstructors(Function function) {
		allInlinedConstructors.remove(function);
	}

	public List<Function> getAllInlinedConstructors() {
		return allInlinedConstructors;
	}

	public void addToAllInlinedDestructors(Function function) {
		allInlinedDestructors.add(function);
	}

	public void removeFromAllInlinedDestructors(Function function) {
		allInlinedDestructors.remove(function);
	}

	public List<Function> getAllInlinedDestructors() {
		return allInlinedDestructors;
	}

	/**
	 * Method to determine if referenced vftables are from the same class
	 * @param vftableReferences list of vftable references
	 * @return true if all listed vftable references refer to vftables from the same class, false otherwise
	 * @throws CancelledException when cancelled
	 */
	public boolean areVftablesInSameClass(List<Address> vftableReferences)
			throws CancelledException {

		List<RecoveredClass> classes = new ArrayList<RecoveredClass>();

		Iterator<Address> iterator = vftableReferences.iterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			Address vftableReference = iterator.next();
			Address vftableAddress = vftableRefToVftableMap.get(vftableReference);
			RecoveredClass recoveredClass = vftableToClassMap.get(vftableAddress);
			if (!classes.contains(recoveredClass)) {
				classes.add(recoveredClass);
			}
		}
		if (classes.size() > 1) {
			return false;
		}
		return true;
	}

	/**
	 * Method to return reference to the class vftable in the given function
	 * @param recoveredClass the given class
	 * @param function the given function
	 * @return the reference to the class vftable in the given function or null if there isn't one
	 * @throws CancelledException if cancelled
	 */
	public Address getClassVftableReference(RecoveredClass recoveredClass,
			Function function) throws CancelledException {

		List<Address> vftableReferenceList = functionToVftableRefsMap.get(function);

		if (vftableReferenceList == null) {
			return null;
		}

		Iterator<Address> vftableRefs = vftableReferenceList.iterator();
		while (vftableRefs.hasNext()) {
			monitor.checkCanceled();
			Address vftableRef = vftableRefs.next();

			Address vftableAddress = vftableRefToVftableMap.get(vftableRef);
			if (vftableAddress == null) {
				continue;
			}

			RecoveredClass referencedClass = vftableToClassMap.get(vftableAddress);
			if (referencedClass == null) {
				continue;
			}

			if (referencedClass.equals(recoveredClass)) {
				return vftableRef;
			}
		}
		return null;

	}

	/**
	 * Method to return the vftable reference in the given function that corresponds to the given class
	 * @param function the given function
	 * @param recoveredClass the given class
	 * @return the vftableRef address in the given function that corresponds to the given class
	 * @throws CancelledException if cancelled
	 */
	public Address getClassVftableRefInFunction(Function function, RecoveredClass recoveredClass)
			throws CancelledException {

		List<Address> listOfClassRefsInFunction =
			getSortedListOfAncestorRefsInFunction(function, recoveredClass);

		Iterator<Address> iterator = listOfClassRefsInFunction.iterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			Address classRef = iterator.next();
			Address vftableAddress = vftableRefToVftableMap.get(classRef);

			// skip the ones that aren't vftable refs
			if (vftableAddress == null) {
				continue;
			}

			// return the first one that is a vftable ref to the given class
			RecoveredClass vftableClass = vftableToClassMap.get(vftableAddress);
			if (vftableClass.equals(recoveredClass)) {
				return classRef;
			}
		}
		return null;
	}

	/**
	 * Method to get a sorted list of both vftable and call refs to ancestor classes of the given 
	 * class in the given function
	 * @param function the given function
	 * @param recoveredClass the given class
	 * @return a sorted list of both vftable and call refs to ancestor classes of the given 
	 * class in the given function
	 * @throws CancelledException if cancelled
	 */
	public List<Address> getSortedListOfAncestorRefsInFunction(Function function,
			RecoveredClass recoveredClass) throws CancelledException {

		// get the map of all referenced vftables or constructor/desstructor calls in this function
		Map<Address, RecoveredClass> referenceToClassMapForFunction =
			getReferenceToClassMap(recoveredClass, function);

		// get a list of all ancestor classes referenced in the map 
		List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();

		// make a list of all related class references
		List<Address> listOfAncestorRefs = new ArrayList<Address>();
		Set<Address> ancestorRefs = referenceToClassMapForFunction.keySet();
		Iterator<Address> ancestorRefIterator = ancestorRefs.iterator();
		while (ancestorRefIterator.hasNext()) {
			monitor.checkCanceled();
			Address ancestorRef = ancestorRefIterator.next();
			RecoveredClass mappedClass = referenceToClassMapForFunction.get(ancestorRef);
			if (classHierarchy.contains(mappedClass)) {
				listOfAncestorRefs.add(ancestorRef);
			}
		}

		Collections.sort(listOfAncestorRefs);
		return listOfAncestorRefs;
	}

	/**
	 * Method to create a map of all references to classes in the given function. Classes are, for this purpose, referenced if they
	 * a vftable belonging to a class is referenced or if a constructor/destructor function from a class is called 
	 * @param recoveredClass the given class
	 * @param function the given function
	 * @return Map of Address references to Class object for the given function
	 * @throws CancelledException when cancelled
	 */
	public Map<Address, RecoveredClass> getReferenceToClassMap(RecoveredClass recoveredClass,
			Function function) throws CancelledException {

		Map<Address, RecoveredClass> referenceToParentMap = new HashMap<Address, RecoveredClass>();

		List<Address> vftableRefs = functionToVftableRefsMap.get(function);

		if (vftableRefs == null) {
			return referenceToParentMap;
		}

		// iterate through all vftable refs in the function and add it to ref/Parent map
		Iterator<Address> vftableRefIterator = vftableRefs.iterator();
		while (vftableRefIterator.hasNext()) {

			monitor.checkCanceled();

			Address vftableRef = vftableRefIterator.next();
			Address vftableAddress = extraUtils.getSingleReferencedAddress(vftableRef);

			if (vftableAddress == null) {
				continue;
			}

			RecoveredClass parentClass = vftableToClassMap.get(vftableAddress);
			referenceToParentMap.put(vftableRef, parentClass);
		}

		// remove duplicate vftable refs (occasionally there are LEA then MOV of same vftable address
		// a few intructions of each other. It confuses later processes to have both.
		referenceToParentMap = dedupeMap(referenceToParentMap);

		// iterate through all the ref/addr pairs of called constructors/destructors in the function
		// and get the class the constructor/destructor belongs to and add the ref/Parent pair to the
		// same map as the vftable refs above
		List<ReferenceAddressPair> refAddrPairsToCalledParents =
			functionToCalledConsDestRefAddrPairMap.get(function);

		// if no calls then just return the ones found in the vftable section above
		if (refAddrPairsToCalledParents == null) {
			return referenceToParentMap;
		}

		Iterator<ReferenceAddressPair> refAddPairIterator = refAddrPairsToCalledParents.iterator();

		while (refAddPairIterator.hasNext()) {

			monitor.checkCanceled();

			ReferenceAddressPair parentRefAddrPair = refAddPairIterator.next();

			Address parentConstructorAddress = parentRefAddrPair.getDestination();
			Function parentConstructor =
				program.getFunctionManager().getFunctionAt(parentConstructorAddress);

			if (parentConstructor.isThunk()) {
				parentConstructor = parentConstructor.getThunkedFunction(true);
			}

			RecoveredClass ancestorClass =
				getAncestorClassWithGivenFunction(recoveredClass, parentConstructor);

			if (ancestorClass == null) {
				continue;
			}

			referenceToParentMap.put(parentRefAddrPair.getSource(), ancestorClass);
		}

		return referenceToParentMap;
	}

	/**
	 * Get the list of incorrect FID functions
	 * @return the list of incorrect FID functions
	 */
	public List<Function> getBadFIDFunctions() {
		return badFIDFunctions;
	}

	/**
	 * Get the list of resolved functions that had multiple FID possibilities before but could 
	 * be resolved to the correct name.
	 * @return the list of resolved FID functions
	 */
	public List<Function> getResolvedFIDFunctions() {
		return badFIDFunctions;
	}

	/**
	 * Get the fixed functions that had incorrect data types due to incorrect FID (includes those
	 * incorrect due to decompiler propagation of bad types from bad FID)
	 * @return the fixed functions that had incorrect data types due to incorrect FID
	 */
	public List<Function> getFixedFIDFunctions() {
		return badFIDFunctions;
	}

	private Map<Address, RecoveredClass> dedupeMap(Map<Address, RecoveredClass> map)
			throws CancelledException {

		// Sort the vftable refs in the order they appear in the function
		Set<Address> vftableRefs = map.keySet();
		List<Address> vftableRefList = new ArrayList<Address>(vftableRefs);
		Collections.sort(vftableRefList);

		Iterator<Address> vftableRefIterator = vftableRefList.iterator();
		RecoveredClass lastClass = null;
		Address lastVftableRef = null;
		while (vftableRefIterator.hasNext()) {
			monitor.checkCanceled();
			Address vftableRef = vftableRefIterator.next();
			RecoveredClass currentClass = map.get(vftableRef);

			if (lastClass != null && lastClass.equals(currentClass)) {
				// if vftable refs are within a few instructions, dedupe map
				if (numInstructionsApart(lastVftableRef, vftableRef) <= 3) {
					map.remove(vftableRef);
				}
			}

			lastClass = currentClass;
			lastVftableRef = vftableRef;
		}

		return map;
	}

	private int numInstructionsApart(Address ref1, Address ref2) throws CancelledException {

		Instruction instruction = program.getListing().getInstructionAfter(ref1);
		int numApart = 0;
		while (instruction != null && !instruction.contains(ref2)) {
			monitor.checkCanceled();
			numApart++;
			instruction = program.getListing().getInstructionAfter(instruction.getMaxAddress());
		}
		return numApart;
	}

	/**
	 * Method to figure out which of the multiple parents of a class contain the given function in their class
	 * @param recoveredClass the given class with multiple parents
	 * @param function the given function that is in one of the parent classes
	 * @return the parent class that the given function belongs to
	 * @throws CancelledException if cancelled
	 */
	private RecoveredClass getAncestorClassWithGivenFunction(RecoveredClass recoveredClass,
			Function function) throws CancelledException {

		List<RecoveredClass> classList = functionToClassesMap.get(function);

		if (classList == null) {
			return null;
		}

		if (classList.contains(recoveredClass)) {
			classList.remove(recoveredClass);
		}

		if (classList.size() == 0) {
			return null;
		}

		if (classList.size() == 1) {
			return classList.get(0);
		}

		List<RecoveredClass> parentClasses =
			new ArrayList<RecoveredClass>(recoveredClass.getClassHierarchyMap().keySet());

		// try direct parents first
		Iterator<RecoveredClass> parentsIterator = parentClasses.iterator();
		while (parentsIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass parentClass = parentsIterator.next();
			List<Function> constructorDestructorList =
				new ArrayList<Function>(parentClass.getConstructorList());
			constructorDestructorList.addAll(parentClass.getDestructorList());
			if (constructorDestructorList.contains(function)) {
				return parentClass;
			}
		}

		// if not found in direct parents, try all ancestors
		List<RecoveredClass> ancestorClasses = recoveredClass.getClassHierarchy();

		if (ancestorClasses.size() <= 1) {
			return recoveredClass;
		}

		ListIterator<RecoveredClass> ancestorIterator = ancestorClasses.listIterator(1);
		while (ancestorIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass ancestorClass = ancestorIterator.next();

			// already checked the parents
			if (parentClasses.contains(ancestorClass)) {
				continue;
			}
			List<Function> constructorDestructorList =
				new ArrayList<Function>(ancestorClass.getConstructorList());
			constructorDestructorList.addAll(ancestorClass.getDestructorList());
			if (constructorDestructorList.contains(function)) {
				return ancestorClass;
			}
		}

		return null;
	}

	/**
	 * Method to get a list of addresses that are references from the given address
	 * @param address the given address
	 * @return a list of addresses that are references from the given address 
	 */
	private List<Address> getReferenceFromAddresses(Address address) {

		Reference[] referencesFrom = program.getReferenceManager().getReferencesFrom(address);

		// get only the address references at the given address (ie no stack refs, ...)
		List<Address> refFromAddresses = new ArrayList<Address>();
		for (Reference referenceFrom : referencesFrom) {
			if (referenceFrom.isMemoryReference()) {
				refFromAddresses.add(referenceFrom.getToAddress());
			}
		}

		return refFromAddresses;
	}

	/**
	 * Retrieve the first stored vftable from the pcodeOps in the list 
	 * @param storedPcodeOps list of offset/PcodeOp pairs
	 * @return first referenced vftable address 
	 * @throws CancelledException if cancelled
	 */
	public Address getStoredVftableAddress(List<OffsetPcodeOpPair> storedPcodeOps)
			throws CancelledException {

		if (storedPcodeOps.size() > 0) {
			Iterator<OffsetPcodeOpPair> iterator = storedPcodeOps.iterator();
			// figure out if vftable is referenced
			while (iterator.hasNext()) {
				monitor.checkCanceled();
				OffsetPcodeOpPair offsetPcodeOpPair = iterator.next();
				PcodeOp pcodeOp = offsetPcodeOpPair.getPcodeOp();
				Varnode storedValue = pcodeOp.getInput(2);
				Address vftableAddress = decompilerUtils.getAssignedAddressFromPcode(storedValue);
				if (vftableAddress != null && vftableToClassMap.containsKey(vftableAddress)) {
					return vftableAddress;
				}
			}
		}
		return null;
	}

	/**
	 * Method to get a list of addresses that reference the given vftable address
	 * @param vftableAddress the given vftable address
	 * @return list of addresses that reference the given vftable address
	 * @throws CancelledException if cancelled
	 */
	public List<Address> getReferencesToVftable(Address vftableAddress) throws CancelledException {

		List<Address> referencesToVftable = new ArrayList<>();

		ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(vftableAddress);

		while (iterator.hasNext()) {

			monitor.checkCanceled();

			Reference reference = iterator.next();
			Address vtableReference = reference.getFromAddress();
			referencesToVftable.add(vtableReference);
		}

		return referencesToVftable;
	}

	/**
	 * Method to retrieve a list of vftable symbols, from the given list of vftables, in the given 
	 * namespace
	 * @param vftableSymbols the list of all vftable symbols
	 * @param namespace the given namespace
	 * @return a list of vftable symbols in the given namespace
	 * @throws CancelledException if cancelled
	 */
	public List<Symbol> getVftablesInNamespace(List<Symbol> vftableSymbols, Namespace namespace)
			throws CancelledException {

		List<Symbol> vftableSymbolsInNamespace = new ArrayList<Symbol>();

		Iterator<Symbol> symbolsInNamespace = program.getSymbolTable().getSymbols(namespace);
		while (symbolsInNamespace.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = symbolsInNamespace.next();
			if (vftableSymbols.contains(symbol) &&
				!isSymbolAddressOnList(vftableSymbolsInNamespace, symbol.getAddress())) {
				vftableSymbolsInNamespace.add(symbol);
			}
		}
		return vftableSymbolsInNamespace;
	}

	private boolean isSymbolAddressOnList(List<Symbol> symbols, Address address)
			throws CancelledException {

		Iterator<Symbol> symbolIterator = symbols.iterator();
		while (symbolIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = symbolIterator.next();
			if (symbol.getAddress().equals(address)) {
				return true;
			}

		}
		return false;
	}

	/**
	 * Method to determine if the given function is an inlined destructor or indeterminate in any class
	 * @param function the given function
	 * @return true if the given function is an inlined function in any class, false if it is not an 
	 * inlined function in any class
	 * @throws CancelledException if cancelled
	 */
	public boolean isInlineDestructorOrIndeterminateInAnyClass(Function function)
			throws CancelledException {

		List<RecoveredClass> functionClasses = getClasses(function);
		if (functionClasses == null) {
			if (DEBUG) {
				Msg.debug(this, "no function to class map for " + function.getEntryPoint());
			}
			return true;
		}
		Iterator<RecoveredClass> functionClassesIterator = functionClasses.iterator();
		while (functionClassesIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = functionClassesIterator.next();

			if (recoveredClass.getInlinedDestructorList().contains(function)) {
				return true;
			}
			if (recoveredClass.getIndeterminateInlineList().contains(function)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method to create mappings for the current class and use the decompiler
	 * to figure out class member data information
	 * @param recoveredClass class that function belongs to
	 * @param function current function to process
	 * @throws CancelledException if cancelled
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if issues setting return type
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	public void gatherClassMemberDataInfoForFunction(RecoveredClass recoveredClass,
			Function function) throws CancelledException, DuplicateNameException,
			InvalidInputException, CircularDependencyException {

		// save off param and return information
		Parameter[] originalParameters = function.getParameters();
		DataType[] originalTypes = new DataType[originalParameters.length];
		SourceType[] originalSources = new SourceType[originalParameters.length];
		for (int i = 0; i < originalParameters.length; i++) {
			monitor.checkCanceled();
			originalTypes[i] = originalParameters[i].getDataType();
			originalSources[i] = originalParameters[i].getSource();
		}
		DataType originalReturnType = function.getReturnType();
		SourceType originalReturnSource = function.getReturn().getSource();

		Namespace originalNamespace = function.getParentNamespace();

		// temporarily remove class data type or other empty structures from return and params
		// so they do not skew the structure contents from FillOutStructureCmd 
		temporarilyReplaceEmptyStructures(function, recoveredClass.getClassNamespace());

		// create maps and updates class member data information using structure and pcode info  returned
		// from FillOutStructureCmd
		updateMapsAndClassMemberDataInfo(function, recoveredClass);

		// replace namespace if it was removed
		if (!function.getParentNamespace().equals(originalNamespace)) {
			function.setParentNamespace(originalNamespace);
		}

		// put back return and param data types that were temporarily removed
		Parameter[] parameters = function.getParameters();
		for (int i = 0; i < parameters.length; i++) {
			monitor.checkCanceled();
			if (parameters[i].getName().equals("this")) {
				continue;
			}
			if (!parameters[i].getDataType().equals(originalTypes[i])) {
				parameters[i].setDataType(originalTypes[i], originalSources[i]);
			}
		}
		if (!function.getReturnType().equals(originalReturnType)) {
			function.setReturnType(originalReturnType, originalReturnSource);
		}
	}

	/**
	 * Method to update the given class's maps and class member data using the given function info
	 * @param function the given function
	 * @param recoveredClass the given class
	 * @throws CancelledException if cancelled
	 */
	private void updateMapsAndClassMemberDataInfo(Function function, RecoveredClass recoveredClass)
			throws CancelledException {

		List<Address> vftableReferenceList = getVftableReferences(function);
		if (vftableReferenceList == null) {
			if (DEBUG) {
				Msg.debug(this, "In update maps: function to class map doesn't exist for " +
					function.getEntryPoint().toString());
			}
			return;
		}
		Collections.sort(vftableReferenceList);
		Address firstVftableReference = vftableReferenceList.get(0);
		if (firstVftableReference == null) {
			return;
		}

		// make sure first vftable ref is in the given class (if inlined it might not be)
		Address vftableAddress = getVftableAddress(firstVftableReference);
		RecoveredClass vftableClass = getVftableClass(vftableAddress);
		if (!vftableClass.equals(recoveredClass)) {

			if (DEBUG) {
				Msg.debug(this, "updating struct for " + recoveredClass.getName() +
					" but first vftable in function " + function.getEntryPoint().toString() +
					" is in class " + vftableClass.getName());
			}

			return;
		}

		getStructureFromDecompilerPcode(recoveredClass, function, firstVftableReference);

	}

	/**
	 * Method to retrieve a filled-in structure associated with the given function's high variable
	 * that stores the given first vftable reference address in the given function.
	 * @param recoveredClass the given class
	 * @param function the given function
	 * @param firstVftableReference the first vftable reference address in the given function
	 * @throws CancelledException if cancelled
	 */
	public void getStructureFromDecompilerPcode(RecoveredClass recoveredClass, Function function,
			Address firstVftableReference) throws CancelledException {

		// get the decompiler highFunction 
		HighFunction highFunction = decompilerUtils.getHighFunction(function);

		if (highFunction == null) {
			return;

		}

		List<HighVariable> highVariables = new ArrayList<HighVariable>();

		// if there are params add the first or the "this" param to the list to be checked first 
		// It is the most likely to store the vftablePtr
		if (highFunction.getFunctionPrototype().getNumParams() > 0) {

			HighVariable thisParam =
				highFunction.getFunctionPrototype().getParam(0).getHighVariable();
			if (thisParam != null) {
				highVariables.add(thisParam);
			}
		}

		// add the other high variables that store vftable pointer
		highVariables.addAll(
			getVariableThatStoresVftablePointer(highFunction, firstVftableReference));
		Iterator<HighVariable> highVariableIterator = highVariables.iterator();

		Address vftableAddress = null;
		while (highVariableIterator.hasNext()) {

			HighVariable highVariable = highVariableIterator.next();
			monitor.checkCanceled();

			FillOutStructureCmd fillCmd = new FillOutStructureCmd(program, location, tool);

			Structure structure = fillCmd.processStructure(highVariable, function);

			NoisyStructureBuilder componentMap = fillCmd.getComponentMap();

			List<OffsetPcodeOpPair> stores = fillCmd.getStorePcodeOps();
			stores = removePcodeOpsNotInFunction(function, stores);

			// this method checks the storedPcodeOps to see if one is the desired vftable address
			vftableAddress = getStoredVftableAddress(stores);
			if (vftableAddress != null &&
				getVftableAddress(firstVftableReference).equals(vftableAddress)) {

				if (structure != null) {
					recoveredClass.updateClassMemberStructure(structure);
					recoveredClass.updateClassMemberStructureUndefineds(componentMap);
				}

				List<OffsetPcodeOpPair> loads = fillCmd.getLoadPcodeOps();
				loads = removePcodeOpsNotInFunction(function, loads);

				//functionToStorePcodeOps.put(function, stores);
				updateFunctionToStorePcodeOpsMap(function, stores);
				updateFunctionToLoadPcodeOpsMap(function, loads);
				return;
			}

			if (DEBUG) {
				Msg.debug(this, "Could not find variable pointing to vftable in " +
					function.getEntryPoint().toString());
			}

		}

	}

	/**
	 * Method to determine which variable in the decompiler stores the vftable address
	 * @param highFunction the decompiler high function 
	 * @param vftableReference the address that points to a vftable
	 * @return the list of variables in the given function that store the vftable address
	 * @throws CancelledException if cancelled
	 */
	//TODO: update to make sure it is getting any global memory variables
	//TODO: Possibly refactor to use the same methodology as getAssignedAddressFrompcode or getStoredVftableAddress
	private List<HighVariable> getVariableThatStoresVftablePointer(HighFunction highFunction,
			Address vftableReference) throws CancelledException {

		List<HighVariable> highVars = new ArrayList<HighVariable>();

		Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
		while (pcodeOps.hasNext()) {
			monitor.checkCanceled();
			PcodeOp pcodeOp = pcodeOps.next();
			if (pcodeOp.getOpcode() == PcodeOp.STORE) {

				Address address = getTargetAddressFromPcodeOp(pcodeOp);
				if (address.equals(vftableReference)) {

					Varnode[] inputs = pcodeOp.getInputs();
					for (Varnode input : inputs) {
						monitor.checkCanceled();
						if (input.getHigh() != null) {
							highVars.add(input.getHigh());
						}
					}
				}
			}
		}
		return highVars;

	}

	/**
	 * temporarily change the function signature of the given constructor or destructor to replace
	 * any empty structure with same size undefined datatype and to also remove the functin from
	 * its namespace to remove the empty structure from the this param. This is so that the
	 * class member data calculations are made without bad info
	 * @param function the given function
	 * @param classNamespace the given class namespace
	 * @throws CancelledException if cancelled
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if issue making function thiscall
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	private void temporarilyReplaceEmptyStructures(Function function, Namespace classNamespace)
			throws CancelledException, DuplicateNameException, InvalidInputException,
			CircularDependencyException {

		int parameterCount = function.getParameterCount();
		for (int i = 0; i < parameterCount; i++) {
			monitor.checkCanceled();

			// if this call - temporarily put in global namespace to remove class structure
			// in order to get unbiased pcode store information
			if (function.getParameter(i).getName().equals("this")) {
				function.setParentNamespace(globalNamespace);
				continue;
			}

			DataType dataType = function.getParameter(i).getDataType();

			if (!extraUtils.isPointerToEmptyStructure(dataType)) {
				continue;
			}

			PointerDataType ptrUndefined = extraUtils.createPointerToUndefinedDataType(dataType);
			if (ptrUndefined != null) {
				function.getParameter(i).setDataType(ptrUndefined, SourceType.ANALYSIS);
			}

		}

		// Next check the return type to see if it is the empty structure
		DataType returnType = function.getReturnType();
		if (extraUtils.isPointerToEmptyStructure(returnType)) {
			PointerDataType ptrUndefined =
				extraUtils.createPointerToUndefinedDataType(returnType);
			if (ptrUndefined != null) {
				function.setReturnType(ptrUndefined, SourceType.ANALYSIS);
			}
		}

	}

	/**
	 * Method to determine if the given possible ancestor is an ancestor of any of the listed classes 
	 * @param recoveredClasses List of classes
	 * @param possibleAncestor possible ancestor of one of the listed classes
	 * @return true if ancestor of one of the listed classes, false otherwise
	 * @throws Exception if one of the classes has empty class hierarchy
	 */
	public boolean isClassAnAncestorOfAnyOnList(List<RecoveredClass> recoveredClasses,
			RecoveredClass possibleAncestor) throws Exception {

		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();

			if (isClassAnAncestor(recoveredClass, possibleAncestor)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method to determine if a class is an ancestor of another class
	 * @param recoveredClass the class with possible ancestor
	 * @param possibleAncestorClass the class that might be ancestor of recoveredClass
	 * @return true if possibleAncestorClass is an ancestor of recoveredClass, false otherwise
	 * @throws Exception if class hierarchy is empty
	 */
	private boolean isClassAnAncestor(RecoveredClass recoveredClass,
			RecoveredClass possibleAncestorClass) throws Exception {

		List<RecoveredClass> classHierarchy =
			new ArrayList<RecoveredClass>(recoveredClass.getClassHierarchy());

		if (classHierarchy.isEmpty()) {
			throw new Exception(
				recoveredClass.getName() + " should not have an empty class hierarchy");
		}

		//remove self
		classHierarchy.remove(recoveredClass);

		if (classHierarchy.contains(possibleAncestorClass)) {
			return true;
		}
		return false;
	}

	/**
	 * Method to return subList of offset/pcodeOp pairs from the given list that are contained in the current function
	 * @param function The given function
	 * @param pcodeOps The list of pcodeOps to filter
	 * @return List of pcodeOps from given list that are contained in given function
	 * @throws CancelledException when cancelled
	 */
	public List<OffsetPcodeOpPair> removePcodeOpsNotInFunction(Function function,
			List<OffsetPcodeOpPair> pcodeOps) throws CancelledException {

		Iterator<OffsetPcodeOpPair> pcodeOpsIterator = pcodeOps.iterator();
		while (pcodeOpsIterator.hasNext()) {
			monitor.checkCanceled();
			OffsetPcodeOpPair offsetPcodeOpPair = pcodeOpsIterator.next();
			PcodeOp pcodeOp = offsetPcodeOpPair.getPcodeOp();
			Address pcodeOpAddress = pcodeOp.getSeqnum().getTarget();
			if (!function.getBody().contains(pcodeOpAddress)) {
				pcodeOpsIterator.remove();
			}
		}
		return pcodeOps;
	}

	/**
	 * Method to get the listing address that the given PcodeOp is associated with
	 * @param pcodeOp the given PcodeOp
	 * @return the address the given PcodeOp is associated with 
	 */
	public Address getTargetAddressFromPcodeOp(PcodeOp pcodeOp) {
		return pcodeOp.getSeqnum().getTarget();
	}

	public Function getCalledFunctionFromCallPcodeOp(PcodeOp calledPcodeOp) {

		Function calledFunction =
			api.getFunctionAt(calledPcodeOp.getInput(0).getAddress());
		if (calledFunction == null) {
			return null;
		}

		return calledFunction;
	}

	/**
	 * method to update the two given classes with their related class hierarchy
	 * @param parentClass parent of childClass
	 * @param childClass child of parentClass
	 */
	public void updateClassWithParent(RecoveredClass parentClass, RecoveredClass childClass) {

		// return if they are already a known parent/child pair
		if (parentClass.getChildClasses().contains(childClass) &&
			childClass.getParentList().contains(parentClass)) {
			return;
		}

		childClass.addParent(parentClass);

		childClass.setHasParentClass(true);
		parentClass.setHasChildClass(true);
		parentClass.addChildClass(childClass);

		return;
	}

	/**
	 * Method to retrieve only the classes that have vfunctions from the given list of classes
	 * @param recoveredClasses the given list of classes
	 * @return a list of classes that have vfunctions
	 * @throws CancelledException if cancelled
	 */
	public List<RecoveredClass> getClassesWithVFunctions(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		List<RecoveredClass> classesWithVFunctions = new ArrayList<RecoveredClass>();

		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();
			if (recoveredClass.hasVftable()) {
				classesWithVFunctions.add(recoveredClass);
			}
		}

		return classesWithVFunctions;
	}

	/**
	 * Method that returns a list of all parents with virtual functions for the given class
	 * @param recoveredClass given class
	 * @return list of all parents with virtual functions for given class or empty list if none
	 * @throws CancelledException when cancelled
	 */
	public List<RecoveredClass> getParentsWithVirtualFunctions(RecoveredClass recoveredClass)
			throws CancelledException {

		List<RecoveredClass> parentsWithVFunctions = new ArrayList<RecoveredClass>();

		Map<RecoveredClass, List<RecoveredClass>> classHierarchyMap =
			recoveredClass.getClassHierarchyMap();

		// no parents so return empty list
		if (classHierarchyMap.isEmpty()) {
			return parentsWithVFunctions;
		}

		List<RecoveredClass> parentClassList =
			new ArrayList<RecoveredClass>(classHierarchyMap.keySet());

		Iterator<RecoveredClass> parentIterator = parentClassList.iterator();
		while (parentIterator.hasNext()) {

			monitor.checkCanceled();

			RecoveredClass parentClass = parentIterator.next();
			if (parentClass.hasVftable()) {
				parentsWithVFunctions.add(parentClass);
			}
		}

		return parentsWithVFunctions;
	}

	/**
	 * Method to get list of the given class's ancestors that have virtual functions or functions inherited virtual functions(ie a vftable)
	 * @param recoveredClass the given class
	 * @return list of the given class's ancestors that have virtual functions or functions inherited virtual functions(ie a vftable)
	 * @throws CancelledException if cancelled
	 */
	public List<RecoveredClass> getAncestorsWithVirtualFunctions(RecoveredClass recoveredClass)
			throws CancelledException {

		List<RecoveredClass> ancestorsWithVFunctions = new ArrayList<RecoveredClass>();

		// no parents so return empty list
		if (!recoveredClass.hasParentClass()) {
			return ancestorsWithVFunctions;
		}

		List<RecoveredClass> classHierarchyList = recoveredClass.getClassHierarchy();

		Iterator<RecoveredClass> ancestorIterator = classHierarchyList.iterator();
		while (ancestorIterator.hasNext()) {

			monitor.checkCanceled();

			RecoveredClass parentClass = ancestorIterator.next();
			if (parentClass.hasVftable()) {
				ancestorsWithVFunctions.add(parentClass);
			}
		}

		return ancestorsWithVFunctions;
	}

	/**
	 * Method to get ancestors that do not have vfunctions
	 * @param recoveredClass the given class
	 * @return List of ancestors without vfunctions
	 * @throws CancelledException if cancelled
	 */
	public List<RecoveredClass> getAncestorsWithoutVfunctions(RecoveredClass recoveredClass)
			throws CancelledException {

		List<RecoveredClass> ancestorsWithoutVfunctions = new ArrayList<RecoveredClass>();

		List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();

		Iterator<RecoveredClass> hierarchyIterator = classHierarchy.iterator();

		while (hierarchyIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass ancestorClass = hierarchyIterator.next();

			// skip self
			if (ancestorClass.equals(recoveredClass)) {
				continue;
			}
			if (!ancestorClass.hasVftable()) {
				ancestorsWithoutVfunctions.add(ancestorClass);
			}
		}

		return ancestorsWithoutVfunctions;
	}

	/**
	 * Method to test whether class has ancestor without virtual functions or not
	 * @param recoveredClass given class object
	 * @return true if class has an ancestor class without virtual functions
	 * @throws CancelledException if cancelled
	 */
	public boolean hasNonVirtualFunctionAncestor(RecoveredClass recoveredClass)
			throws CancelledException {
		List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();
		Iterator<RecoveredClass> recoveredClassIterator = classHierarchy.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass currentClass = recoveredClassIterator.next();
			if (!currentClass.hasVftable()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method to get all ancestor class constructors for the given class
	 * @param recoveredClass given class
	 * @return List of all functions that are constructors of an ancestor class of given class
	 * @throws CancelledException if script is cancelled
	 */
	public List<Function> getAllAncestorConstructors(RecoveredClass recoveredClass)
			throws CancelledException {

		List<Function> allAncestorConstructors = new ArrayList<Function>();

		List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();
		ListIterator<RecoveredClass> classHierarchyIterator = classHierarchy.listIterator(1);

		while (classHierarchyIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass currentClass = classHierarchyIterator.next();

			List<Function> constructorList =
				new ArrayList<Function>(currentClass.getConstructorList());
			constructorList.addAll(currentClass.getInlinedConstructorList());
			Iterator<Function> constructors = constructorList.iterator();
			while (constructors.hasNext()) {
				monitor.checkCanceled();
				Function constructor = constructors.next();
				if (!allAncestorConstructors.contains(constructor)) {
					allAncestorConstructors.add(constructor);
				}
			}
		}
		return allAncestorConstructors;
	}

	/**
	 * Method to retrieve a list of destructors for the ancestors of the given class
	 * @param recoveredClass the given class
	 * @return a list of destructors for the ancestors of the given class
	 * @throws CancelledException if cancelled
	 */
	public List<Function> getAncestorDestructors(RecoveredClass recoveredClass)
			throws CancelledException {

		List<Function> allAncestorDestructors = new ArrayList<Function>();

		List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();
		ListIterator<RecoveredClass> classHierarchyIterator = classHierarchy.listIterator(1);

		while (classHierarchyIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass parentClass = classHierarchyIterator.next();

			List<Function> destructorList =
				new ArrayList<Function>(parentClass.getDestructorList());
			destructorList.addAll(parentClass.getInlinedDestructorList());
			Iterator<Function> destructors = destructorList.iterator();
			while (destructors.hasNext()) {
				monitor.checkCanceled();
				Function destructor = destructors.next();
				if (!allAncestorDestructors.contains(destructor)) {
					allAncestorDestructors.add(destructor);
				}
			}
		}
		return allAncestorDestructors;
	}

	/**
	 * Method to retrieve all constructors of descendants of the given class
	 * @param recoveredClass the given class
	 * @return a list of all constructors of descendants of the given class
	 * @throws CancelledException if cancelled
	 */
	public List<Function> getAllDescendantConstructors(RecoveredClass recoveredClass)
			throws CancelledException {

		List<Function> allDescendantConstructors = new ArrayList<Function>();

		List<RecoveredClass> childClasses = recoveredClass.getChildClasses();
		Iterator<RecoveredClass> childClassIterator = childClasses.iterator();
		while (childClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass childClass = childClassIterator.next();

			List<Function> constructorList =
				new ArrayList<Function>(childClass.getConstructorList());
			constructorList.addAll(childClass.getInlinedConstructorList());
			Iterator<Function> constructors = constructorList.iterator();
			while (constructors.hasNext()) {
				monitor.checkCanceled();
				Function constructor = constructors.next();
				if (!allDescendantConstructors.contains(constructor)) {
					allDescendantConstructors.add(constructor);
				}
			}
			allDescendantConstructors.addAll(getAllDescendantConstructors(childClass));
		}

		return allDescendantConstructors;
	}

	/**
	 * Method to retrieve all destructors of descendants of the given class
	 * @param recoveredClass the given class
	 * @return a list of all destructors of descendants of the given class
	 * @throws CancelledException if cancelled
	 */
	public List<Function> getAllDescendantDestructors(RecoveredClass recoveredClass)
			throws CancelledException {

		List<Function> allDescendantDestructors = new ArrayList<Function>();

		List<RecoveredClass> childClasses = recoveredClass.getChildClasses();
		Iterator<RecoveredClass> childClassIterator = childClasses.iterator();
		while (childClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass childClass = childClassIterator.next();

			List<Function> destructorList = new ArrayList<Function>(childClass.getDestructorList());
			destructorList.addAll(childClass.getInlinedDestructorList());
			Iterator<Function> destructors = destructorList.iterator();
			while (destructors.hasNext()) {
				monitor.checkCanceled();
				Function destructor = destructors.next();
				if (!allDescendantDestructors.contains(destructor)) {
					allDescendantDestructors.add(destructor);
				}
			}
			allDescendantDestructors.addAll(getAllDescendantDestructors(childClass));
		}

		return allDescendantDestructors;
	}

	/**
	 * Method to retrieve a list of possible parent class constructors to the given function
	 * @param function the given function
	 * @return a list of possible parent class constructors to the given function
	 * @throws CancelledException if cancelled
	 */
	public List<Function> getPossibleParentConstructors(Function function)
			throws CancelledException {

		List<Function> possibleParentConstructors = new ArrayList<Function>();

		List<ReferenceAddressPair> refAddrPairList = getCalledConstDestRefAddrPairs(function);

		List<Address> vftableReferenceList = getVftableReferences(function);
		if (vftableReferenceList == null) {
			return possibleParentConstructors;
		}

		Address minVftableReference = extraUtils.getMinimumAddressOnList(vftableReferenceList);
		Iterator<ReferenceAddressPair> iterator = refAddrPairList.iterator();

		while (iterator.hasNext()) {
			monitor.checkCanceled();
			ReferenceAddressPair refAddrPair = iterator.next();
			Address sourceAddr = refAddrPair.getSource();
			if (sourceAddr.compareTo(minVftableReference) < 0) {
				Function calledFunction = api.getFunctionAt(refAddrPair.getDestination());
				if (calledFunction != null) {
					possibleParentConstructors.add(calledFunction);
				}
			}
		}
		return possibleParentConstructors;
	}

	/**
	 * Method to retrieve a single common function on both lists
	 * @param list1 first list of functions
	 * @param list2 second list of functions
	 * @return single function if there is one function on both lists, null if there are none or 
	 * more than one
	 */
	public Function getFunctionOnBothLists(List<Function> list1, List<Function> list2) {

		List<Function> commonFunctions = getFunctionsOnBothLists(list1, list2);

		if (commonFunctions.size() == 1) {
			return commonFunctions.get(0);
		}
		// if none or more than one return null
		return null;
	}

	public List<Function> getFunctionsOnBothLists(List<Function> list1, List<Function> list2) {
		List<Function> commonFunctions =
			list1.stream().distinct().filter(list2::contains).collect(Collectors.toList());

		return commonFunctions;
	}

	/**
	 * Method to retrieve a set of functions contained in both of the given sets of functions
	 * @param set1 the first set of functions
	 * @param set2 the second set of functions
	 * @return a set of functions contained in both of the given sets of functions
	 */
	public Set<Function> getFunctionsContainedInBothSets(Set<Function> set1, Set<Function> set2) {
		Set<Function> commonFunctions =
			set1.stream().distinct().filter(set2::contains).collect(Collectors.toSet());

		return commonFunctions;

	}

	/**
	 * Method to retrieve a list of possible parent class destructors to the given function
	 * @param function the given function
	 * @return a list of possible parent class destructors to the given function
	 * @throws CancelledException if cancelled
	 */
	public List<Function> getPossibleParentDestructors(Function function)
			throws CancelledException {

		List<Function> possibleParentDestructors = new ArrayList<Function>();

		List<ReferenceAddressPair> refAddrPairList = getCalledConstDestRefAddrPairs(function);

		List<Address> vftableReferenceList = getVftableReferences(function);
		if (vftableReferenceList == null) {
			return possibleParentDestructors;
		}

		Address maxVftableReference = extraUtils.getMaximumAddressOnList(vftableReferenceList);
		Iterator<ReferenceAddressPair> iterator = refAddrPairList.iterator();

		while (iterator.hasNext()) {
			monitor.checkCanceled();
			ReferenceAddressPair refAddrPair = iterator.next();
			Address sourceAddr = refAddrPair.getSource();
			if (sourceAddr.compareTo(maxVftableReference) > 0) {
				Function calledFunction = extraUtils.getFunctionAt(refAddrPair.getDestination());
				if (calledFunction != null) {
					possibleParentDestructors.add(calledFunction);
				}
			}
		}
		return possibleParentDestructors;
	}

	/**
	 * Method to determine the constructors/destructors using known parent
	 * @param recoveredClass RecoveredClass object
	 * @param parentClass possible parent class of the given RecoveredClass
	 * @return true if processed successfully, else false
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issue setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	public boolean processConstructorsAndDestructorsUsingParent(RecoveredClass recoveredClass,
			RecoveredClass parentClass) throws CancelledException, InvalidInputException,
			DuplicateNameException, CircularDependencyException {

		if (parentClass == null) {
			return false;
		}

		Map<Function, Function> childParentConstructorMap = new HashMap<Function, Function>();
		Map<Function, Function> childParentDestructorMap = new HashMap<Function, Function>();

		List<Function> constDestFunctions =
			new ArrayList<Function>(recoveredClass.getConstructorOrDestructorFunctions());
		constDestFunctions.removeAll(recoveredClass.getIndeterminateInlineList());

		List<Function> parentConstDestFunctions = parentClass.getConstructorOrDestructorFunctions();

		List<Function> parentConstructors = getAllClassConstructors(parentClass);
		List<Function> parentDestructors = getAllClassDestructors(parentClass);
		List<Function> childConstructors = getAllClassConstructors(recoveredClass);
		List<Function> childDestructors = getAllClassDestructors(recoveredClass);

		Iterator<Function> constDestIterator = constDestFunctions.iterator();
		while (constDestIterator.hasNext()) {
			monitor.checkCanceled();

			Function constDestFunction = constDestIterator.next();

			// based on call order get possible parent constructors for the given function
			List<Function> possibleParentConstructors =
				getPossibleParentConstructors(constDestFunction);

			// remove any known destructors since they can't also be constructors - rarely these 
			// show up on possible const list
			possibleParentConstructors.removeAll(parentDestructors);

			Function parentConstructor =
				getFunctionOnBothLists(possibleParentConstructors, parentConstDestFunctions);

			// another sanity check - make sure child function isn't a known destructor
			if (parentConstructor != null && !childDestructors.contains(constDestFunction)) {
				childParentConstructorMap.put(constDestFunction, parentConstructor);
				continue;
			}

			// based on call order get possible parent destructors for the given function 
			List<Function> possibleParentDestructors =
				getPossibleParentDestructors(constDestFunction);

			// remove any known constructors since they can't also be destructors - rarely these 
			// show up on possible dest list
			possibleParentDestructors.removeAll(parentConstructors);

			Function parentDestructor =
				getFunctionOnBothLists(possibleParentDestructors, parentConstDestFunctions);

			// another sanity check - make sure child function isn't a known constructor			
			if (parentDestructor != null && !childConstructors.contains(constDestFunction)) {
				childParentDestructorMap.put(constDestFunction, parentDestructor);
				continue;
			}
		}

		// check to make sure there is no overlap in the poss c and poss d maps
		Set<Function> constructorKeySet = childParentConstructorMap.keySet();
		Set<Function> destructorKeySet = childParentDestructorMap.keySet();
		Set<Function> functionsContainedInBothSets =
			getFunctionsContainedInBothSets(constructorKeySet, destructorKeySet);

		if (functionsContainedInBothSets.size() > 0) {
			constructorKeySet.removeAll(functionsContainedInBothSets);
			destructorKeySet.removeAll(functionsContainedInBothSets);
			if (constructorKeySet.isEmpty() && destructorKeySet.isEmpty()) {
				return false;
			}
		}

		// once all checks pass, add both the child and parent constructors to their class 
		// constructor list and remove from the indeterminate lists
		// the addConstructor method processes the offsets and types for the initialized class data
		Iterator<Function> childConstructorIterator = constructorKeySet.iterator();
		while (childConstructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function childConstructor = childConstructorIterator.next();
			addConstructorToClass(recoveredClass, childConstructor);
			recoveredClass.removeIndeterminateConstructorOrDestructor(childConstructor);
			Function parentConstructor = childParentConstructorMap.get(childConstructor);
			addConstructorToClass(parentClass, parentConstructor);
			parentClass.removeIndeterminateConstructorOrDestructor(parentConstructor);
		}

		// Do the same for the child/parent destructors
		Iterator<Function> childDestructorIterator = destructorKeySet.iterator();
		while (childDestructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function childDestructor = childDestructorIterator.next();
			addDestructorToClass(recoveredClass, childDestructor);
			recoveredClass.removeIndeterminateConstructorOrDestructor(childDestructor);
			Function parentDestructor = childParentDestructorMap.get(childDestructor);
			addDestructorToClass(parentClass, parentDestructor);
			parentClass.removeIndeterminateConstructorOrDestructor(parentDestructor);
		}
		return true;

	}

	/**
	 * Method to retrieve all types of class destructors including normal destructors, non-this 
	 * destructors and inline destructors(does not include deleting destructors since they are 
	 * really a vfunction)
	 * @param recoveredClass the given class
	 * @return the list of all destructors for the given class
	 */
	public List<Function> getAllClassDestructors(RecoveredClass recoveredClass) {

		List<Function> allClassDestructors = new ArrayList<Function>();
		allClassDestructors.addAll(recoveredClass.getDestructorList());
		allClassDestructors.addAll(recoveredClass.getNonThisDestructors());
		allClassDestructors.addAll(recoveredClass.getInlinedDestructorList());

		return allClassDestructors;
	}

	/**
	 * Method to retrieve all types of class constructors including normal constructors and inline 
	 * constructors
	 * @param recoveredClass the given class
	 * @return the list of all constructors for the given class
	 */
	public List<Function> getAllClassConstructors(RecoveredClass recoveredClass) {

		List<Function> allClassConstructors = new ArrayList<Function>();

		allClassConstructors.addAll(recoveredClass.getConstructorList());
		allClassConstructors.addAll(recoveredClass.getInlinedConstructorList());

		return allClassConstructors;

	}

	/**
	 * Method to add constructor function to the given class and collect member data information
	 * @param recoveredClass given class
	 * @param constructorFunction given function
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if error setting return type
	 * @throws DuplicateNameException  if try to create same symbol name already in namespace
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	public void addConstructorToClass(RecoveredClass recoveredClass, Function constructorFunction)
			throws CancelledException, InvalidInputException, DuplicateNameException,
			CircularDependencyException {

		// skip if already a constructor for this class
		if (recoveredClass.getConstructorList().contains(constructorFunction)) {
			return;
		}

		// create vftable mapping for any class that didn't have a constructor when the
		// original mappings were created
		if (recoveredClass.getOrderToVftableMap().size() == 0) {
			createVftableOrderMapping(recoveredClass);
		}

		// If not already, make function a thiscall
		extraUtils.makeFunctionThiscall(constructorFunction);

		recoveredClass.addConstructor(constructorFunction);
		addToAllConstructors(constructorFunction);
	}

	/**
	 * Method to add inlined constructor function to the given class
	 * @param recoveredClass given class
	 * @param inlinedConstructorFunction given function
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace 
	 */
	public void addInlinedConstructorToClass(RecoveredClass recoveredClass,
			Function inlinedConstructorFunction)
			throws InvalidInputException, DuplicateNameException {

		//If not already, make function a thiscall
		extraUtils.makeFunctionThiscall(inlinedConstructorFunction);

		recoveredClass.addInlinedConstructor(inlinedConstructorFunction);
		addToAllInlinedConstructors(inlinedConstructorFunction);
	}

	/**
	 * Method to add destructor to the given class
	 * @param recoveredClass given class
	 * @param destructorFunction given destructor function
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace 
	 */
	public void addDestructorToClass(RecoveredClass recoveredClass, Function destructorFunction)
			throws InvalidInputException, DuplicateNameException {

		//If not already, make function a thiscall
		extraUtils.makeFunctionThiscall(destructorFunction);

		recoveredClass.addDestructor(destructorFunction);
		addToAllDestructors(destructorFunction);
	}

	/**
	 * Method to add inlined destructor to the given class
	 * @param recoveredClass given class
	 * @param inlinedDestructorFunction given function
	 * @throws InvalidInputException if error setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	public void addInlinedDestructorToClass(RecoveredClass recoveredClass,
			Function inlinedDestructorFunction)
			throws InvalidInputException, DuplicateNameException {

		//If not already, make function a thiscall
		extraUtils.makeFunctionThiscall(inlinedDestructorFunction);

		recoveredClass.addInlinedDestructor(inlinedDestructorFunction);
		addToAllInlinedDestructors(inlinedDestructorFunction);
	}

	/**
	 * Method to create a mapping between the order it appears and the vftable for the given class
	 * @param recoveredClass the given class
	 * @throws CancelledException if cancelled
	 */
	public void createVftableOrderMapping(RecoveredClass recoveredClass) throws CancelledException {

		if (!recoveredClass.hasVftable()) {
			return;
		}

		List<Address> vftableAddresses = recoveredClass.getVftableAddresses();

		Map<Integer, Address> classOffsetToVftableMap = recoveredClass.getClassOffsetToVftableMap();

		if (classOffsetToVftableMap.size() == 0) {
			return;
		}

		if (vftableAddresses.size() != classOffsetToVftableMap.size()) {
			if (DEBUG) {
				Msg.debug(this, recoveredClass.getName() + " has " + vftableAddresses.size() +
					" vftables but " + classOffsetToVftableMap.size() + " offset to vftable maps");
			}
		}

		List<Integer> offsetList = new ArrayList<Integer>(classOffsetToVftableMap.keySet());

		Collections.sort(offsetList);

		int order = 0;
		Iterator<Integer> offsetIterator = offsetList.iterator();
		while (offsetIterator.hasNext()) {
			monitor.checkCanceled();
			Integer offset = offsetIterator.next();
			Address vftableAddress = classOffsetToVftableMap.get(offset);
			recoveredClass.addOrderToVftableMapping(order, vftableAddress);
			order++;
		}
	}

	/**
	 * Method to create a map for each class between the order a vftable is seen in a class and the vftable itself
	 * @param recoveredClasses list of classes to processes
	 * @throws CancelledException if cancelled
	 */
	public void createVftableOrderMap(List<RecoveredClass> recoveredClasses)
			throws CancelledException {
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			// create a mapping of the order of the vftable to the vftable address and save to class
			createVftableOrderMapping(recoveredClass);
		}
	}

	/**
	 * 
	 * @param referenceToClassMap map of references to the class that contains the referenced function
	 * @param referencesToConstructors list of addresses referring to constructors
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if error setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	public void createListedConstructorFunctions(Map<Address, RecoveredClass> referenceToClassMap,
			List<Address> referencesToConstructors) throws CancelledException,
			InvalidInputException, DuplicateNameException, CircularDependencyException {

		Iterator<Address> constructorIterator = referencesToConstructors.iterator();
		while (constructorIterator.hasNext()) {
			monitor.checkCanceled();

			Address constructorReference = constructorIterator.next();
			RecoveredClass recoveredClass = referenceToClassMap.get(constructorReference);

			Function constructor = extraUtils.getReferencedFunction(constructorReference, true);

			if (recoveredClass.getIndeterminateList().contains(constructor)) {
				addConstructorToClass(recoveredClass, constructor);
				recoveredClass.removeIndeterminateConstructorOrDestructor(constructor);
				continue;
			}

			if (recoveredClass.getIndeterminateInlineList().contains(constructor)) {
				processInlineConstructor(recoveredClass, constructor, referenceToClassMap);
			}
		}
	}

	/**
	 * Method to process a found inlined constructor
	 * @param recoveredClass the class being processed
	 * @param inlinedConstructorFunction the function containing an inlined ancestor constructor
	 * @param referenceToClassMap the map of references to classes
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issue setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */

	public void processInlineConstructor(RecoveredClass recoveredClass,
			Function inlinedConstructorFunction, Map<Address, RecoveredClass> referenceToClassMap)
			throws CancelledException, InvalidInputException, DuplicateNameException,
			CircularDependencyException {

		if (referenceToClassMap.isEmpty()) {
			return;
		}

		List<Address> referencesToVftables = new ArrayList<Address>();

		List<Address> referenceAddresses = new ArrayList<Address>(referenceToClassMap.keySet());
		Iterator<Address> referenceIterator = referenceAddresses.iterator();
		while (referenceIterator.hasNext()) {
			monitor.checkCanceled();
			Address reference = referenceIterator.next();
			Address vftableAddress = getVftableAddress(reference);
			if (vftableAddress != null) {
				referencesToVftables.add(reference);
			}
		}

		if (referencesToVftables.isEmpty()) {
			return;
		}

		Collections.sort(referencesToVftables);

		int numRefs = referencesToVftables.size();
		Address lastRef = referencesToVftables.get(numRefs - 1);

		Iterator<Address> refToVtablesIterator = referencesToVftables.iterator();
		while (refToVtablesIterator.hasNext()) {
			monitor.checkCanceled();
			Address refToVftable = refToVtablesIterator.next();
			RecoveredClass referencedClass = referenceToClassMap.get(refToVftable);

			// last reference is the constructor
			if (refToVftable.equals(lastRef)) {
				addConstructorToClass(referencedClass, inlinedConstructorFunction);
			}
			// the rest are inlined constructors
			else {
				addInlinedConstructorToClass(referencedClass, inlinedConstructorFunction);

			}
			referencedClass.removeIndeterminateInline(inlinedConstructorFunction);
		}

		return;

	}

	/**
	 * Method to process an inlinedDestructor function
	 * @param recoveredClass the class the inlinedDestructor is in
	 * @param inlinedDestructorFunction the inlined function
	 * @param referenceToClassMap the map of references to classes
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issue setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	public void processInlineDestructor(RecoveredClass recoveredClass,
			Function inlinedDestructorFunction, Map<Address, RecoveredClass> referenceToClassMap)
			throws CancelledException, InvalidInputException, DuplicateNameException {

		if (referenceToClassMap.isEmpty()) {
			return;
		}

		List<Address> referencesToVftables = new ArrayList<Address>();

		List<Address> referenceAddresses = new ArrayList<Address>(referenceToClassMap.keySet());
		Iterator<Address> referenceIterator = referenceAddresses.iterator();
		while (referenceIterator.hasNext()) {
			monitor.checkCanceled();
			Address reference = referenceIterator.next();
			Address vftableAddress = getVftableAddress(reference);
			if (vftableAddress != null) {
				referencesToVftables.add(reference);
			}
		}

		if (referencesToVftables.isEmpty()) {
			return;
		}

		// reverse sort
		Collections.sort(referencesToVftables, Collections.reverseOrder());

		int numRefs = referencesToVftables.size();
		Address lastRef = referencesToVftables.get(numRefs - 1);

		Iterator<Address> refToVtablesIterator = referencesToVftables.iterator();
		while (refToVtablesIterator.hasNext()) {
			monitor.checkCanceled();
			Address refToVftable = refToVtablesIterator.next();
			RecoveredClass referencedClass = referenceToClassMap.get(refToVftable);

			// last reference is the constructor
			if (refToVftable.equals(lastRef)) {
				addDestructorToClass(referencedClass, inlinedDestructorFunction);
			}
			// the rest are inlined constructors
			else {
				addInlinedDestructorToClass(referencedClass, inlinedDestructorFunction);

			}
			referencedClass.removeIndeterminateInline(inlinedDestructorFunction);
		}

		return;

	}

	/**
	 * Method to get the address that references the first vftable in the given function
	 * @param function the given function
	 * @return the address in the given function that references the first referenced vftable or 
	 * null if no vftable is referenced in the given function 
	 */
	public Address getFirstVftableReferenceInFunction(Function function) {

		List<Address> vftableReferenceList = getVftableReferences(function);

		Collections.sort(vftableReferenceList);

		return vftableReferenceList.get(0);

	}

	/**
	 * Method to make the given function a thiscall
	 * @param function the given function
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	public void makeFunctionThiscall(Function function)
			throws InvalidInputException, DuplicateNameException {

		if (function.getCallingConventionName().equals("__thiscall")) {
			return;
		}

		ReturnParameterImpl returnType =
			new ReturnParameterImpl(function.getSignature().getReturnType(), program);

		function.updateFunction("__thiscall", returnType,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, function.getSignatureSource(),
			function.getParameters());
	}

	/**
	 * Method to determine if the given function calls a known constructor or inlined constructor
	 * @param function the given function
	 * @return true if function calls a known constructor or inlined constructor, false otherwise
	 * @throws CancelledException if cancelled
	 */
	public boolean callsKnownConstructor(Function function) throws CancelledException {

		List<ReferenceAddressPair> calledFunctionRefAddrPairs =
			getCalledConstDestRefAddrPairs(function);

		Iterator<ReferenceAddressPair> calledFunctionIterator =
			calledFunctionRefAddrPairs.iterator();
		while (calledFunctionIterator.hasNext()) {

			monitor.checkCanceled();

			ReferenceAddressPair referenceAddressPair = calledFunctionIterator.next();

			Address calledFunctionAddress = referenceAddressPair.getDestination();
			Function calledFunction = extraUtils.getFunctionAt(calledFunctionAddress);

			if (calledFunction.isThunk()) {
				calledFunction = calledFunction.getThunkedFunction(true);
			}

			if (getAllConstructors().contains(calledFunction) ||
				getAllInlinedConstructors().contains(calledFunction)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method to determine if the given function calls a known constructor or inlined constructor
	 * @param function the given function
	 * @return true if function calls a known constructor or inlined constructor, false otherwise
	 * @throws CancelledException if cancelled
	 */
	public boolean callsKnownDestructor(Function function) throws CancelledException {

		List<ReferenceAddressPair> calledFunctionRefAddrPairs =
			getCalledConstDestRefAddrPairs(function);

		Iterator<ReferenceAddressPair> calledFunctionIterator =
			calledFunctionRefAddrPairs.iterator();
		while (calledFunctionIterator.hasNext()) {

			monitor.checkCanceled();

			ReferenceAddressPair referenceAddressPair = calledFunctionIterator.next();

			Address calledFunctionAddress = referenceAddressPair.getDestination();
			Function calledFunction = extraUtils.getFunctionAt(calledFunctionAddress);

			if (calledFunction.isThunk()) {
				calledFunction = calledFunction.getThunkedFunction(true);
			}

			if (getAllDestructors().contains(calledFunction) ||
				getAllInlinedDestructors().contains(calledFunction)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method to get the total number of constructors in the given list of classes
	 * @param recoveredClasses list of classes to process
	 * @return number of constructor functions in all classes
	 * @throws CancelledException if cancelled
	 */
	public int getNumberOfConstructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();
			List<Function> constructorList = recoveredClass.getConstructorList();
			total += constructorList.size();
		}
		return total;
	}

	/**
	 * Method to return the total number of destructors in the given list of classes
	 * @param recoveredClasses the list of classes
	 * @return the total number of destructors in the given list of classes
	 * @throws CancelledException if cancelled
	 */
	public int getNumberOfDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();

			int numDestructors = recoveredClass.getDestructorList().size();
			total += numDestructors;
		}
		return total;
	}

	/**
	 * Method to return the total number of inlined destructors in the given list of classes
	 * @param recoveredClasses the list of classes
	 * @return the total number of inlined destructors in the given list of classes
	 * @throws CancelledException if cancelled
	 */
	public int getNumberOfInlineDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();

			int numInlinedDestructors = recoveredClass.getInlinedDestructorList().size();
			total += numInlinedDestructors;
		}
		return total;
	}

	/**
	 * Method to get the total number of deleting destructors in the given list of classes 
	 * @param recoveredClasses the list of classes
	 * @return the total number of deleting destructors in the given list of classes
	 * @throws CancelledException if cancelled
	 */
	public int getNumberOfDeletingDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();

			List<Function> deletingDestructors = recoveredClass.getDeletingDestructors();
			total += deletingDestructors.size();
		}
		return total;
	}

	/**
	 * Method to retrieve the total number of clone functions assigned to all the classes 
	 * @param recoveredClasses List of classes
	 * @return total number of clone functions assigned to classes
	 * @throws CancelledException if cancelled
	 */
	public int getNumberOfCloneFunctions(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();
			List<Function> cloneFunctions = recoveredClass.getCloneFunctions();
			total += cloneFunctions.size();
		}
		return total;
	}

	/**
	 * Method to return the total number of vbase destructors in the given list of classes
	 * @param recoveredClasses the list of classes
	 * @return the the total number of vbase destructors in the given list of classes
	 * @throws CancelledException if cancelled
	 */
	public int getNumberOfVBaseFunctions(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();

			Function cloneFunction = recoveredClass.getVBaseDestructor();
			if (cloneFunction != null) {
				total++;
			}
		}
		return total;
	}

	/**
	 * Method to get the total number of virtual functions (or functions that inherit from virtual functions) in the given list of classes
	 * @param recoveredClasses the list of classes
	 * @return the total number of virtual functions (or functions that inherit from virtual functions) in the given list of classes
	 * @throws CancelledException if cancelled
	 */
	public int getNumberOfVirtualFunctions(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();

			List<Function> vfunctionList = recoveredClass.getAllVirtualFunctions();
			if (vfunctionList == null) {
				continue;
			}

			total += vfunctionList.size();

		}
		return total;
	}

	/**
	 * Method to get a list of functions from the list of classes that could not be determined whether they
	 * were constructors or destructors 
	 * @param recoveredClasses the list of classes
	 * @return list of functions from the list of classes that could not be determined whether they
	 * were constructors or destructors 
	 * @throws CancelledException if cancelled
	 */
	public List<Function> getRemainingIndeterminates(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		List<Function> remainingIndeterminates = new ArrayList<Function>();
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();

			List<Function> indeterminateConstructorOrDestructorList =
				recoveredClass.getIndeterminateList();
			remainingIndeterminates.addAll(indeterminateConstructorOrDestructorList);

			List<Function> indeterminateInlines = recoveredClass.getIndeterminateInlineList();
			remainingIndeterminates.addAll(indeterminateInlines);

		}
		return remainingIndeterminates;
	}

	/**
	 * 
	 * @param referenceToClassMap map from reference to class the referenced function is in
	 * @param referencesToDestructors list of addresses referring to destructors
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if error setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	public void createListedDestructorFunctions(Map<Address, RecoveredClass> referenceToClassMap,
			List<Address> referencesToDestructors)
			throws CancelledException, InvalidInputException, DuplicateNameException {

		Iterator<Address> destructorIterator = referencesToDestructors.iterator();
		while (destructorIterator.hasNext()) {
			monitor.checkCanceled();

			Address destructorReference = destructorIterator.next();
			RecoveredClass recoveredClass = referenceToClassMap.get(destructorReference);

			Function destructor = extraUtils.getReferencedFunction(destructorReference, true);

			if (recoveredClass.getIndeterminateList().contains(destructor)) {
				addDestructorToClass(recoveredClass, destructor);
				recoveredClass.removeIndeterminateConstructorOrDestructor(destructor);
				continue;
			}

			if (recoveredClass.getIndeterminateInlineList().contains(destructor)) {
				processInlineDestructor(recoveredClass, destructor, referenceToClassMap);
			}
		}
	}

	/**
	 * Method to use existing pdb names to assign class constructors and destructors
	 * @param recoveredClasses List of classes
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if error setting return type
	 * @throws CancelledException if cancelled
	 */
	public void assignConstructorsAndDestructorsUsingExistingName(
			List<RecoveredClass> recoveredClasses) throws CancelledException, InvalidInputException,
			DuplicateNameException, CircularDependencyException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<Function> indeterminateFunctions = recoveredClass.getIndeterminateList();
			Iterator<Function> functionIterator = indeterminateFunctions.iterator();
			while (functionIterator.hasNext()) {

				monitor.checkCanceled();

				Function function = functionIterator.next();
				Namespace namespace = function.getParentNamespace();
				if (!namespace.equals(recoveredClass.getClassNamespace())) {
					continue;
				}
				String name = function.getName();
				if (name.equals(recoveredClass.getName())) {
					addConstructorToClass(recoveredClass, function);
					functionIterator.remove();
					continue;
				}
				if (name.equals("~" + recoveredClass.getName())) {
					addDestructorToClass(recoveredClass, function);
					functionIterator.remove();
					continue;
				}
			}

		}
	}

	/**
	 * Method to determine if a class's identified vbase_destructor is valid or not
	 * If the class has both a vbase destructor and a regular destructor and the class has
	 * a non-virtual ancestor, and either the class is the lowest child or has a child with a 
	 * vbase_destructor then it is a valid vbase_destructor. Otherwise, it isn't.
	 * @param recoveredClass the given class object
	 * @return true if class has a vbase destructor, false if not 
	 */
	private boolean hasVbaseDestructor(RecoveredClass recoveredClass) throws CancelledException {
		Function vBaseDestructor = recoveredClass.getVBaseDestructor();

		StringBuffer string = new StringBuffer();
		string.append(recoveredClass.getName());

		if (vBaseDestructor == null) {
			return false;
		}
		if (recoveredClass.getDestructorList().size() != 1) {
			return false;
		}

		if (!hasNonVirtualFunctionAncestor(recoveredClass)) {
			return false;
		}

		if (!recoveredClass.hasChildClass() || hasChildWithVBaseAndDestructor(recoveredClass)) {
			return true;
		}
		return false;
	}

	/**
	 * Method to determine if the given class has a child class with both a vbase destructor and a 
	 * regular destructor
	 * @param recoveredClass the given class
	 * @return true if the given class has a child class with both a vbase destructor and a regular 
	 * destructor, false otherwise
	 * @throws CancelledException if cancelled
	 */
	public boolean hasChildWithVBaseAndDestructor(RecoveredClass recoveredClass)
			throws CancelledException {
		if (recoveredClass.hasChildClass()) {
			List<RecoveredClass> childClasses = recoveredClass.getChildClasses();
			Iterator<RecoveredClass> childIterator = childClasses.iterator();
			while (childIterator.hasNext()) {
				monitor.checkCanceled();
				RecoveredClass childClass = childIterator.next();
				if (childClass.getDestructorList().size() == 1 &&
					childClass.getVBaseDestructor() != null) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Method to create a new recovered class object and add it to the namespaceToClassMap
	 * @param namespace the namespace to put the new class in
	 * @param hasVftable true if class has at least one vftable, false otherwise
	 * @return the RecoveredClass object
	 * @throws CancelledException if cancelled
	 */
	public RecoveredClass createNewClass(Namespace namespace, boolean hasVftable)
			throws CancelledException {

		String className = namespace.getName();
		String classNameWithNamespace = namespace.getName(true);

		CategoryPath classPath = extraUtils.createDataTypeCategoryPath(classDataTypesCategoryPath,
			classNameWithNamespace);

		RecoveredClass newClass =
			new RecoveredClass(className, classPath, namespace, dataTypeManager);
		newClass.setHasVftable(hasVftable);

		updateNamespaceToClassMap(namespace, newClass);
		return newClass;

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
	 * @param vftableSymbolList List of vftable symbols
	 * @param allowNullFunctionPtrs if true, allow existance of null pointers in vftable
	 * @param allowDefaultRefsInMiddle if true, allow existance of default refs into the middle of a vftable
	 * @return List of RecoveredClass objects created corresponding to the vftable symbols
	 * @throws CancelledException if cancelled
	 * @throws Exception if issues getting data
	 */
	List<RecoveredClass> recoverClassesFromVftables(List<Symbol> vftableSymbolList,
			boolean allowNullFunctionPtrs, boolean allowDefaultRefsInMiddle)
			throws CancelledException, Exception {

		List<RecoveredClass> recoveredClasses = new ArrayList<RecoveredClass>();

		Iterator<Symbol> vftableSymbolsIterator = vftableSymbolList.iterator();
		while (vftableSymbolsIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol vftableSymbol = vftableSymbolsIterator.next();
			Address vftableAddress = vftableSymbol.getAddress();

			// Get class name from class vftable is in
			Namespace vftableNamespace = vftableSymbol.getParentNamespace();
			if (vftableNamespace.equals(globalNamespace)) {
				if (DEBUG) {
					Msg.debug(this,
						"vftable is in the global namespace, ie not in a class namespace, so cannot process");
				}
				continue;
			}

			// get only the functions from the ones that are not already processed structures
			// return null if not an unprocessed table
			List<Function> virtualFunctions = getFunctionsFromVftable(vftableAddress, vftableSymbol,
				allowNullFunctionPtrs, allowDefaultRefsInMiddle);

			// the vftable has already been processed - skip it
			if (virtualFunctions == null) {
				continue;
			}

			// Check to see if already have an existing RecoveredClass object for the
			// class associated with the current vftable. 
			RecoveredClass recoveredClass = getClass(vftableNamespace);

			if (recoveredClass == null) {
				// Create a RecoveredClass object for the current class
				recoveredClass = createNewClass(vftableNamespace, true);
				recoveredClass.addVftableAddress(vftableAddress);
				recoveredClass.addVftableVfunctionsMapping(vftableAddress, virtualFunctions);

				// add it to the running list of RecoveredClass objects
				recoveredClasses.add(recoveredClass);
			}
			else {
				recoveredClass.addVftableAddress(vftableAddress);
				recoveredClass.addVftableVfunctionsMapping(vftableAddress, virtualFunctions);
				if (!recoveredClasses.contains(recoveredClass)) {
					recoveredClasses.add(recoveredClass);
				}

			}

			// add it to the vftableAddress to Class map
			updateVftableToClassMap(vftableAddress, recoveredClass);

			List<Address> referencesToVftable = getReferencesToVftable(vftableAddress);
			addReferenceToVtableMapping(referencesToVftable, vftableAddress);

			Map<Address, Function> vftableReferenceToFunctionMapping =
				createVftableReferenceToFunctionMapping(referencesToVftable);

			//vftableReferenceToFunctionMapping
			List<Function> possibleConstructorDestructorsForThisClass =
				findPossibleConstructorDestructors(vftableReferenceToFunctionMapping);

			addFunctionsToClassMapping(possibleConstructorDestructorsForThisClass, recoveredClass);

			// add the vftable reference to function mapping to the global list
			addFunctionToVftableReferencesMapping(vftableReferenceToFunctionMapping);

			// add the possible constructor/destructor list to the class
			recoveredClass.addConstructorDestructorList(possibleConstructorDestructorsForThisClass);
			recoveredClass.addIndeterminateConstructorOrDestructorList(
				possibleConstructorDestructorsForThisClass);

			// Add them to the list of all constructors and destructors in program			
			updateAllConstructorsAndDestructorsList(possibleConstructorDestructorsForThisClass);

		} // end of looping over vfTables
		return recoveredClasses;
	}

	public void promoteClassNamespaces(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = classIterator.next();
			Namespace classNamespace = recoveredClass.getClassNamespace();
			promoteNamespaces(classNamespace);
		}
	}

	private boolean promoteNamespaces(Namespace namespace) throws CancelledException {

		while (!namespace.isGlobal()) {

			monitor.checkCanceled();
			SymbolType namespaceType = namespace.getSymbol().getSymbolType();
			// if it is a namespace but not a class and it is in our namespace map (which makes
			// it a valid class) we need to promote it to a class namespace
			if (namespaceType != SymbolType.CLASS && namespaceType == SymbolType.NAMESPACE &&
				namespaceToClassMap.get(namespace) != null) {

				namespace = promoteToClassNamespace(namespace);
				if (namespace == null) {
					return false;
				}
				//if (DEBUG) {
				Msg.debug(this,
					"Promoted namespace " + namespace.getName(true) + " to a class namespace");
				//}
			}
			else {
				namespace = namespace.getParentNamespace();
			}
		}
		return true;
	}

	/**
	 * Method to promote the namespace is a class namespace. 
	 * @return true if namespace is (now) a class namespace or false if it could not be promoted.
	 */
	private Namespace promoteToClassNamespace(Namespace namespace) {

		SymbolType symbolType = namespace.getSymbol().getSymbolType();
		if (symbolType == SymbolType.CLASS) {
			return namespace;
		}

		if (symbolType != SymbolType.NAMESPACE) {
			return namespace;
		}

		try {
			Namespace newClass = NamespaceUtils.convertNamespaceToClass(namespace);

			SymbolType newSymbolType = newClass.getSymbol().getSymbolType();
			if (newSymbolType == SymbolType.CLASS) {
				return newClass;
			}
			if (DEBUG) {
				Msg.debug(this,
					"Could not promote " + namespace.getName() + " to a class namespace");
			}
			return null;
		}
		catch (InvalidInputException e) {

			Msg.debug(this, "Could not promote " + namespace.getName() +
				" to a class namespace because " + e.getMessage());
			return null;
		}
	}

	/**
	 * Method to create mapping to possible constructor/destructor functions
	 * @param referencesToVftable list of references to a particular vftable
	 * @return Map of reference to vftable to the function it is in
	 * @throws CancelledException if cancelled
	 */
	private Map<Address, Function> createVftableReferenceToFunctionMapping(
			List<Address> referencesToVftable) throws CancelledException {

		Map<Address, Function> vftableRefToFunctionMapping = new HashMap<Address, Function>();
		Iterator<Address> referencesIterator = referencesToVftable.iterator();
		while (referencesIterator.hasNext()) {
			monitor.checkCanceled();
			Address vftableReference = referencesIterator.next();
			Function functionContaining = extraUtils.getFunctionContaining(vftableReference);
			if (functionContaining != null) {
				vftableRefToFunctionMapping.put(vftableReference, functionContaining);
			}
		}
		return vftableRefToFunctionMapping;
	}

	/**
	 * Method to generate a list of constructors and destructors given the mapping of the
	 * vftable to the functions that reference it
	 * @param vftableReferenceToFunctionMapping the mapping of vftable to the functions that reference the vftable
	 * @return a list of possible constructors or destructors using the given mapping
	 * @throws CancelledException if cancelled
	 */
	private List<Function> findPossibleConstructorDestructors(
			Map<Address, Function> vftableReferenceToFunctionMapping) throws CancelledException {

		List<Function> cdFunctions = new ArrayList<Function>();
		Set<Address> keySet = vftableReferenceToFunctionMapping.keySet();
		Iterator<Address> referencesIterator = keySet.iterator();
		while (referencesIterator.hasNext()) {
			monitor.checkCanceled();
			Address vtableReference = referencesIterator.next();
			Function function = vftableReferenceToFunctionMapping.get(vtableReference);
			if (!cdFunctions.contains(function)) {
				cdFunctions.add(function);
			}
		}
		return cdFunctions;
	}

	/**
	 * Method to get functions from vftable
	 * @param vftableAddress the address of the vftable
	 * @param vftableSymbol the name of the vftable
	 * @param allowNullFunctionPtrs if true, allow null pointers in table
	 * @param allowDefaultRefsInMiddle if true, allow references in middle of table
	 * @return the list of functions in the vftable
	 * @throws CancelledException if cancelled
	 * @throws Exception if issues getting data
	 */
	public List<Function> getFunctionsFromVftable(Address vftableAddress, Symbol vftableSymbol,
			boolean allowNullFunctionPtrs, boolean allowDefaultRefsInMiddle)
			throws CancelledException, Exception {

		List<Function> virtualFunctionList = new ArrayList<Function>();
		Data vftableData = program.getListing().getDefinedDataAt(vftableAddress);

		// now make sure the array or the structure is all pointers
		if (!extraUtils.isArrayOrStructureOfAllPointers(vftableData)) {
			// if it isn't an array of pointers then we don't know the size of the vftable
			// If undefined or pointers not in array or struct then see if what they are
			// pointing to are in the class already to determine size of array

			// create vtable
			int numFunctionPointers =
				createVftable(vftableAddress, allowNullFunctionPtrs, allowDefaultRefsInMiddle);
			if (numFunctionPointers == 0) {
				return null;
			}
			// make it an array
			vftableData = createVftableArray(vftableAddress, numFunctionPointers);
			if (vftableData == null) {
				return null;
			}
		}

		// if there is already a structure created there and it is
		// contained in the ClassDataTypes folder then it has already been processed so skip it
		// TODO: can this be checked using the folderpath not the folder name?
		if (vftableData.isStructure()) {
			String[] pathElements = vftableData.getDataType().getCategoryPath().getPathElements();
			if ((pathElements.length > 0) && (pathElements[0].equals(DTM_CLASS_DATA_FOLDER_NAME))) {
				return null;
			}
		}

		// Loop over the pointers in the vftable and add the pointed to functions to the list
		int numPointers = vftableData.getNumComponents();

		for (int i = 0; i < numPointers; ++i) {
			monitor.checkCanceled();

			Address functionPointerAddress = vftableData.getComponent(i).getAddress();
			if (allowNullFunctionPtrs && extraUtils.isNullPointer(functionPointerAddress)) {
				virtualFunctionList.add(null);
				continue;
			}

			Function function = extraUtils.getPointedToFunction(functionPointerAddress);

			if (function != null) {
				virtualFunctionList.add(function);
			}

		}
		return virtualFunctionList;

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
	 * Method to create an array of pointers at the given vftable address
	 * @param vftableAddress the vftable address
	 * @param allowNullFunctionPtrs if true allow vftables to have null pointers
	 * @param allowDefaultRefsInMiddle if true allow default references into the middle of the table
	 * @return the created array of pointers Data or null
	 * @throws CancelledException if cancelled
	 */
	private int createVftable(Address vftableAddress, boolean allowNullFunctionPtrs,
			boolean allowDefaultRefsInMiddle) throws CancelledException {

		int numFunctionPointers = 0;
		Address address = vftableAddress;
		MemoryBlock currentBlock = program.getMemory().getBlock(vftableAddress);

		boolean stillInCurrentTable = true;
		while (address != null && currentBlock.contains(address) && stillInCurrentTable &&
			extraUtils.isFunctionPointer(address, allowNullFunctionPtrs)) {
			numFunctionPointers++;
			address = address.add(defaultPointerSize);
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
			if (symbol == null) {
				continue;
			}
			// never let non-default refs
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
	 * Method to find references to vftables that are not in functions, either in undefined areas or 
	 * instructions that are not in functions. 
	 * @param vftableSymbols List of vftable symbols
	 * @return List of addresses where vftables are referenced but are not in a function
	 * @throws CancelledException when cancelled
	 */
	public List<Address> findVftableReferencesNotInFunction(List<Symbol> vftableSymbols)
			throws CancelledException {

		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Vftable References");

		AddressSet searchSet = new AddressSet();
		AddressSetView executeSet = program.getMemory().getExecuteSet();
		AddressRangeIterator addressRanges = executeSet.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCanceled();
			AddressRange addressRange = addressRanges.next();
			searchSet.add(addressRange.getMinAddress(), addressRange.getMaxAddress());
		}

		List<Address> vftableAddresses = new ArrayList<Address>();

		List<Address> notInFunctionVftableRefs = new ArrayList<Address>();
		List<Address> newFunctions = new ArrayList<Address>();

		Iterator<Symbol> vftableSymbolIterator = vftableSymbols.iterator();
		while (vftableSymbolIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol vftableSymbol = vftableSymbolIterator.next();
			Address vftableAddress = vftableSymbol.getAddress();
			vftableAddresses.add(vftableAddress);

			// check direct refs to see if they are in undefined area or not in function
			byte[] bytes = ProgramMemoryUtil.getDirectAddressBytes(program, vftableAddress);

			addByteSearchPattern(searcher, notInFunctionVftableRefs, newFunctions, vftableAddress,
				bytes, monitor);

		}

		searcher.search(program, searchSet, monitor);

		// check existing refs to see if in instruction but not in function
		Iterator<Address> vftableAddressIterator = vftableAddresses.iterator();
		while (vftableAddressIterator.hasNext()) {
			monitor.checkCanceled();

			Address vftableAddress = vftableAddressIterator.next();

			ReferenceIterator referencesIterator =
				program.getReferenceManager().getReferencesTo(vftableAddress);

			while (referencesIterator.hasNext()) {
				monitor.checkCanceled();

				Reference reference = referencesIterator.next();
				Address vftableReference = reference.getFromAddress();
				Function functionContaining =
					program.getListing().getFunctionContaining(vftableReference);

				if (functionContaining == null) {

					Instruction instructionContaining =
						program.getListing().getInstructionContaining(vftableReference);
					if (instructionContaining != null) {
						boolean functionCreated =
							extraUtils.createFunction(program, vftableReference);

						if (!functionCreated) {
							notInFunctionVftableRefs.add(vftableReference);

						}

					}
				}
			}
		}

		return notInFunctionVftableRefs;
	}

	/**
	 * Method to add a search pattern, to the searcher, for the set of bytes representing a vftable 
	 * address
	 * @param searcher the MemoryBytePatternSearcher
	 * @param notInFunctionVftableRefs a list addresses of vftable references that are not contained 
	 * in a function
	 * @param newFunctions a list of newly created functions that reference the given vftable address
	 * @param vftableAddress the given vftable address
	 * @param bytes the bytes to search for
	 * @param taskMonitor a cancellable monitor
	 */
	private void addByteSearchPattern(MemoryBytePatternSearcher searcher,
			List<Address> notInFunctionVftableRefs, List<Address> newFunctions,
			Address vftableAddress, byte[] bytes, TaskMonitor taskMonitor) {

		// no pattern bytes.
		if (bytes == null) {
			return;
		}

		// Each time a match for this byte pattern ...
		GenericMatchAction<Address> action = new GenericMatchAction<Address>(vftableAddress) {
			@Override
			public void apply(Program prog, Address addr, Match match) {

				Function functionContainingVftable = prog.getListing().getFunctionContaining(addr);

				Data dataAt = prog.getListing().getDefinedDataContaining(addr);

				Instruction instructionContainingAddr =
					prog.getListing().getInstructionContaining(addr);

				// check the direct references found with the searcher
				// if not in function but is an instruction then create the function
				// otherwise, add to the list to report to user
				if (functionContainingVftable == null && dataAt == null) {
					if (instructionContainingAddr == null) {
						notInFunctionVftableRefs.add(addr);
					}
					else {
						boolean functionCreated =
							extraUtils.createFunction(prog, addr);
						if (!functionCreated) {
							notInFunctionVftableRefs.add(addr);
						}
					}
				}
			}

		};

		// create a Pattern of the bytes and the MatchAction to perform upon a match
		GenericByteSequencePattern<Address> genericByteMatchPattern =
			new GenericByteSequencePattern<>(bytes, action);

		searcher.addPattern(genericByteMatchPattern);

	}

	/**
	 * Method to create a string buffer containing class parents in the correct order. The format
	 * of the parent string is of the format "class <class_name> : <parent1_spec> : <parent2_spec> ...
	 * where parentN_spec = "virtual (only if inherited virtually) <parentN_name>"
	 * Examples: 
	 * The class Pet with no parents would be "class Pet"
	 * The class Cat with non-virtual parent Pet would be "class Cat : Pet"
	 * The class A with virtual parent B and non-virtual parent C would be "class A : virtual B : C"
	 * @param recoveredClass the given class
	 * @return StringBuffer containing class parent description
	 * @throws CancelledException if cancelled
	 */
	public StringBuffer createParentStringBuffer(RecoveredClass recoveredClass)
			throws CancelledException {

		StringBuffer parentStringBuffer = new StringBuffer();
		String classString = recoveredClass.getName();

		if (recoveredClass.hasParentClass()) {

			// use this to get direct  parents
			Map<RecoveredClass, List<RecoveredClass>> classHierarchyMap =
				recoveredClass.getClassHierarchyMap();
			Set<RecoveredClass> directParents = classHierarchyMap.keySet();

			// use this to get correct parent order and to get the type of parent
			Map<RecoveredClass, Boolean> parentToBaseTypeMap =
				recoveredClass.getParentToBaseTypeMap();
			Set<RecoveredClass> ancestors = parentToBaseTypeMap.keySet();
			Iterator<RecoveredClass> ancestorIterator = ancestors.iterator();
			while (ancestorIterator.hasNext()) {
				monitor.checkCanceled();
				RecoveredClass ancestor = ancestorIterator.next();
				if (directParents.contains(ancestor)) {

					Boolean isVirtualParent = parentToBaseTypeMap.get(ancestor);
					if (isVirtualParent != null && isVirtualParent) {
						classString = classString.concat(" : virtual " + ancestor.getName());
					}
					else {
						classString = classString.concat(" : " + ancestor.getName());
					}
				}
			}
		}
		parentStringBuffer.append("class " + classString);
		return parentStringBuffer;
	}

	/**
	 * Method to determine if all data for the ancestors of the given class have been created
	 * @param recoveredClass the given class
	 * @return true if all data for the ancestors of the given class have been created, false otherwise
	 * @throws CancelledException if cancelled
	 * @throws Exception if class hierarchy list has not been populated
	 */
	public boolean allAncestorDataHasBeenCreated(RecoveredClass recoveredClass)
			throws CancelledException, Exception {

		List<RecoveredClass> parentClasses = recoveredClass.getClassHierarchy();

		if (parentClasses.isEmpty()) {
			throw new Exception(
				recoveredClass.getClassNamespace().getName(true) +
					" should not have an empty class hierarchy");
		}

		// if size one it only includes self
		if (parentClasses.size() == 1) {
			return true;
		}

		Iterator<RecoveredClass> parentIterator = parentClasses.listIterator(1);
		while (parentIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass parentClass = parentIterator.next();

			if (getClassStructureFromDataTypeManager(parentClass) == null) {
				return false;
			}

		}
		return true;

	}

	/**
	 * Method to retrieve the given class's class structure from the data type manager
	 * @param recoveredClass the given class
	 * @return the given class's class structure from the data type manager
	 */
	public Structure getClassStructureFromDataTypeManager(RecoveredClass recoveredClass) {

		DataType classDataType =
			dataTypeManager.getDataType(recoveredClass.getClassPath(), recoveredClass.getName());

		if (classDataType != null && classDataType instanceof Structure) {
			Structure classStructure = (Structure) classDataType;
			return classStructure;
		}

		return null;

	}

	/**
	 * Method to name class constructors and add them to class namespace
	 * @param recoveredClass current class
	 * @param classStruct the given class structure
	 * @throws Exception when cancelled
	 */
	public void addConstructorsToClassNamespace(RecoveredClass recoveredClass,
			Structure classStruct) throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();
		String className = recoveredClass.getName();

		List<Function> constructorList = recoveredClass.getConstructorList();
		Iterator<Function> constructorsIterator = constructorList.iterator();

		while (constructorsIterator.hasNext()) {
			monitor.checkCanceled();
			Function constructorFunction = constructorsIterator.next();

			createNewSymbolAtFunction(constructorFunction, className, classNamespace, true, true);

			// check to see if the "this" data type is an empty placeholder for the class
			// structure and replace it with the one that was just created by the script
			//deleteEmptyClassStructure(constructorFunction, className);
			replaceEmptyClassStructure(constructorFunction, className, classStruct);

			// if current decompiler function return type is a pointer then set the return type
			// to a pointer to the class structure, otherwise if it is a void, make it a void so the
			// listing has void too, otherwise, leave it as is, probably a void
			String returnType = getReturnTypeFromDecompiler(constructorFunction);

			if (returnType.equals("void")) {
				DataType voidDataType = new VoidDataType();
				constructorFunction.setReturnType(voidDataType, SourceType.ANALYSIS);
			}
			else if (returnType.contains("*")) {
				DataType classPointerDataType = dataTypeManager.getPointer(classStruct);
				constructorFunction.setReturnType(classPointerDataType, SourceType.ANALYSIS);
			}

		}
	}

	/**
	 * Get the return value from the decompiler signature for the given function
	 * @param function the given function
	 * @return the decompiler return value for the given function
	 */
	private String getReturnTypeFromDecompiler(Function function) {

		DataType decompilerReturnType = decompilerUtils.getDecompilerReturnType(function);

		if (decompilerReturnType == null) {
			return null;
		}

		return decompilerReturnType.getDisplayName();
	}

	/**
	 * Method to name class destructors and add them to class namespace
	 * @param recoveredClass current class
	 * @throws Exception when cancelled
	 */
	public void addDestructorsToClassNamespace(RecoveredClass recoveredClass) throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();
		String className = recoveredClass.getName();

		List<Function> destructorList = recoveredClass.getDestructorList();
		Iterator<Function> destructorIterator = destructorList.iterator();
		while (destructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function destructorFunction = destructorIterator.next();
			String destructorName = "~" + className;

			createNewSymbolAtFunction(destructorFunction, destructorName, classNamespace, true,
				true);

			destructorFunction.setReturnType(DataType.VOID, SourceType.ANALYSIS);
		}
	}

	/**
	 * Method to name non-this destructors and add them to class namespace
	 * @param recoveredClass current class
	 * @throws Exception when cancelled
	 */
	public void addNonThisDestructorsToClassNamespace(RecoveredClass recoveredClass)
			throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();
		String className = recoveredClass.getName();

		List<Function> nonThisDestructorList = recoveredClass.getNonThisDestructors();
		Iterator<Function> destructorIterator = nonThisDestructorList.iterator();
		while (destructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function destructorFunction = destructorIterator.next();
			String destructorName = "~" + className;

			createNewSymbolAtFunction(destructorFunction, destructorName, classNamespace, false,
				false);
		}
	}

	/**
	 * Method to name class vbase destructors and add them to class namespace
	 * @param recoveredClass current class
	 * @throws Exception when cancelled
	 */
	public void addVbaseDestructorsToClassNamespace(RecoveredClass recoveredClass)
			throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();

		Function vbaseDestructorFunction = recoveredClass.getVBaseDestructor();
		if (vbaseDestructorFunction != null) {
			String destructorName = VBASE_DESTRUCTOR_LABEL;

			createNewSymbolAtFunction(vbaseDestructorFunction, destructorName, classNamespace, true,
				true);

			vbaseDestructorFunction.setReturnType(DataType.VOID, SourceType.ANALYSIS);
		}

	}

	/**
	 * Method to name the class vbtable, if one exists, and add it to the class namespace
	 * @param recoveredClass the given class
	 * @throws Exception if exception thrown
	 */
	public void addVbtableToClassNamespace(RecoveredClass recoveredClass) throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();

		Address vbtableAddress = recoveredClass.getVbtableAddress();

		if (vbtableAddress == null) {
			return;
		}

		createNewSymbolAtAddress(vbtableAddress, VBTABLE_LABEL, classNamespace);

	}

	/**
	 * Method to create a new symbol at an address
	 * @param address the given address
	 * @param name the name to give the new symbol
	 * @param namespace the namespace to put the new symbol in
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CancelledException if cancelled
	 */
	public void createNewSymbolAtAddress(Address address, String name, Namespace namespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException,
			CancelledException {

		Symbol symbol = symbolTable.getSymbol(name, address, namespace);

		// already exists
		if (symbol != null) {
			return;
		}

		// check to see if symbol is same name but in global namespace
		List<Symbol> symbolsByNameAtAddress = getSymbolsByNameAtAddress(address, name);

		// if no same name symbol, add new symbol
		if (symbolsByNameAtAddress.size() == 0) {
			AddLabelCmd lcmd = new AddLabelCmd(address, name, namespace, SourceType.ANALYSIS);
			if (!lcmd.applyTo(program)) {
				if (DEBUG) {
					Msg.debug(this,
						"ERROR: Could not add new symbol " + name + " to " + address.toString());
				}
			}
		}
		//put the same name one in the namespace
		else {
			Iterator<Symbol> iterator = symbolsByNameAtAddress.iterator();
			while (iterator.hasNext()) {
				monitor.checkCanceled();
				Symbol sameNameSymbol = iterator.next();
				sameNameSymbol.setNamespace(namespace);
			}
		}

		return;
	}

	/**
	 * Method to replace the program's current class structure, only if an empty placeholder structure,
	 * with the one generated by this script
	 * @param function a class method with current class structure applied
	 * @param className the given class name
	 * @param newClassStructure the new structure to replace the old with
	 * @throws DataTypeDependencyException if there is a data dependency exception when replacing
	 */
	public void replaceEmptyClassStructure(Function function, String className,
			Structure newClassStructure) throws DataTypeDependencyException {

		Parameter thisParam = function.getParameter(0);
		if (thisParam == null) {
			return;
		}

		DataType dataType = thisParam.getDataType();
		if (dataType instanceof Pointer) {
			Pointer ptr = (Pointer) dataType;
			DataType baseDataType = ptr.getDataType();
			if (baseDataType.getName().equals(className) && baseDataType.isNotYetDefined()) {

				dataTypeManager.replaceDataType(baseDataType, newClassStructure, false);

				// remove original folder if it is empty after the replace
				CategoryPath originalPath = baseDataType.getCategoryPath();
				Category category = dataTypeManager.getCategory(originalPath);
				Category parentCategory = category.getParent();
				if (parentCategory != null) {
					parentCategory.removeEmptyCategory(category.getName(), monitor);
				}

			}
		}
	}

	/**
	 * Method to create a new symbol at the given function
	 * @param function the given function
	 * @param name the name for the new symbol
	 * @param namespace the namespace to put the new symbol in
	 * @param setPrimary if true, set the new symbol primary, if false do not make the new symbol primary
	 * @param removeBadFID if true, check for and remove any incorrect FID symbols, if false leave them there
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CancelledException if cancelled
	 */
	private void createNewSymbolAtFunction(Function function, String name, Namespace namespace,
			boolean setPrimary, boolean removeBadFID) throws DuplicateNameException,
			InvalidInputException, CircularDependencyException, CancelledException {

		// check for bad FID or FID that needs fix up and remove those bad symbols
		if (removeBadFID) {
			removeBadFIDSymbols(namespace, name, function);
		}

		if (function.equals(purecall)) {
			return;
		}

		Symbol symbol = symbolTable.getSymbol(name, function.getEntryPoint(), namespace);

		// already exists
		if (symbol != null) {
			return;
		}

		// check to see if symbol is same name but in global namespace
		List<Symbol> symbolsByNameAtAddress =
			getSymbolsByNameAtAddress(function.getEntryPoint(), name);

		// if no same name symbol, add new symbol
		if (symbolsByNameAtAddress.size() == 0) {
			AddLabelCmd lcmd =
				new AddLabelCmd(function.getEntryPoint(), name, namespace, SourceType.ANALYSIS);
			if (!lcmd.applyTo(program)) {
				if (DEBUG) {
					Msg.debug(this, "ERROR: Could not add new function label " + name + " to " +
						function.getEntryPoint().toString());
				}
				return;
			}

			symbol = lcmd.getSymbol();
			if (setPrimary && !symbol.isPrimary()) {
				SetLabelPrimaryCmd scmd =
					new SetLabelPrimaryCmd(function.getEntryPoint(), name, namespace);
				if (!scmd.applyTo(program)) {
					if (DEBUG) {
						Msg.debug(this, "ERROR: Could not make function label " + name +
							" primary at " + function.getEntryPoint().toString());
					}
				}
			}
		}
		//put the same name one in the namespace
		else {
			Iterator<Symbol> iterator = symbolsByNameAtAddress.iterator();
			while (iterator.hasNext()) {
				monitor.checkCanceled();
				Symbol sameNameSymbol = iterator.next();
				sameNameSymbol.setNamespace(namespace);
			}
		}

		return;
	}

	/**
	 * Method to remove the primary label, applied by FID analyzer,  at the given address if it does not match the given name
	 * leave the secondary labels alone, ie the mangled name, so people can regenerate the old symbol
	 * if they want to
	 * @param namespace the given namespace
	 * @param name the given name
	 * @param function the given function
	 * @throws CancelledException if cancelled
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if issues setting return type
	 */
	private void removeBadFIDSymbols(Namespace namespace, String name, Function function)
			throws CancelledException, InvalidInputException, DuplicateNameException,
			CircularDependencyException {

		Address functionAddress = function.getEntryPoint();

		BookmarkManager bm = program.getBookmarkManager();

		Bookmark bookmark =
			bm.getBookmark(functionAddress, BookmarkType.ANALYSIS, "Function ID Analyzer");

		if (bookmark == null) {
			return;
		}

		String bookmarkComment = bookmark.getComment();

		// just get primary symbol and check it - if no match then remove all symbols and replace with good one
		if (bookmarkComment.contains("Single Match")) {

			Symbol symbol = symbolTable.getPrimarySymbol(functionAddress);
			if (symbol != null && symbol.getSource() == SourceType.ANALYSIS &&
				!symbol.getName().equals(name) && !symbol.getParentNamespace().equals(namespace)) {
				// add to list of bad namespaces to be cleaned up later 
				if (!badFIDNamespaces.contains(symbol.getParentNamespace())) {
					badFIDNamespaces.add(symbol.getParentNamespace());
				}
				extraUtils.addUniqueStringToPlateComment(functionAddress,
					"***** Removed Bad FID Symbol *****");

				if (!badFIDFunctions.contains(function)) {
					badFIDFunctions.add(function);
				}

				findAndRemoveBadStructuresFromFunction(function, namespace);
				extraUtils.removeAllSymbolsAtAddress(functionAddress);

			}
			return;
		}
		// FID with multiple matches - either all FID_conflicts or one common name 
		// since no good namespace all need to be removed but if there is a good base name
		// add FID
		if (bookmarkComment.contains("Multiple Matches")) {
			// See if any contain the class name and if so add "resolved" and if not
			if (doAnySymbolsHaveMatchingName(functionAddress, name)) {
				extraUtils.addUniqueStringToPlateComment(functionAddress,
					"***** Resolved FID Conflict *****");

				if (!resolvedFIDFunctions.contains(function)) {
					resolvedFIDFunctions.add(function);
				}

				findAndRemoveBadStructuresFromFunction(function, namespace);
			}
			else {
				extraUtils.addUniqueStringToPlateComment(functionAddress,
					"***** Removed Bad FID Symbol(s) *****");

				if (!badFIDFunctions.contains(function)) {
					badFIDFunctions.add(function);
				}

				findAndRemoveBadStructuresFromFunction(function, namespace);

			}
			extraUtils.removeAllSymbolsAtAddress(functionAddress);
			return;
		}
	}

	/**
	* Method to find empty structures that were created when incorrect FID function
	* signatures were applied and remove them from the given function. Incorrect structure
	* data types are added to a global list so that if nothing remains that references the data
	* type, it can be removed after all functions have been processed.
	* @param function the function with incorrect FID signature
	* @param namespace the correct namespace of the function
	* @throws CancelledException if cancelled
	* @throws InvalidInputException if error setting return type
	* @throws DuplicateNameException if try to create same symbol name already in namespace
	* @throws CircularDependencyException if parent namespace is descendent of given namespace
	*/
	private void findAndRemoveBadStructuresFromFunction(Function function, Namespace namespace)
			throws CancelledException, InvalidInputException, DuplicateNameException,
			CircularDependencyException {

		// find bad structure parameter data types 
		List<Structure> badStructureDataTypes = findBadParameterDataTypes(function, namespace);

		// find bad structure return data types
		Structure badReturnType = findBadReturnType(function, namespace);
		if (badReturnType != null && !badStructureDataTypes.contains(badReturnType)) {
			badStructureDataTypes.add(badReturnType);
		}

		// if bad structures were found delete and recreate the function and all calling functions
		// in order to remove the bad data types from the function signature
		if (badStructureDataTypes.size() > 0) {
			// find all functions that call this function and do the same
			fixBadSignatures(function, badStructureDataTypes);
			// add all the new bad dts to the list of bad ones 
			Iterator<Structure> badStructuresIterator = badStructureDataTypes.iterator();
			while (badStructuresIterator.hasNext()) {
				monitor.checkCanceled();
				Structure structure = badStructuresIterator.next();
				if (!badFIDStructures.contains(structure)) {
					badFIDStructures.add(structure);
				}
			}
		}
	}

	/**
	 * Method to remove incorrect data types from the given function's signature and from
	 * all calling functions
	 * @param function function with bad signature
	 * @throws CancelledException if cancelled
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if invalid data input
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	private void fixBadSignatures(Function function, List<Structure> badStructureDataTypes)
			throws CancelledException, InvalidInputException, DuplicateNameException,
			CircularDependencyException {

		List<Function> allFunctionsToFix = new ArrayList<Function>();
		allFunctionsToFix.add(function);
		Set<Function> callingFunctions = function.getCallingFunctions(monitor);

		while (callingFunctions != null && !callingFunctions.isEmpty()) {
			monitor.checkCanceled();
			List<Function> moreCallingFunctions = new ArrayList<Function>();
			Iterator<Function> callingFunctionsIterator = callingFunctions.iterator();
			while (callingFunctionsIterator.hasNext()) {
				monitor.checkCanceled();
				Function callingFunction = callingFunctionsIterator.next();
				if (!allFunctionsToFix.contains(callingFunction)) {
					allFunctionsToFix.add(callingFunction);
					moreCallingFunctions.addAll(callingFunction.getCallingFunctions(monitor));
				}
				callingFunctionsIterator.remove();
			}
			callingFunctions.addAll(moreCallingFunctions);
		}

		Iterator<Function> functionsToFixIterator = allFunctionsToFix.iterator();
		while (functionsToFixIterator.hasNext()) {
			monitor.checkCanceled();
			Function functionToFix = functionsToFixIterator.next();
			if (!functionToFix.isThunk()) {

				removeBadReturnType(functionToFix, badStructureDataTypes);
				removeBadParameterDataTypes(functionToFix, badStructureDataTypes);

				if (!fixedFIDFunctions.contains(functionToFix)) {
					fixedFIDFunctions.add(functionToFix);
				}
			}
		}

	}

	/**
	 * Method to find and add to permanent removal list any incorrect empty structure params 
	 * @param function the function to check for bad params
	 * @param namespace the correct parent namespace of function
	 * @throws CancelledException when cancelled
	 */
	private List<Structure> findBadParameterDataTypes(Function function, Namespace namespace)
			throws CancelledException {

		List<Structure> badStructureDataTypes = new ArrayList<Structure>();

		int parameterCount = function.getParameterCount();
		for (int i = 0; i < parameterCount; i++) {
			monitor.checkCanceled();
			DataType dataType = function.getParameter(i).getDataType();
			if (!dataType.getName().equals(namespace.getName()) &&
				extraUtils.isPointerToEmptyStructure(dataType)) {
				Pointer ptr = (Pointer) dataType;
				Structure structure = (Structure) ptr.getDataType();

				if (!badStructureDataTypes.contains(structure)) {
					badStructureDataTypes.add(structure);
				}
			}
		}
		return badStructureDataTypes;
	}

	/**
	 * Method to replace the given bad structure data types with undefined data types of same size 
	 * for the given functions parameters
	 * @param function the function to fix
	 * @param badStructureDataTypes the list of bad structure data types to replace if found
	 * @throws CancelledException if cancelled
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if invalid data input
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	private void removeBadParameterDataTypes(Function function,
			List<Structure> badStructureDataTypes) throws CancelledException,
			DuplicateNameException, InvalidInputException, CircularDependencyException {

		int parameterCount = function.getParameterCount();
		for (int i = 0; i < parameterCount; i++) {
			monitor.checkCanceled();
			DataType paramDataType = function.getParameter(i).getDataType();
			Structure baseDataType = extraUtils.getBaseStructureDataType(paramDataType);
			if (baseDataType != null && badStructureDataTypes.contains(baseDataType)) {

				// To remove from this param we have to remove the function from its namespace
				if (function.getParameter(i).getName().equals("this")) {
					function.setParentNamespace(globalNamespace);

				}
				else {
					PointerDataType ptrUndefined =
						extraUtils.createPointerToUndefinedDataType(paramDataType);
					if (ptrUndefined != null) {
						function.getParameter(i).setDataType(ptrUndefined, SourceType.ANALYSIS);
					}

					else {
						if (DEBUG) {
							Msg.debug(this, "ERROR: " + function.getEntryPoint().toString() +
								" Could not replace parameter " + i + " with undefined pointer.");
						}
					}
				}
			}
		}
	}

	/**
	 * Method to find incorrect empty structure return type
	 * @param function the function to check
	 * @param namespace the parent namespace of the function
	 */
	private Structure findBadReturnType(Function function, Namespace namespace) {

		DataType returnType = function.getReturnType();
		if (!returnType.getName().equals(namespace.getName()) &&
			extraUtils.isPointerToEmptyStructure(returnType)) {
			Pointer ptr = (Pointer) returnType;
			Structure structure = (Structure) ptr.getDataType();

			return structure;

		}
		return null;
	}

	/**
	 * Method to fix a bad return type if it is one of the bad structure data types on the given 
	 * list. The list was previously generated from functions that had incorrect FID signatures 
	 * placed on them that this script recognized and corrected.
	 * @param function the given function
	 * @param badStructureDataTypes a list of bad structure data types
	 * @throws InvalidInputException if issue setting return type
	 */
	private void removeBadReturnType(Function function, List<Structure> badStructureDataTypes)
			throws InvalidInputException {

		DataType returnType = function.getReturnType();
		Structure baseDataType = extraUtils.getBaseStructureDataType(returnType);
		if (baseDataType != null && badStructureDataTypes.contains(baseDataType)) {
			PointerDataType ptrUndefined =
				extraUtils.createPointerToUndefinedDataType(returnType);
			if (ptrUndefined != null) {
				function.setReturnType(ptrUndefined, SourceType.ANALYSIS);
			}
		}
	}

	/**
	 * Method to determine if any symbols at the given address have matching names
	 * as the given name after removing template, pdb quotes, or FID_conflict characters
	 * added by other analyzers.
	 * @param address the given address
	 * @param name the name to match
	 * @return true if any symbols at the given address "match" the given name, false otherwise
	 * @throws CancelledException when canceled
	 */
	private boolean doAnySymbolsHaveMatchingName(Address address, String name)
			throws CancelledException {

		String simpleName = extraUtils.removeTemplate(name);

		SymbolIterator it = symbolTable.getSymbolsAsIterator(address);
		for (Symbol symbol : it) {
			monitor.checkCanceled();

			String simpleSymbolName = extraUtils.removeTemplate(symbol.getName());
			simpleSymbolName = removeSingleQuotes(simpleSymbolName);
			simpleSymbolName = removeFIDConflict(simpleSymbolName);
			simpleSymbolName = removeSingleQuotes(simpleSymbolName);

			if (simpleName.equals(simpleSymbolName)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method to remove single quotes from beginning and end of given string
	 * @param string string to process
	 * @return string without leading or trailing single quotes
	 */
	private String removeSingleQuotes(String string) {
		if (string.startsWith("`")) {
			string = string.substring(1);
		}
		if (string.endsWith("'")) {
			string = string.substring(0, string.length() - 1);
		}
		return string;

	}

	/**
	 * Method to remove "FID_conflict:" prefix from the given string
	 * @param string string to process
	 * @return string without "FID_conflict:" prefix
	 */
	private String removeFIDConflict(String string) {
		if (string.startsWith("FID_conflict:")) {
			string = string.substring(13);
		}
		return string;

	}

	/**
	 * Method to get symbols with the given name at the given address
	 * @param address the given address
	 * @param name the given name to match
	 * @return a list of symbols with the given name at the given address
	 * @throws CancelledException if cancelled
	 */
	List<Symbol> getSymbolsByNameAtAddress(Address address, String name) throws CancelledException {

		List<Symbol> sameNameSymbols = new ArrayList<Symbol>();

		Symbol[] symbols = symbolTable.getSymbols(address);
		for (Symbol symbol : symbols) {
			monitor.checkCanceled();
			Namespace namespace = symbol.getParentNamespace();

			if (namespace.isGlobal() && symbol.getName().equals(name)) {
				sameNameSymbols.add(symbol);
			}
			else if (namespace.isGlobal() && name.equals(DELETING_DESTRUCTOR_LABEL) &&
				symbol.getName().contains(DELETING_DESTRUCTOR_LABEL)) {
				sameNameSymbols.add(symbol);
			}
		}
		return sameNameSymbols;
	}

	/**
	 * Returns a new address with the specified offset in the default address space.
	 * @param offset the offset for the new address
	 * @return a new address with the specified offset in the default address space
	 */
	public final Address toAddr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Method to determine if the given constructor function calls any non-parent constructors 
	 * before the vftable refererence
	 * @param recoveredClass the given class
	 * @param constructor the given constructor function
	 * @param vftableReference the address of the reference to the class vftable 
	 * @return true if the given constructor function calls any non-parent constructors before the 
	 * vftable refererence, false otherwise
	 * @throws CancelledException if cancelled
	 */
	public boolean doesFunctionCallAnyNonParentConstructorsBeforeVtableReference(
			RecoveredClass recoveredClass, Function constructor, Address vftableReference)
			throws CancelledException {

		List<ReferenceAddressPair> orderedReferenceAddressPairsFromCallingFunction =
			extraUtils.getOrderedReferenceAddressPairsFromCallingFunction(constructor);

		// if there are no calls from the function then return false
		if (orderedReferenceAddressPairsFromCallingFunction.size() == 0) {
			return false;
		}

		Iterator<ReferenceAddressPair> iterator =
			orderedReferenceAddressPairsFromCallingFunction.iterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			ReferenceAddressPair refPair = iterator.next();
			int callRefCompareToVftableRef = refPair.getSource().compareTo(vftableReference);
			// if call is after the vtable reference then return false
			if (callRefCompareToVftableRef > 0) {
				return false;
			}

			// if call is before vtable and is not an inherited constructor and not the operator_new 
			// then return true
			Address calledAddress = refPair.getDestination();
			Function calledFunction = api.getFunctionAt(calledAddress);
			if (calledFunction.isThunk()) {
				calledFunction = calledFunction.getThunkedFunction(true);
			}

			if (calledFunction.equals(operator_new)) {
				continue;
			}

			if (calledFunction.getName().contains("prolog")) {
				continue;
			}

			if (!getAllConstructors().contains(calledFunction)) {
				return true;
			}

		}
		return false;

	}

	/**
	 * Method to find class clone functions 
	 * @param recoveredClasses List of RecoveredClass objects
	 * @throws CancelledException when script is cancelled
	 * @throws Exception if issues making label
	 */
	public void findCloneFunctions(List<RecoveredClass> recoveredClasses)
			throws CancelledException, Exception {

		Map<Function, RecoveredClass> cloneToClassMap = new HashMap<Function, RecoveredClass>();

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

			List<Function> allOtherConstructors =
				new ArrayList<Function>(getAllConstructors());
			allOtherConstructors.removeAll(recoveredClass.getConstructorList());

			// iterate through the vtable functions
			List<Function> virtualFunctions = recoveredClass.getAllVirtualFunctions();
			if (virtualFunctions == null) {
				continue;
			}
			Iterator<Function> vfunctionIterator = virtualFunctions.iterator();
			while (vfunctionIterator.hasNext()) {
				monitor.checkCanceled();

				Function vfunction = vfunctionIterator.next();
				if (extraUtils.doesFunctionACallAnyListedFunction(vfunction,
					recoveredClass.getConstructorList()) &&
					!extraUtils.doesFunctionACallAnyListedFunction(vfunction,
						allOtherConstructors)) {
					cloneToClassMap.put(vfunction, recoveredClass);
				}
			}

		}

		// use the clone functions with only two calls (one to constructor and one to operator new)
		Function operatorNew = identifyOperatorNewFunction(cloneToClassMap);

		// use the operator new to accept only the good clones
		// if more than one operator new remove
		if (operatorNew != null) {
			Set<Function> cloneFunctions = cloneToClassMap.keySet();
			Iterator<Function> cloneIterator = cloneFunctions.iterator();
			while (cloneIterator.hasNext()) {
				monitor.checkCanceled();
				Function cloneFunction = cloneIterator.next();
				if (isBasicCloneFunction(cloneFunction, operator_new, cloneToClassMap)) {
					RecoveredClass recoveredClass = cloneToClassMap.get(cloneFunction);
					recoveredClass.addCloneFunction(cloneFunction);
				}
			}
		}

	}

	/**
	 * Method to identify basic clone functions
	 * @param caller possible clone function
	 * @param firstCalled first function called by caller
	 * @param cloneFunctionToClassMap map of possible clone functions to their parent class
	 * @return true if caller function is a basic clone, else false
	 * @throws CancelledException if cancelled
	 */
	private boolean isBasicCloneFunction(Function caller, Function firstCalled,
			Map<Function, RecoveredClass> cloneFunctionToClassMap) throws CancelledException {

		Set<Function> calledFunctions = caller.getCalledFunctions(monitor);
		if (calledFunctions.size() != 2 && calledFunctions.size() != 3) {
			return false;
		}
		if (!extraUtils.getCalledFunctionByCallOrder(caller, 1).equals(firstCalled)) {
			return false;
		}
		RecoveredClass recoveredClass = cloneFunctionToClassMap.get(caller);
		List<Function> constructorList = recoveredClass.getConstructorList();

		Function secondFunction = extraUtils.getCalledFunctionByCallOrder(caller, 2);
		if (secondFunction.isThunk()) {
			secondFunction = secondFunction.getThunkedFunction(true);
		}

		if (!constructorList.contains(secondFunction)) {
			return false;
		}

		return true;
	}

	/**
	 * Method to identify the operator_new function using found clone functions
	 * @param cloneToClassMap Map of clone functions and their classes
	 * @return the operator_new function or null if not identified
	 * @throws CancelledException if cancelled
	 * @throws Exception if issue making label
	 */
	private Function identifyOperatorNewFunction(Map<Function, RecoveredClass> cloneToClassMap)
			throws CancelledException, Exception {

		Map<Function, Integer> functionOccuranceMap = new HashMap<Function, Integer>();

		Set<Function> cloneFunctions = cloneToClassMap.keySet();
		Iterator<Function> cloneIterator = cloneFunctions.iterator();
		while (cloneIterator.hasNext()) {
			monitor.checkCanceled();
			Function cloneFunction = cloneIterator.next();

			// Easiest to find using those with only two calls so skip the bigger ones
			Set<Function> calledFunctions = cloneFunction.getCalledFunctions(monitor);
			if (calledFunctions.size() != 2) {
				continue;
			}
			// get first called function which should be the operator_new function
			// The second call is a class constructor and we know it is called
			// from the cloneFunction or it wouldn't be a cloneFunction
			Function firstCalledFunction =
				extraUtils.getCalledFunctionByCallOrder(cloneFunction, 1);
			if (firstCalledFunction == null) {
				continue;
			}
			// skip any constructor or destructors that are called first
			if (getAllConstructorsAndDestructors().contains(firstCalledFunction)) {
				continue;
			}

			if (!functionOccuranceMap.keySet().contains(firstCalledFunction)) {
				functionOccuranceMap.put(firstCalledFunction, 1);
			}
			else {
				Integer numOccurances = functionOccuranceMap.get(firstCalledFunction);
				functionOccuranceMap.replace(firstCalledFunction, numOccurances + 1);
			}

		}

		Function probableOperatorNewFunction = getMostFrequentFunction(functionOccuranceMap);

		if (probableOperatorNewFunction == null) {
			return null;
		}

		Integer numOccurances = functionOccuranceMap.get(probableOperatorNewFunction);
		if (functionOccuranceMap.get(probableOperatorNewFunction) < MIN_OPERATOR_NEW_REFS) {
			Msg.debug(this, probableOperatorNewFunction.toString() +
				" is a possible operator_new function but has less than the defined minimum number " +
				"of matching calls " + numOccurances);

			return null;
		}

		// If we get this far then we are sure the operator_new function
		// is correct so assign the global variable to it
		operator_new = probableOperatorNewFunction;
		//If its symbol is not already named then name it
		if (probableOperatorNewFunction.getSymbol().getSource() == SourceType.DEFAULT) {
			Msg.debug(this,
				"Found unlabeled operator new that matched in all found clone functions: " +
					probableOperatorNewFunction.getEntryPoint().toString() +
					". Creating label there.");
			api.createLabel(probableOperatorNewFunction.getEntryPoint(), "operator_new", true);
		}

		return operator_new;

	}

	/**
	 * Method to get the function in the map with the highest mapped Integer value
	 * @param map the map containing function, count mappings
	 * @return the function with the highest count mapped to it
	 * @throws CancelledException if cancelled
	 */
	private Function getMostFrequentFunction(Map<Function, Integer> map) throws CancelledException {

		Integer highest = null;
		Function mostFrequentFunction = null;
		Set<Function> keySet = map.keySet();
		Iterator<Function> iterator = keySet.iterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			Function function = iterator.next();
			if (mostFrequentFunction == null) {
				mostFrequentFunction = function;
				highest = map.get(function);
				continue;
			}
			Integer frequency = map.get(function);
			if (frequency > highest) {
				highest = frequency;
				mostFrequentFunction = function;
			}
		}
		return mostFrequentFunction;
	}

	/**
	 * Method to remove the empty namespaces and unreferenced empty class structures that 
	 *  that were incorrectly applied by FID
	 * @throws CancelledException when script is cancelled
	 */
	public void removeEmptyClassesAndStructures() throws CancelledException {

		Iterator<Namespace> badNamespaceIterator = badFIDNamespaces.iterator();
		while (badNamespaceIterator.hasNext()) {
			monitor.checkCanceled();
			Namespace badNamespace = badNamespaceIterator.next();

			// delete empty namespace and parent namespaces
			if (!extraUtils.hasSymbolsInNamespace(badNamespace)) {
				removeEmptyNamespaces(badNamespace);
			}
		}

		// remove unused empty structures
		removeEmptyStructures();

	}

	/**
	 * Method to remove the given namespace if it is empty and its parent namepaces if they are empty
	 * @param namespace the given namespace
	 * @throws CancelledException if cancelled
	 */
	private void removeEmptyNamespaces(Namespace namespace) throws CancelledException {

		// delete empty namespace and parent namespaces
		Namespace parentNamespace = namespace.getParentNamespace();

		namespace.getSymbol().delete();
		while (parentNamespace != null && !extraUtils.hasSymbolsInNamespace(parentNamespace)) {
			monitor.checkCanceled();

			namespace = parentNamespace;
			parentNamespace = parentNamespace.getParentNamespace();
			namespace.getSymbol().delete();
		}
	}

	/**
	 * Method to remove the incorrectly applied and unreferenced empty structures that are not used 
	 * @throws CancelledException when script is cancelled
	 */
	private void removeEmptyStructures() throws CancelledException {

		Iterator<Structure> badStructureIterator = badFIDStructures.iterator();
		while (badStructureIterator.hasNext()) {

			monitor.checkCanceled();

			Structure badStructure = badStructureIterator.next();
			// if not used by anything remove it
			ListAccumulator<LocationReference> accumulator = new ListAccumulator<>();
			ReferenceUtils.findDataTypeReferences(accumulator, badStructure, null, program, true,
				monitor);

			List<LocationReference> referenceList = accumulator.asList();
			if (referenceList.isEmpty()) {
				// delete empty class data type and empty parent folders
				removeEmptyStructure(badStructure.getDataTypePath().getCategoryPath(),
					badStructure.getName());
			}
		}
	}

	/**
	 * Method to remove the structure with the given folder path and name if it is empty
	 * @param folderPath the given folder path in the data type manager
	 * @param structureName the given structure name
	 * @throws CancelledException if cancelled
	 */
	private void removeEmptyStructure(CategoryPath folderPath, String structureName)
			throws CancelledException {

		DataType dataType = dataTypeManager.getDataType(folderPath, structureName);
		if (extraUtils.isEmptyStructure(dataType)) {

			dataTypeManager.remove(dataType, monitor);
			Category classCategory = dataTypeManager.getCategory(folderPath);
			Category parentCategory = classCategory.getParent();
			boolean tryToRemove = true;
			while (parentCategory != null && tryToRemove) {
				monitor.checkCanceled();

				tryToRemove = parentCategory.removeEmptyCategory(classCategory.getName(), monitor);
				classCategory = parentCategory;
				parentCategory = parentCategory.getParent();
			}

		}

	}

	/**
	 * Method to create empty vftable structures before class struct is created so that 
	 * they can be added to the class structure. Afterwords, they are filled in with pointers
	 * to vftable functions
	 * @param recoveredClass the given class
	 * @return Map of address/vftable structure pointers
	 * @throws Exception when invalid data creation
	 */
	public Map<Address, DataType> createEmptyVfTableStructs(RecoveredClass recoveredClass)
			throws Exception {

		Map<Address, DataType> vftableToStructureMap = new HashMap<Address, DataType>();

		String className = recoveredClass.getName();

		CategoryPath classPath = recoveredClass.getClassPath();

		Structure vftableStruct = null;

		Map<Integer, Address> orderToVftableMap = recoveredClass.getOrderToVftableMap();

		for (int index = 0; index < orderToVftableMap.size(); index++) {

			monitor.checkCanceled();

			Address vftableAddress = orderToVftableMap.get(index);

			// if only one vftable name the structure <class_name>_vftable
			if (orderToVftableMap.size() == 1) {
				vftableStruct = new StructureDataType(classPath,
					className + CLASS_VFUNCTION_STRUCT_NAME, 0, dataTypeManager);
			}
			// if more than one, name it <class_name>_vftable_for_<associated_parent_name> if
			// can associate them or <class_name_vftable_<vftable_order> if can't assoc parent
			else {
				RecoveredClass vftableParentClass =
					recoveredClass.getVftableBaseClass(vftableAddress);
				// should never happen but just in case
				if (vftableParentClass == null) {
					vftableStruct = new StructureDataType(classPath,
						className + CLASS_VFUNCTION_STRUCT_NAME + index, 0, dataTypeManager);
				}
				else {
					vftableStruct =
						new StructureDataType(classPath, className + CLASS_VFUNCTION_STRUCT_NAME +
							"_for_" + vftableParentClass.getName(), 0, dataTypeManager);
				}
			}

			// pack the structure then add it to the data type manager
			vftableStruct.setPackingEnabled(true);
			vftableStruct = (Structure) dataTypeManager.addDataType(vftableStruct,
				DataTypeConflictHandler.DEFAULT_HANDLER);

			DataType vfPointerDataType = dataTypeManager.getPointer(vftableStruct);

			vftableToStructureMap.put(vftableAddress, vfPointerDataType);
		}
		return vftableToStructureMap;
	}

	/**
	 * Method to create class structure for single inheritance, no parent, non-vftable classes
	 * @param recoveredClass the given class
	 * @throws CancelledException when cancelled
	 */
	public void createClassStructureWhenNoParentOrVftable(RecoveredClass recoveredClass)
			throws CancelledException {

		Structure classStruct;
		if (recoveredClass.hasExistingClassStructure()) {
			Structure computedClassDataStructure = recoveredClass.getExistingClassStructure();
			int structLen = 0;
			if (computedClassDataStructure != null) {
				structLen = computedClassDataStructure.getLength();
				int mod = structLen % defaultPointerSize;
				int alignment = 0;
				if (mod != 0) {
					alignment = defaultPointerSize - mod;
					structLen += alignment;
				}

				classStruct = new StructureDataType(recoveredClass.getClassPath(),
					recoveredClass.getName(), structLen, dataTypeManager);

				int numComponents = computedClassDataStructure.getNumDefinedComponents();
				for (int i = 1; i < numComponents; i++) {
					monitor.checkCanceled();
					DataTypeComponent component = computedClassDataStructure.getComponent(i);
					int offset = component.getOffset();
					classStruct.replaceAtOffset(offset, component.getDataType(),
						component.getDataType().getLength(), component.getFieldName(),
						component.getComment());
				}
			}
			else {
				classStruct = new StructureDataType(recoveredClass.getClassPath(),
					recoveredClass.getName(), defaultPointerSize, dataTypeManager);
			}

		}
		// make it default ptr size so it aligns inside child class correctly
		else {
			classStruct = new StructureDataType(recoveredClass.getClassPath(),
				recoveredClass.getName(), defaultPointerSize, dataTypeManager);
		}

		// create a description indicating class parentage
		classStruct.setDescription(createParentStringBuffer(recoveredClass).toString());

		classStruct = (Structure) dataTypeManager.addDataType(classStruct,
			DataTypeConflictHandler.DEFAULT_HANDLER);

	}

	/**
	 * Method to fill in the vftable structure with pointers to virtual function signature data types
	 * @param recoveredClass the current class to be processed
	 * @param vftableToStructureMap the map from the class's vftables to the correct vftable structure data type
	 * @throws CancelledException when cancelled
	 * @throws Exception if other exception
	 */
	public void fillInAndApplyVftableStructAndNameVfunctions(RecoveredClass recoveredClass,
			Map<Address, DataType> vftableToStructureMap) throws CancelledException, Exception {

		//create function definition for each virtual function and put in vftable structure and 
		// data subfolder
		CategoryPath classPath = recoveredClass.getClassPath();

		List<Address> vftableAddresses = recoveredClass.getVftableAddresses();
		Iterator<Address> vftableAddressIterator = vftableAddresses.iterator();

		while (vftableAddressIterator.hasNext()) {
			monitor.checkCanceled();
			Address vftableAddress = vftableAddressIterator.next();

			PointerDataType vftablePointerDataType =
				(PointerDataType) vftableToStructureMap.get(vftableAddress);

			DataType vftableDataType = vftablePointerDataType.getDataType();

			String vftableStructureName = vftableDataType.getName();
			vftableDataType = dataTypeManager.getDataType(vftableDataType.getCategoryPath(),
				vftableStructureName);

			Structure vftableStruct = (Structure) vftableDataType;

			if (nameVfunctions) {
				// if no pdb info, name all the vfunctions for this vftable and put in class namespace
				nameVfunctions(recoveredClass, vftableAddress, vftableStructureName);
			}

			List<Function> vFunctions = recoveredClass.getVirtualFunctions(vftableAddress);
			int vfunctionNumber = 1;
			Iterator<Function> vfIterator = vFunctions.iterator();

			while (vfIterator.hasNext()) {

				monitor.checkCanceled();
				Function vfunction = vfIterator.next();

				if (vfunction == null) {
					Pointer nullPointer = dataTypeManager.getPointer(DataType.DEFAULT);
					vftableStruct.add(nullPointer, "null pointer", null);
					continue;
				}

				// get the classPath of highest level parent with vfAddress in their vftable
				classPath =
					getCategoryPathForFunctionSignature(vfunction, recoveredClass, vftableAddress);

				Symbol vfunctionSymbol = symbolTable.getPrimarySymbol(vfunction.getEntryPoint());
				Namespace parentNamespace = vfunctionSymbol.getParentNamespace();

				String classCommentPrefix = "";

				if (!parentNamespace.equals(globalNamespace)) {
					RecoveredClass vfunctionClass = getClass(parentNamespace);

					// this is null when there is a class from somewhere other than RTTI so it is
					// not stored in the map. Just use the parent namespace name in this case
					// TODO: can check against other program namespace names to see if it can be shortened
					if (vfunctionClass == null) {
						classCommentPrefix = parentNamespace.getName();
					}
					else if (vfunctionClass.getShortenedTemplateName() != null &&
						useShortTemplates && !vfunctionClass.getShortenedTemplateName().isEmpty()) {
						classCommentPrefix = vfunctionClass.getShortenedTemplateName();
					}
					else {
						classCommentPrefix = vfunctionClass.getName();
					}

				}

				// Create comment to indicate it is a virtual function and which number in the table
				String comment = VFUNCTION_COMMENT + vfunctionNumber;

				// add suffix for multi classes to distinguish which vftable it is for
				String commentSuffix = getForClassSuffix(vftableStructureName);
				if (!commentSuffix.isEmpty()) {
					int index = commentSuffix.indexOf("for_");
					if (index > 0) {
						commentSuffix = " for parent class " + commentSuffix.substring(index + 4);
					}
					comment = comment + commentSuffix;
				}

				// if function is "purecall" function make the class field name "vfunction #n" instead
				// of using the function name of "purecall" and prepend "pure" to the comment so
				// they know it is pure virtual function, ie not actually implemented in the parent class
				String nameField = vfunction.getName();
				if (nameField.contains("purecall")) {
					nameField = DEFAULT_VFUNCTION_PREFIX + vfunctionNumber;
					comment = recoveredClass.getName() + " pure " + comment;

				}

				PointerDataType functionPointerDataType =
					createFunctionSignaturePointerDataType(vfunction, classPath);

				vftableStruct.add(functionPointerDataType, nameField,
					classCommentPrefix + " " + comment);
				vfunctionNumber++;
			}

			// align the structure then add it to the data type manager
			vftableStruct.setPackingEnabled(true);
			vftableStruct = (Structure) dataTypeManager.addDataType(vftableStruct,
				DataTypeConflictHandler.DEFAULT_HANDLER);

			// clear the array or unprocessed structure at the current vftable location and 
			// apply the structure. It has to be one or the other and the correct length
			// because of the check at the beginning of the script that checked for either
			// array or structure of pointers and got size from them initially
			api.clearListing(vftableAddress);
			api.createData(vftableAddress, vftableStruct);

		}
	}

	/**
	 * Method to give default names to the vfunctions in the given vftable if they don't have a name already. If they are a clone or deleting destructor name them accordingly.
	 * @param recoveredClass the given class
	 * @param vftableAddress the address of the vftable
	 * @param vftableStructureName the name of the vftable structure to be used as a prefix for the vfunctions in the given vftable
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	private void nameVfunctions(RecoveredClass recoveredClass, Address vftableAddress,
			String vftableStructureName) throws CancelledException, InvalidInputException,
			DuplicateNameException, CircularDependencyException {

		Namespace classNamespace = recoveredClass.getClassNamespace();

		List<Function> deletingDestructors = recoveredClass.getDeletingDestructors();
		List<Function> cloneFunctions = recoveredClass.getCloneFunctions();

		Iterator<Function> vfIterator =
			recoveredClass.getVirtualFunctions(vftableAddress).iterator();

		String vfunctionName;
		int tableEntry = 1;

		// get the "_for_<className> suffix for classes with multiple vftables or empty
		// string for those with single vftable
		String vfunctionSuffix = getForClassSuffix(vftableStructureName);

		while (vfIterator.hasNext()) {
			monitor.checkCanceled();
			Function vfunction = vfIterator.next();

			// create a one-up number for the next virtual function
			int entryNumber = tableEntry++;

			boolean setPrimary = false;
			boolean removeBadFID = false;
			boolean isDeletingDestructor = false;

			if (deletingDestructors.contains(vfunction)) {
				vfunctionName = DELETING_DESTRUCTOR_LABEL + vfunctionSuffix;
				setPrimary = true;
				removeBadFID = true;
				isDeletingDestructor = true;
			}

			else if (cloneFunctions.contains(vfunction)) {
				vfunctionName = CLONE_LABEL + vfunctionSuffix;
				setPrimary = true;
				removeBadFID = true;
			}

			else {
				vfunctionName = DEFAULT_VFUNCTION_PREFIX + entryNumber + vfunctionSuffix;
			}

			// can't put external functions into a namespace from this program
			if (!vfunction.isExternal()) {

				// if not already, make it a this call
				makeFunctionThiscall(vfunction);

				// put symbol on the virtual function
				Symbol vfunctionSymbol = vfunction.getSymbol();
				Namespace vfunctionNamespace = vfunctionSymbol.getParentNamespace();

				// if the name already contains deleting_destructor for this namespace don't add
				// another dd symbol
				if (hasDeletingDestructorInNamespace(vfunction.getEntryPoint(), classNamespace)) {
					continue;
				}

				if (!isDeletingDestructor &&
					isParentNamespace(vfunctionNamespace, classNamespace)) {
					String plateComment = api.getPlateComment(vfunction.getEntryPoint());
					String newComment = vfunctionNamespace.getName(true) +
						" member function inherited by " + classNamespace.getName(true);
					if (plateComment != null) {
						newComment = plateComment + "\n" + newComment;
					}
					api.setPlateComment(vfunction.getEntryPoint(), newComment);
					continue;
				}

				SourceType originalSourceType = vfunctionSymbol.getSource();
				if (originalSourceType == SourceType.DEFAULT || setPrimary) {
					createNewSymbolAtFunction(vfunction, vfunctionName, classNamespace, setPrimary,
						removeBadFID);
				}
			}
		}
	}

	private String getForClassSuffix(String vftableStructureName) {

		String vfunctionSuffix = "";
		if (vftableStructureName.contains("_for_")) {
			int index = vftableStructureName.indexOf("for_");
			if (index > 0) {
				vfunctionSuffix = "_" + vftableStructureName.substring(index);
			}
		}
		return vfunctionSuffix;
	}

	private String getParentClassNameFromForClassSuffix(String commentSuffix) {

		if (!commentSuffix.isEmpty()) {
			int index = commentSuffix.indexOf("for_");
			if (index > 0) {
				return commentSuffix.substring(index + 4);
			}

		}
		return null;
	}

	private boolean hasDeletingDestructorInNamespace(Address address, Namespace namespace)
			throws CancelledException {

		Symbol[] symbols = symbolTable.getSymbols(address);
		for (Symbol symbol : symbols) {
			monitor.checkCanceled();

			if (symbol.getName().contains("deleting_destructor") &&
				symbol.getParentNamespace().equals(namespace)) {
				return true;
			}
		}
		return false;
	}

	private boolean isParentNamespace(Namespace namespace, Namespace childNamespace) {

		RecoveredClass possibleParentClass = getClass(namespace);
		if (possibleParentClass == null) {
			return false;
		}

		RecoveredClass childClass = getClass(childNamespace);
		if (childClass == null) {
			return false;
		}

		if (childClass.equals(possibleParentClass)) {
			return false;
		}

		List<RecoveredClass> classHierarchy = childClass.getClassHierarchy();
		if (classHierarchy.contains(possibleParentClass)) {
			return true;
		}
		return false;
	}

	// may skip a parent so continue through all parents
	// for multi-inheritance, get the correct parent class for the given vftable
	/**
	 * Method to retrieve the class path of the highest ancestor with matching vfunction in its vftable
	 * @param vfunction the given virtual function
	 * @param recoveredClass the given class
	 * @param vftableAddress the given virtual function table from the given class
	 * @return the class path for the highest ancestor with matching virtual function in its vftable
	 * @throws CancelledException when cancelled
	 */
	CategoryPath getCategoryPathForFunctionSignature(Function vfunction,
			RecoveredClass recoveredClass, Address vftableAddress) throws CancelledException {

		// if class has no parent, return its own classPath
		CategoryPath classPath = recoveredClass.getClassPath();
		if (!recoveredClass.hasParentClass()) {
			return classPath;
		}

		// if no ancestor has virtual functions then return the given class's class path
		List<RecoveredClass> ancestorsWithVirtualFunctions =
			getAncestorsWithVirtualFunctions(recoveredClass);
		if (ancestorsWithVirtualFunctions.size() == 0) {
			return classPath;
		}

		Iterator<RecoveredClass> classHierarchyIterator;
		if (recoveredClass.hasSingleInheritance()) {
			List<RecoveredClass> classHierarchy = recoveredClass.getClassHierarchy();
			classHierarchyIterator = classHierarchy.listIterator(1);
		}
		else {
			// get the parent that goes with the given vftableAddress
			// if there is no parent associated with the vftable then return the current
			// class's class path
			RecoveredClass parentClass = recoveredClass.getVftableBaseClass(vftableAddress);
			if (parentClass == null) {
				return classPath;
			}

			// get the class hierarchy for the parent
			List<RecoveredClass> classHierarchy =
				recoveredClass.getClassHierarchyMap().get(parentClass);
			if (classHierarchy == null) {
				return classPath;
			}

			classHierarchyIterator = classHierarchy.iterator();
		}

		while (classHierarchyIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass currentClass = classHierarchyIterator.next();
			List<Function> virtualFunctions = currentClass.getAllVirtualFunctions();
			if (virtualFunctions.contains(vfunction)) {
				classPath = currentClass.getClassPath();
			}
		}
		return classPath;

	}

	/**
	 * 
	 * @param vfunction the given function
	 * @param classPath the given data type manager classPath
	 * @return pointer to function signature data type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	private PointerDataType createFunctionSignaturePointerDataType(Function vfunction,
			CategoryPath classPath) throws DuplicateNameException {

		FunctionDefinition functionDataType = (FunctionDefinitionDataType) vfunction.getSignature();

		DataType returnType = vfunction.getReturnType();

		functionDataType.setReturnType(returnType);

		// If this data type doesn't exist in this folder make a new one
		// otherwise use the existing one
		DataType existingDataType =
			dataTypeManager.getDataType(classPath, functionDataType.getName());

		PointerDataType functionPointerDataType;

		if (existingDataType == null) {
			functionDataType.setCategoryPath(classPath);
			functionDataType = (FunctionDefinition) dataTypeManager.addDataType(functionDataType,
				DataTypeConflictHandler.DEFAULT_HANDLER);
			functionPointerDataType = new PointerDataType(functionDataType);
		}
		else {
			functionPointerDataType = new PointerDataType(existingDataType);
		}
		return functionPointerDataType;

	}

	/**
	 * Method to add precomment inside functions containing inlined constructors at approximate
	 * address of start of inlined function
	 * @param recoveredClass current class
	 * @throws Exception when cancelled
	 */
	public void createInlinedConstructorComments(RecoveredClass recoveredClass) throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();
		String className = recoveredClass.getName();

		List<Function> inlinedConstructorList = recoveredClass.getInlinedConstructorList();
		Iterator<Function> inlinedConstructorsIterator = inlinedConstructorList.iterator();

		while (inlinedConstructorsIterator.hasNext()) {
			monitor.checkCanceled();
			Function inlinedFunction = inlinedConstructorsIterator.next();

			List<Address> listOfClassRefsInFunction =
				getSortedListOfAncestorRefsInFunction(inlinedFunction, recoveredClass);

			if (!listOfClassRefsInFunction.isEmpty()) {

				Address markupAddress = listOfClassRefsInFunction.get(0);
				String markupString = classNamespace.getName(true) + "::" + className;

				String existingComment = api.getPreComment(markupAddress);
				if (existingComment != null) {
					existingComment = existingComment + "\n";
				}
				else {
					existingComment = "";
				}
				api.setPreComment(markupAddress,
					existingComment + "inlined constructor: " + markupString);
				bookmarkAddress(markupAddress, INLINE_CONSTRUCTOR_BOOKMARK + " " + markupString);
			}
		}
	}

	/**
	 * Method to add precomment inside functions containing inlined destructors at approximate
	 * address of start of inlined function
	 * @param recoveredClass current class
	 * @throws Exception when cancelled
	 */
	public void createInlinedDestructorComments(RecoveredClass recoveredClass) throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();
		String className = recoveredClass.getName();

		List<Function> inlinedDestructorList = recoveredClass.getInlinedDestructorList();
		Iterator<Function> inlinedDestructorIterator = inlinedDestructorList.iterator();
		while (inlinedDestructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function destructorFunction = inlinedDestructorIterator.next();
			Address classVftableRef =
				getClassVftableRefInFunction(destructorFunction, recoveredClass);

			//TODO: use this one instead if testing pans out
			Address otherWayRef = getClassVftableReference(recoveredClass, destructorFunction);

			if (classVftableRef == null) {
				continue;
			}

			//TODO: remove after testing
			if (!classVftableRef.equals(otherWayRef)) {
				if (DEBUG) {
					Msg.debug(this, recoveredClass.getName() + " function " +
						destructorFunction.getEntryPoint().toString() + " first ref: " +
						classVftableRef.toString() + " other way ref: " + otherWayRef.toString());
				}
			}

			String markupString = classNamespace.getName(true) + "::~" + className;
			api.setPreComment(classVftableRef, "inlined destructor: " + markupString);

			bookmarkAddress(classVftableRef, INLINE_DESTRUCTOR_BOOKMARK + " " + markupString);
		}
	}

	/**
	 * Method to add label on functions with inlined constructor or destructors but couldn't tell which
	 * @param recoveredClass current class
	 * @throws Exception when cancelled
	 */
	public void createIndeterminateInlineComments(RecoveredClass recoveredClass) throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();

		List<Function> functionsContainingInlineList = recoveredClass.getIndeterminateInlineList();
		Iterator<Function> functionsContainingInlineIterator =
			functionsContainingInlineList.iterator();
		while (functionsContainingInlineIterator.hasNext()) {
			monitor.checkCanceled();
			Function functionContainingInline = functionsContainingInlineIterator.next();

			Address classVftableRef =
				getClassVftableRefInFunction(functionContainingInline, recoveredClass);
			//TODO: use this one if testing more progs gives same results
			Address otherWayRef =
				getClassVftableReference(recoveredClass, functionContainingInline);

			if (classVftableRef == null) {
				continue;
			}
			//TODO: remove after testing
			if (!classVftableRef.equals(otherWayRef)) {
				if (DEBUG) {
					Msg.debug(this,
						recoveredClass.getName() + " function " +
							functionContainingInline.getEntryPoint().toString() + " first ref: " +
							classVftableRef.toString() + " other way ref: " +
							otherWayRef.toString());
				}
			}

			String markupString = "inlined constructor or destructor (approx location) for " +
				classNamespace.getName(true);
			api.setPreComment(classVftableRef, markupString);

			bookmarkAddress(classVftableRef, INDETERMINATE_INLINE_BOOKMARK + " " + markupString);
		}
	}

	/**
	 * Method to add label on constructor or destructors but couldn't tell which
	 * @param recoveredClass current class
	 * @throws Exception when cancelled
	 */
	public void createIndeterminateLabels(RecoveredClass recoveredClass) throws Exception {

		Namespace classNamespace = recoveredClass.getClassNamespace();
		String className = recoveredClass.getName();

		List<Function> unknownIfConstructorOrDestructorLIst = recoveredClass.getIndeterminateList();
		Iterator<Function> unknownsIterator = unknownIfConstructorOrDestructorLIst.iterator();
		while (unknownsIterator.hasNext()) {
			monitor.checkCanceled();
			Function indeterminateFunction = unknownsIterator.next();
			createNewSymbolAtFunction(indeterminateFunction,
				className + "_Constructor_or_Destructor", classNamespace, false, false);
		}
	}

	/**
	 * Method to create an ANALYSIS bookmark at the given address with the given comment
	 * @param address the given address
	 * @param comment the given comment
	 */
	public void bookmarkAddress(Address address, String comment) {

		BookmarkManager bookmarkMgr = program.getBookmarkManager();

		Bookmark bookmark =
			bookmarkMgr.getBookmark(address, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY);
		String bookmarkComment;
		if (bookmark != null && !bookmark.getComment().equals(comment) &&
			!containsString(bookmark.getComment(), comment)) {
			bookmarkComment = bookmark.getComment() + " + " + comment;
		}
		else {
			bookmarkComment = comment;
		}
		bookmarkMgr.setBookmark(address, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY, bookmarkComment);
	}

	/**
	 * Method to determine if the given comment string that has pieces separated by +'s has any
	 * piece exactly equal to the given string.
	 * @param bookmarkComment the bookmark comment string
	 * @param string the string to search for within the comment
	 * @return true if string is contained exactly within the +'s
	 */
	private boolean containsString(String bookmarkComment, String string) {

		// first split comment into pieces between the +'s
		String[] commentPieces = bookmarkComment.split("\\+");
		for (String piece : commentPieces) {
			// remove leading and trailing spaces from each piece
			int len = piece.length();

			if (piece.charAt(len - 1) == ' ') {
				piece = piece.substring(0, len - 2);
			}

			if (piece.charAt(0) == ' ') {
				piece = piece.substring(1);
			}

			// return true if any piece exactly equals the new string
			if (piece.equals(string)) {
				return true;
			}
		}

		// return false if string does not match any of the pieces
		return false;

	}

	/**
	 * Method to find the operator_delete function using the known deleting destructor functions
	 * @param recoveredClasses List of RecoveredClass objects
	 * @return operator_delete function or null if one cannot be determined
	 * @throws CancelledException when cancelled
	 * @throws Exception when issues creating labels
	 */
	private Function findOperatorDeleteUsingKnownDeletingDestructors(
			List<RecoveredClass> recoveredClasses) throws CancelledException, Exception {

		Function possibleOperatorDelete = null;
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<Function> deletingDestructors = recoveredClass.getDeletingDestructors();
			Iterator<Function> deletingDestructorIterator = deletingDestructors.iterator();
			while (deletingDestructorIterator.hasNext()) {
				monitor.checkCanceled();
				Function deletingDestructor = deletingDestructorIterator.next();

				if (deletingDestructorsThatCallDestructor.contains(deletingDestructor)) {
					Set<Function> calledFunctions = deletingDestructor.getCalledFunctions(monitor);

					// just use the ones that call two functions to find operator_delete
					if (calledFunctions.size() != 2) {
						return null;
					}
					// get first called function and verify it is on cd list
					Function firstCalledFunction =
						extraUtils.getCalledFunctionByCallOrder(deletingDestructor, 1);
					if (firstCalledFunction == null ||
						!recoveredClass.getConstructorOrDestructorFunctions()
								.contains(
									firstCalledFunction)) {
						return null;
					}

					// get second one and if operator_delete has not been assigned yet, assign it
					Function secondCalledFunction =
						extraUtils.getCalledFunctionByCallOrder(deletingDestructor, 2);
					if (secondCalledFunction == null) {
						return null;
					}

					// if we didn't already have one, set it here
					if (possibleOperatorDelete == null) {
						possibleOperatorDelete = secondCalledFunction;
					}
					// if we find another possibility and they don't match return null
					else if (!possibleOperatorDelete.equals(secondCalledFunction)) {
						return null;
					}
				}
			}
		}
		// If we get this far then we are sure the operator_delete function
		// is correct so assign the global variable. If its symbol is not already named then name it
		if (possibleOperatorDelete != null) {
			operator_delete = possibleOperatorDelete;
			if (possibleOperatorDelete.getSymbol().getSource() == SourceType.DEFAULT) {
				Msg.debug(this,
					"Found unlabeled operator delete that matched in all found deleting destructors: " +
						possibleOperatorDelete.getEntryPoint().toString() +
						". Creating label there.");
				api.createLabel(operator_delete.getEntryPoint(), "operator_delete", true);
			}
		}

		return possibleOperatorDelete;

	}

	/**
	 * 
	 * @param recoveredClass the given class
	 * @param virtualFunction the given virtual function
	 * @param operatorDeleteFunction the operator delete function
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	private void processClassDeletingDestructorByOperatorDelete(RecoveredClass recoveredClass,
			Function virtualFunction, Function operatorDeleteFunction)
			throws CancelledException, InvalidInputException, DuplicateNameException {

		// don't continue checking if it doesn't call operator_delete
		if (!extraUtils.doesFunctionACallFunctionB(virtualFunction, operatorDeleteFunction)) {
			return;
		}

		List<Function> ownConstructorOrDestructorFunctions =
			new ArrayList<Function>(recoveredClass.getConstructorOrDestructorFunctions());

		ownConstructorOrDestructorFunctions.removeAll(recoveredClass.getConstructorList());
		ownConstructorOrDestructorFunctions.removeAll(recoveredClass.getInlinedConstructorList());

		Iterator<Function> functionIterator = ownConstructorOrDestructorFunctions.iterator();
		while (functionIterator.hasNext()) {
			monitor.checkCanceled();
			Function function = functionIterator.next();

			//Type 4 - class c/d called from other than first vfunction
			if (extraUtils.doesFunctionACallFunctionB(virtualFunction, function)) {
				recoveredClass.addDeletingDestructor(virtualFunction);
				addDestructorToClass(recoveredClass, function);
				recoveredClass.removeIndeterminateConstructorOrDestructor(function);
				return;
			}
		}

		// Type 4 inlined - inlined class c/d called from other than first function
		// either just vftable ref before operator delete or vftableref followed by parent call
		// before operator delete

		Address vftableReference = getClassVftableReference(recoveredClass, virtualFunction);

		//TODO remove after testing against prev method in more progs
		Address otherWayRef = getClassVftableRefInFunction(virtualFunction, recoveredClass);
		if (vftableReference == null) {
			return;
		}
		if (!vftableReference.equals(otherWayRef)) {
			if (DEBUG) {
				Msg.debug(this, recoveredClass.getName() + " function " +
					virtualFunction.getEntryPoint().toString() + " first ref: " +
					vftableReference.toString() + " other way ref (with ances): " +
					otherWayRef.toString());
			}
		}

		List<Function> possibleParentDestructors = getPossibleParentDestructors(virtualFunction);

		boolean foundVftableRef = false;
		Function parentDestructor = null;

		AddressSetView virtualFunctionBody = virtualFunction.getBody();
		CodeUnitIterator virtualFunctionCodeUnits =
			program.getListing().getCodeUnits(virtualFunctionBody, true);
		while (virtualFunctionCodeUnits.hasNext()) {
			monitor.checkCanceled();
			CodeUnit codeUnit = virtualFunctionCodeUnits.next();
			Address codeUnitAddress = codeUnit.getAddress();

			if (codeUnitAddress.equals(vftableReference)) {
				foundVftableRef = true;
				continue;
			}

			Function referencedFunction = extraUtils.getReferencedFunction(codeUnitAddress, true);
			if (referencedFunction == null) {
				continue;
			}

			if (referencedFunction.equals(operatorDeleteFunction)) {
				// if find operator delete call before vftable ref then not valid deleting destructor
				if (!foundVftableRef) {
					return;
				}

				recoveredClass.addDeletingDestructor(virtualFunction);
				if (recoveredClass.getDestructorList().contains(virtualFunction)) {
					if (DEBUG) {
						Msg.debug(this, "Already created vfunction as a destructor");
					}
				}
				recoveredClass.removeFromConstructorDestructorList(virtualFunction);
				recoveredClass.removeIndeterminateConstructorOrDestructor(virtualFunction);
				recoveredClass.addInlinedDestructor(virtualFunction);

				if (parentDestructor == null) {
					return;
				}
				List<RecoveredClass> parentDestructorClasses = getClasses(parentDestructor);
				if (parentDestructorClasses == null) {
					return;
				}
				if (parentDestructorClasses.size() == 1) {
					if (!parentDestructorClasses.get(0)
							.getDestructorList()
							.contains(
								parentDestructor)) {
						addDestructorToClass(parentDestructorClasses.get(0), parentDestructor);
						parentDestructorClasses.get(0)
								.removeIndeterminateConstructorOrDestructor(
									parentDestructor);
					}
				}
				// if more than one parent class for this function then let either inline or multi-class
				// processing handle it later

				return;
			}

			if (possibleParentDestructors.contains(referencedFunction)) {
				// if find parent call before vftable ref then not valid deleting destructor
				if (!foundVftableRef) {
					return;
				}
				parentDestructor = referencedFunction;
				continue;
			}

		}

	}

	/**
	 * Method to remove functions from the class constructor/destructor lists (and the overall list) 
	 * that are not self-contained constructor/destructor functions. Add them to the list of 
	 * functions that contain inlined constructors or destructors.
	 * NOTE: this must be called after the global const/dest list is created but before 
	 * functions get added to the other class lists
	 * @param recoveredClasses list of classes to process
	 * @throws CancelledException if cancelled
	 */
	public void separateInlinedConstructorDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<Function> indeterminateFunctions = recoveredClass.getIndeterminateList();
			Iterator<Function> indeterminateIterator = indeterminateFunctions.iterator();
			while (indeterminateIterator.hasNext()) {
				monitor.checkCanceled();
				Function indeterminateFunction = indeterminateIterator.next();

				List<Address> vftableReferenceList = getVftableReferences(indeterminateFunction);
				if (vftableReferenceList == null) {
					continue;
				}

				// if inline, put on separate list and remove from indeterminate list
				// process later
				if (vftableReferenceList.size() > 1) {
					if (!areVftablesInSameClass(vftableReferenceList)) {
						recoveredClass.addIndeterminateInline(indeterminateFunction);
						indeterminateIterator.remove();
					}

					continue;
				}
			}
		}
	}

	/**
	 * Method to add the given structcure component to the given structure at the given offset 
	 * @param structureDataType the structure to add to
	 * @param structureToAdd the structure to add
	 * @param startOffset the starting offset where to add 
	 * @param endOffset the ending offset of the added structure
	 * @return the updated structure
	 * @throws CancelledException if cancelled
	 */
	public Structure addIndividualComponentsToStructure(Structure structureDataType,
			Structure structureToAdd, int startOffset, int endOffset) throws CancelledException {

		DataTypeComponent[] definedComponents = structureToAdd.getDefinedComponents();
		for (int ii = 0; ii < definedComponents.length; ii++) {

			monitor.checkCanceled();

			DataTypeComponent dataTypeComponent = structureToAdd.getComponent(ii);

			int dataComponentOffset = dataTypeComponent.getOffset();
			if (endOffset != NONE && (dataComponentOffset + startOffset) >= endOffset) {
				return structureDataType;
			}

			// This is to distinguish between class items and parent items in classes that 
			// have individual components of the parent split out and added to them and not just 
			// the whole parent structure added to them 
			// TODO: add method to get class obj using from the name of the structure
			// so i can get the shortened class name if a template and put that here instead
			String fieldname = structureToAdd.getName() + "_" + dataTypeComponent.getFieldName();

			structureDataType = structUtils.addDataTypeToStructure(structureDataType,
				startOffset + dataComponentOffset, dataTypeComponent.getDataType(), fieldname,
				monitor);
		}
		return structureDataType;
	}

	/**
	 * Method to add alignment to the given length based on the default program address size
	 * @param len the given length
	 * @return len updated with alignment size
	 */
	public int addAlignment(int len) {

		int mod = len % defaultPointerSize;
		int alignment = 0;
		if (mod != 0) {
			alignment = defaultPointerSize - mod;
			len += alignment;
		}
		return len;
	}

	/**
	 * Method to retrieve the offset of the virtual parent of the given class in the given structure
	 * @param recoveredClass the given class
	 * @param structure the given structure
	 * @return the offset of the virtual parent of the given class in the given structure
	 * @throws CancelledException if cancelled
	 */
	public int getOffsetOfVirtualParent(RecoveredClass recoveredClass, Structure structure)
			throws CancelledException {

		DataTypeComponent[] definedComponents = structure.getDefinedComponents();

		for (DataTypeComponent dataTypeComponent : definedComponents) {
			// if run into a virtual parent class structure, return its offset
			monitor.checkCanceled();
			if (isVirtualParentClassStructure(recoveredClass, dataTypeComponent.getDataType())) {
				return dataTypeComponent.getOffset();
			}
		}
		return NONE;

	}

	/**
	 * Method to determine if the given data type is the virtual parent class structure for the given class
	 * @param recoveredClass the given class
	 * @param dataType the given data type
	 * @return true if the given data type is the virtual parent class structure for the given class
	 * @throws CancelledException if cancelled
	 */
	private boolean isVirtualParentClassStructure(RecoveredClass recoveredClass, DataType dataType)
			throws CancelledException {

		// return false right away if it isn't even a structure
		if (!(dataType instanceof Structure)) {
			return false;
		}

		String parentClassName = dataType.getName();

		Map<RecoveredClass, Boolean> parentToBaseTypeMap = recoveredClass.getParentToBaseTypeMap();

		Set<RecoveredClass> parentClasses = parentToBaseTypeMap.keySet();
		Iterator<RecoveredClass> parentClassIterator = parentClasses.iterator();
		while (parentClassIterator.hasNext()) {

			monitor.checkCanceled();
			RecoveredClass parentClass = parentClassIterator.next();
			if (parentClass.getName().equals(parentClassName)) {
				Boolean isVirtualParent = parentToBaseTypeMap.get(parentClass);
				if (isVirtualParent) {
					return true;
				}
			}

		}
		return false;

	}

	/**
	 * Method to determine if all of a class's vftables are accounted for in its classOffsetToVftableMap
	 * @param recoveredClass the given class
	 * @return true if all vftables have a mapping, false otherwise
	 */
	public boolean isClassOffsetToVftableMapComplete(RecoveredClass recoveredClass) {

		if (recoveredClass.getClassOffsetToVftableMap()
				.values()
				.containsAll(
					recoveredClass.getVftableAddresses())) {
			return true;
		}
		return false;
	}

	/**
	 * Method to find deleting destructors that call a destructor but have no reference to a vftable
	 * @param recoveredClasses the list of classes
	 * @throws CancelledException if cancelled
	 */
	public void findDeletingDestructorsWithCallToDestructorWithNoVftableReference(
			List<RecoveredClass> recoveredClasses) throws CancelledException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			List<Function> virtualFunctions = recoveredClass.getAllVirtualFunctions();

			if (virtualFunctions == null) {
				continue;
			}

			Iterator<Function> vfIterator = virtualFunctions.iterator();
			while (vfIterator.hasNext()) {
				monitor.checkCanceled();
				Function vFunction = vfIterator.next();

				Set<Function> calledFunctions = vFunction.getCalledFunctions(monitor);
				if (calledFunctions.size() != 2) {
					continue;
				}

				// get first called function and verify is not a c/d function in current class or 
				// any class get second called function and verify it is operator delete
				Function firstCalledFunction =
					extraUtils.getCalledFunctionByCallOrder(vFunction, 1);
				Function secondCalledFunction =
					extraUtils.getCalledFunctionByCallOrder(vFunction, 2);
				if (firstCalledFunction != null && secondCalledFunction != null &&
					!recoveredClass.getConstructorOrDestructorFunctions()
							.contains(
								firstCalledFunction) &&
					secondCalledFunction.equals(operator_delete) &&
					!getAllConstructorsAndDestructors().contains(vFunction)) {
					recoveredClass.addDeletingDestructor(vFunction);
					recoveredClass.setVBaseDestructor(firstCalledFunction);
				}
			}
		}
	}

	/**
	 * Method to find destructors that have no parameters or return type
	 * @param recoveredClasses list of classes to process
	 * @throws CancelledException if cancelled
	 */
	public void findDestructorsWithNoParamsOrReturn(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {

			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<Function> indeterminateFunctions = recoveredClass.getIndeterminateList();
			Iterator<Function> indeterminateIterator = indeterminateFunctions.iterator();
			while (indeterminateIterator.hasNext()) {
				monitor.checkCanceled();
				Function indeterminateFunction = indeterminateIterator.next();

				DataType returnDataType =
					decompilerUtils.getDecompilerReturnType(indeterminateFunction);
				if (returnDataType == null) {
					continue;
				}

				String returnDataName = returnDataType.getDisplayName();
				//ParameterDefinition[] params = getParametersFromDecompiler(indeterminateFunction);
				ParameterDefinition[] params =
					decompilerUtils.getParametersFromDecompiler(indeterminateFunction);
				int numberParams = 0;

				if (params == null) {
					numberParams = indeterminateFunction.getParameterCount();
				}
				else {
					numberParams = params.length;
				}

				if (numberParams == 0 && returnDataName.equals("void")) {

					Address firstVftableReference =
						getFirstVftableReferenceInFunction(indeterminateFunction);
					if (firstVftableReference == null) {
						continue;
					}

					FillOutStructureCmd fillCmd =
						runFillOutStructureCmd(indeterminateFunction, firstVftableReference);

					if (fillCmd == null) {
						continue;
					}

					List<OffsetPcodeOpPair> stores = fillCmd.getStorePcodeOps();
					List<OffsetPcodeOpPair> loads = fillCmd.getLoadPcodeOps();
					stores = removePcodeOpsNotInFunction(indeterminateFunction, stores);
					loads = removePcodeOpsNotInFunction(indeterminateFunction, loads);

					if (loads == null || stores == null) {
						continue;
					}

					if (stores.size() == 1 && loads.size() == 0) {
						recoveredClass.addNonThisDestructor(indeterminateFunction);
						indeterminateIterator.remove();
					}
				}
			}
		}
	}

	/**
	 * Method to determine if the vftable reference(s) in a constructor are not in the first code 
	 * block for constructors that have more than one block
	 * @param recoveredClasses List of RecoveredClass objects
	 * @throws CancelledException when cancelled
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	public void findMoreInlinedConstructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException {
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<Function> constructorList = recoveredClass.getConstructorList();
			Iterator<Function> constructorIterator = constructorList.iterator();
			while (constructorIterator.hasNext()) {
				monitor.checkCanceled();
				Function constructor = constructorIterator.next();

				// get the references to the vftable(s) that are referenced in this function

				List<Address> referencesToVftablesFromFunction = getVftableReferences(constructor);

				if (referencesToVftablesFromFunction == null) {
					continue;
				}

				Collections.sort(referencesToVftablesFromFunction);
				Address firstVftableReferenceAddress = referencesToVftablesFromFunction.get(0);

				Address firstEndOfBlock = getEndOfFirstBlockAddress(constructor);
				if (firstEndOfBlock != null) {

					// not as reliable for virtual or multi-virtual inheritance so skip
					if (recoveredClass.inheritsVirtualAncestor() ||
						recoveredClass.hasMultipleVirtualInheritance()) {
						continue;
					}

					// if the first vftable reference is not in the first code block and the 
					// constructor calls any non-inherited constructors before the vtable reference, 
					// the constructor function is really another function with the constructor 
					// function inlined in it

					if (firstVftableReferenceAddress.compareTo(firstEndOfBlock) > 0) {
						if (doesFunctionCallAnyNonParentConstructorsBeforeVtableReference(
							recoveredClass, constructor, firstVftableReferenceAddress)) {

							// remove from the allConstructors too
							addInlinedConstructorToClass(recoveredClass, constructor);
							constructorIterator.remove();
							removeFromAllConstructors(constructor);

						}
					}
				}
			}
		}

	}

	/**
	 * Method to retrieve the address of the end of the first code block in the given function
	 * @param function the given function
	 * @return the address of the end of the first code block in the given function
	 * @throws CancelledException if cancelled
	 */
	private Address getEndOfFirstBlockAddress(Function function) throws CancelledException {

		Address instructionAddress = null;
		Listing listing = program.getListing();
		AddressSetView functionAddressSet = function.getBody();
		InstructionIterator instructionsIterator =
			listing.getInstructions(functionAddressSet, true);
		while (instructionsIterator.hasNext()) {
			monitor.checkCanceled();
			Instruction instruction = instructionsIterator.next();
			if (!instruction.isFallthrough() && (!instruction.getFlowType().isCall())) {
				instructionAddress = instruction.getAddress();
				return instructionAddress;
			}

		}

		return instructionAddress;

	}

	/**
	 * Method to run the FillOutStructureCmd and return a FillOutStructureCmd object when
	 * a high variable used to run the cmd is found that stores the given firstVftableReference 
	 * address.  
	 * @param function the given function
	 * @param firstVftableReference the first vftableReference in the given function
	 * @return FillOutStructureCmd for the highVariable that stores the firstVftableReference address
	 * or null if one isn't found.
	 * @throws CancelledException if cancelled
	 */
	public FillOutStructureCmd runFillOutStructureCmd(Function function,
			Address firstVftableReference) throws CancelledException {

		Address vftableAddress = getVftableAddress(firstVftableReference);

		if (vftableAddress == null) {
			return null;
		}

		// get the decompiler highFunction 
		HighFunction highFunction = decompilerUtils.getHighFunction(function);

		if (highFunction == null) {
			return null;
		}

		List<HighVariable> highVariables = new ArrayList<HighVariable>();

		// if there are params add the first or the "this" param to the list to be checked first 
		// It is the most likely to store the vftablePtr
		if (highFunction.getFunctionPrototype().getNumParams() > 0) {

			HighVariable thisParam =
				highFunction.getFunctionPrototype().getParam(0).getHighVariable();
			if (thisParam != null) {
				highVariables.add(thisParam);
			}
		}

		// add the other high variables that store vftable pointer
		highVariables.addAll(
			getVariableThatStoresVftablePointer(highFunction, firstVftableReference));

		Iterator<HighVariable> highVariableIterator = highVariables.iterator();

		while (highVariableIterator.hasNext()) {

			HighVariable highVariable = highVariableIterator.next();
			monitor.checkCanceled();

			FillOutStructureCmd fillCmd = new FillOutStructureCmd(program, location, tool);
			fillCmd.processStructure(highVariable, function);
			List<OffsetPcodeOpPair> stores = fillCmd.getStorePcodeOps();
			stores = removePcodeOpsNotInFunction(function, stores);

			// this method checks the storedPcodeOps to see if one is the vftable address
			Address storedVftableAddress = getStoredVftableAddress(stores);
			if (storedVftableAddress == null) {
				continue;
			}

			if (storedVftableAddress.equals(vftableAddress)) {
				return fillCmd;
			}

		}
		return null;
	}

	/**
	 * Method to figure out the indetermined inlined functions from each class as either combination 
	 * constructor/inlined constructor or destrucor/inlined destructor. The method first uses any 
	 * known called constructors or destructors to help determine which type then calls a method to 
	 * determine, using vftable order, which class contains the constructor/destructor and which 
	 * contains the inlined constructor/destructor.
	 * @param recoveredClasses List of classes
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if error setting return type
	 * @throws CancelledException when cancelled and others
	 */
	public void processInlinedConstructorsAndDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException,
			CircularDependencyException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			List<Function> inlineFunctionsList =
				new ArrayList<>(recoveredClass.getIndeterminateInlineList());

			Iterator<Function> inlineIterator = inlineFunctionsList.iterator();
			while (inlineIterator.hasNext()) {
				monitor.checkCanceled();

				Function inlineFunction = inlineIterator.next();

				// get the addresses in the function that refer to classes either by 
				// referencing a vftable in a class or by calling a function in a class
				// TODO: add the atexit refs and then check them - make a map of atexit call to class map if not already
				Map<Address, RecoveredClass> referenceToClassMap =
					getReferenceToClassMap(recoveredClass, inlineFunction);
				List<Address> referencesToFunctions =
					extraUtils.getReferencesToFunctions(referenceToClassMap);

				// if some of the references are to functions figure out if they are 
				// constructors destructors or add them to list of indetermined
				boolean isConstructor = false;
				boolean isDestructor = false;
				List<Address> referenceToIndeterminates = new ArrayList<Address>();

				if (!referencesToFunctions.isEmpty()) {
					Iterator<Address> functionReferenceIterator = referencesToFunctions.iterator();
					while (functionReferenceIterator.hasNext()) {

						monitor.checkCanceled();
						Address functionReference = functionReferenceIterator.next();
						Function function =
							extraUtils.getReferencedFunction(functionReference, true);
						if (function == null) {
							continue;
						}

						if (getAllConstructors().contains(function) ||
							getAllInlinedConstructors().contains(function)) {
							isConstructor = true;
							continue;
						}

						if (getAllDestructors().contains(function) ||
							getAllInlinedDestructors().contains(function)) {
							isDestructor = true;
							continue;
						}

						// TODO: refactor to make this function and refactor method that uses
						// it to use function instead of refiguring it out
						referenceToIndeterminates.add(functionReference);

					}

				}

				// if one or more is a constructor and none are destructors then the indeterminate
				// inline is is an inlined constructor
				if (isConstructor == true && isDestructor == false) {
					processInlineConstructor(recoveredClass, inlineFunction, referenceToClassMap);
				}
				// if one or more is a destructor and none are constructors then the indeterminate
				// inline is an inlined destructor
				else if (isConstructor == false && isDestructor == true) {
					processInlineDestructor(recoveredClass, inlineFunction, referenceToClassMap);
				}
				else {

					// otherwise, use pcode info to figure out if inlined constructor or destructor
					//If not already, make function a this call	
					makeFunctionThiscall(inlineFunction);

					List<OffsetPcodeOpPair> loads = getLoadPcodeOpPairs(inlineFunction);
					List<OffsetPcodeOpPair> stores = getStorePcodeOpPairs(inlineFunction);

					if (loads == null || stores == null) {
						Address firstVftableReferenceInFunction =
							getFirstVftableReferenceInFunction(inlineFunction);
						if (firstVftableReferenceInFunction == null) {
							continue;
						}
						FillOutStructureCmd fillOutStructureCmd =
							runFillOutStructureCmd(inlineFunction, firstVftableReferenceInFunction);

						if (fillOutStructureCmd == null) {
							continue;
						}

						loads = fillOutStructureCmd.getLoadPcodeOps();
						loads = removePcodeOpsNotInFunction(inlineFunction, loads);
						stores = fillOutStructureCmd.getStorePcodeOps();
						stores = removePcodeOpsNotInFunction(inlineFunction, stores);

						updateFunctionToStorePcodeOpsMap(inlineFunction, stores);
						updateFunctionToLoadPcodeOpsMap(inlineFunction, loads);

					}

					if (loads == null || stores == null) {
						continue;
					}

					// inlined constructor
					if (stores.size() > 1 && loads.size() == 0) {
						processInlineConstructor(recoveredClass, inlineFunction,
							referenceToClassMap);
						isConstructor = true;
					}

					// inlined destructor
					else if (stores.size() == 1 && loads.size() > 0) {
						processInlineDestructor(recoveredClass, inlineFunction,
							referenceToClassMap);
						isDestructor = true;
					}
				}

				if (!referenceToIndeterminates.isEmpty()) {
					// make the other referenced indeterminate c/d functions constructors
					if (isConstructor == true && isDestructor == false) {
						createListedConstructorFunctions(referenceToClassMap,
							referenceToIndeterminates);
						continue;
					}
					// make the other referenced indeterminate c/d functions destructors 
					if (isConstructor == false && isDestructor == true) {
						createListedDestructorFunctions(referenceToClassMap,
							referenceToIndeterminates);
						continue;
					}

				}

			}

		}
	}

	/**
	 * Method to retrieve the offset of the class data in the given structure
	 * @param recoveredClass the given class
	 * @param structure the given structure
	 * @return the offset of the class data in the given structure
	 * @throws CancelledException if cancelled
	 */
	public int getDataOffset(RecoveredClass recoveredClass, Structure structure)
			throws CancelledException {

		int offsetOfVirtualParent = getOffsetOfVirtualParent(recoveredClass, structure);

		int endOfData;
		if (offsetOfVirtualParent == NONE) {
			endOfData = structure.getLength();
		}
		else {
			// end of data is beginning of virt parent
			endOfData = offsetOfVirtualParent;
		}

		int dataLength =
			structUtils.getNumberOfUndefinedsBeforeOffset(structure, endOfData, monitor);
		if (dataLength < 0) {
			return NONE;
		}

		return endOfData - dataLength;

	}

	/**
	 * Method to process remaining indeterminate functions to determine if they are constructors or destructors
	 * @param recoveredClasses list of classes
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	public void processRemainingIndeterminateConstructorsAndDestructors(
			List<RecoveredClass> recoveredClasses) throws CancelledException, InvalidInputException,
			DuplicateNameException, CircularDependencyException {

		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();

			List<Function> indeterminateList = recoveredClass.getIndeterminateList();
			Iterator<Function> indeterminateIterator = indeterminateList.iterator();
			while (indeterminateIterator.hasNext()) {
				monitor.checkCanceled();
				Function indeterminateFunction = indeterminateIterator.next();

				// first try identifying useing known constructors and destructors
				boolean callsKnownConstructor = callsKnownConstructor(indeterminateFunction);
				boolean callsKnownDestrutor = callsKnownDestructor(indeterminateFunction);
				boolean callsAtexit =
					extraUtils.doesFunctionACallFunctionB(indeterminateFunction, atexit);

				if (callsKnownConstructor && !callsKnownDestrutor) {
					addConstructorToClass(recoveredClass, indeterminateFunction);
					indeterminateIterator.remove();
					continue;
				}
				if (!callsKnownConstructor && callsKnownDestrutor) {
					addDestructorToClass(recoveredClass, indeterminateFunction);
					indeterminateIterator.remove();
					continue;
				}

				if (!callsKnownConstructor && callsAtexit) {
					addDestructorToClass(recoveredClass, indeterminateFunction);
					indeterminateIterator.remove();
					continue;
				}

				// Next try identifying constructors using decompiler return type
				DataType decompilerReturnType =
					decompilerUtils.getDecompilerReturnType(indeterminateFunction);
				if (decompilerReturnType != null) {

					String returnDataName = decompilerReturnType.getDisplayName();
					if (returnDataName.contains("*") && !isFidFunction(indeterminateFunction)) {

						addConstructorToClass(recoveredClass, indeterminateFunction);
						indeterminateIterator.remove();
						continue;
					}
				}

				// Next try identifying using load/store information
				List<OffsetPcodeOpPair> loads = getLoadPcodeOpPairs(indeterminateFunction);

				List<OffsetPcodeOpPair> stores = getStorePcodeOpPairs(indeterminateFunction);

				if (loads == null || stores == null) {
					Address firstVftableReferenceInFunction =
						getFirstVftableReferenceInFunction(indeterminateFunction);
					if (firstVftableReferenceInFunction == null) {
						continue;
					}
					FillOutStructureCmd fillOutStructureCmd = runFillOutStructureCmd(
						indeterminateFunction, firstVftableReferenceInFunction);

					if (fillOutStructureCmd == null) {
						continue;
					}

					loads = fillOutStructureCmd.getLoadPcodeOps();
					loads = removePcodeOpsNotInFunction(indeterminateFunction, loads);
					stores = fillOutStructureCmd.getStorePcodeOps();
					stores = removePcodeOpsNotInFunction(indeterminateFunction, stores);

					updateFunctionToStorePcodeOpsMap(indeterminateFunction, stores);
					updateFunctionToLoadPcodeOpsMap(indeterminateFunction, loads);

				}

				if (loads == null || stores == null) {
					continue;
				}

				if (stores.size() > 1 && loads.size() == 0) {
					addConstructorToClass(recoveredClass, indeterminateFunction);
					indeterminateIterator.remove();
				}
				else if (stores.size() == 1 && loads.size() > 0) {
					addDestructorToClass(recoveredClass, indeterminateFunction);
					indeterminateIterator.remove();
				}

			}
		}

	}

	/**
	 * Method to determine if the given function is a "FID" function or one that has had function
	 * signature assigned by the FID (Function ID) Analyzer
	 * @param function the given function
	 * @return true if function is a FID function, false otherwise
	 */
	private boolean isFidFunction(Function function) {

		Address address = function.getEntryPoint();

		BookmarkManager bm = program.getBookmarkManager();

		Bookmark bookmark = bm.getBookmark(address, BookmarkType.ANALYSIS, "Function ID Analyzer");

		if (bookmark == null) {
			return false;
		}
		return true;
	}

	/**
	 * Method to identify missing functions using param to _atexit function
	 * because it always is passed a pointer to a function.
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if return type is not a fixed length
	 */
	public void findFunctionsUsingAtexit() throws CancelledException, InvalidInputException {

		Function atexitFunction = null;
		List<Function> atexitFunctions = extraUtils.getGlobalFunctions("_atexit");
		if (atexitFunctions.size() != 1) {
			return;
		}

		atexitFunction = atexitFunctions.get(0);
		atexit = atexitFunction;

		ReferenceIterator referenceIterator =
			program.getReferenceManager().getReferencesTo(atexitFunction.getEntryPoint());
		while (referenceIterator.hasNext()) {
			monitor.checkCanceled();
			Reference ref = referenceIterator.next();
			Address fromAddress = ref.getFromAddress();

			Function function = extraUtils.getFunctionContaining(fromAddress);
			if (function == null) {
				AddressSet subroutineAddresses =
					extraUtils.getSubroutineAddresses(program, fromAddress);
				Address minAddress = subroutineAddresses.getMinAddress();

				function = extraUtils.createFunction(minAddress, null);
				if (function == null) {
					continue;
				}
			}

			// get the decompiler highFunction 
			HighFunction highFunction = decompilerUtils.getHighFunction(function);

			if (highFunction == null) {
				continue;
			}

			Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps(fromAddress);
			while (pcodeOps.hasNext()) {
				monitor.checkCanceled();
				PcodeOpAST pcodeOp = pcodeOps.next();
				int opcode = pcodeOp.getOpcode();
				if (opcode == PcodeOp.CALL) {
					Varnode input = pcodeOp.getInput(1);
					if (input == null) {
						continue;
					}
					Address callingAddress = input.getPCAddress();
					if (callingAddress.equals(Address.NO_ADDRESS)) {
						continue;
					}

					Address calledAddress =
						decompilerUtils.getCalledAddressFromCallingPcodeOp(input);

					if (calledAddress == null) {
						continue;
					}

					Function calledFunction = extraUtils.getFunctionAt(calledAddress);
					if (calledFunction == null) {
						calledFunction = extraUtils.createFunction(calledAddress, null);
						if (calledFunction == null) {
							continue;
						}

						if (!atexitCalledFunctions.contains(calledFunction)) {
							atexitCalledFunctions.add(calledFunction);
						}
						calledFunction.setReturnType(DataType.VOID, SourceType.ANALYSIS);
					}
					else {
						if (!atexitCalledFunctions.contains(calledFunction)) {
							atexitCalledFunctions.add(calledFunction);
						}
					}

				}

			}

		}

	}

	/**
	 * Find deleting destructors using first vfunction on vtable
	 * @param recoveredClasses List of RecoveredClass objects
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	private void findFirstDeletingDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

			if (!recoveredClass.hasVftable()) {
				continue;
			}

			List<Address> vftableAddresses = recoveredClass.getVftableAddresses();
			Iterator<Address> vftableIterator = vftableAddresses.iterator();
			while (vftableIterator.hasNext()) {
				monitor.checkCanceled();
				Address vftableAddress = vftableIterator.next();

				// this gets the first function pointer in the vftable
				Function firstVirtualFunction = extraUtils.getPointedToFunction(vftableAddress);
				processDeletingDestructor(recoveredClass, firstVirtualFunction);
			}
		}
	}

	/**
	 * Find more deleting destructors by looking at other vfunctions to see if they call
	 * their own cd and also call operator_delete
	 * @param recoveredClasses List of RecoveredClass objects
	 * @throws CancelledException when script cancelled 
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws Exception if issues making label
	 */
	private void findMoreDeletingDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException, Exception {

		// first identify operator delete function
		Function operatorDeleteFunction =
			findOperatorDeleteUsingKnownDeletingDestructors(recoveredClasses);
		if (operatorDeleteFunction == null) {
			if (DEBUG) {
				Msg.debug(this,
					"Could not find operator delete function. Cannot process more deleting destructors.");
			}
			return;
		}

		// then use it to find more deleting destructors of type 3 (the ones that call their own
		// destructor)
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			if (!recoveredClass.hasVftable()) {
				continue;
			}

			List<Address> vftableAddresses = recoveredClass.getVftableAddresses();
			Iterator<Address> vftableAddressIterator = vftableAddresses.iterator();
			while (vftableAddressIterator.hasNext()) {
				monitor.checkCanceled();
				Address vftableAddress = vftableAddressIterator.next();

				Function firstVirtualFunction = extraUtils.getPointedToFunction(vftableAddress);
				List<Function> virtualFunctions =
					recoveredClass.getVirtualFunctions(vftableAddress);

				if (virtualFunctions == null) {
					continue;
				}

				Iterator<Function> virtualFunctionsIterator = virtualFunctions.iterator();
				while (virtualFunctionsIterator.hasNext()) {
					monitor.checkCanceled();
					Function virtualFunction = virtualFunctionsIterator.next();
					if (virtualFunction.equals(firstVirtualFunction)) {
						continue;
					}
					processClassDeletingDestructorByOperatorDelete(recoveredClass, virtualFunction,
						operatorDeleteFunction);
				}
			}
		}

	}

	/**
	 * Method to find deleting destructors that do one of the following:
	 * 	1. reference their own vftable (ie on own c/d list) which means function
	 *       is both a deleting destructor and has inlined the class destructor
	 *   2. reference their parent vftable (ie on parent c/d list) which means function
	 *       is a deleting destructor for class and inlined destructor for parent class
	 *   3. do not reference a vftable but call own destructor (call func on own c/d list) which
	 *       means it is just a deleting destructor for class but has no inlined destructor
	 * @param recoveredClass the given class
	 * @param firstVftableFunction the first vftableFunction a class vftable 
	 * @throws CancelledException if cancelled
	 * @throws DuplicateNameException if try to create same symbol name already in namespace 
	 * @throws InvalidInputException if issues setting return type
	 */
	private void processDeletingDestructor(RecoveredClass recoveredClass,
			Function firstVftableFunction)
			throws CancelledException, DuplicateNameException, InvalidInputException {

		// if the first function on the vftable IS ALSO on the class constructor/destructor list
		// then it is a deleting destructor with and inline destructor and we need to 
		// determine if the inline is the class or parent/grandparent class destructor
		if (getAllConstructorsAndDestructors().contains(firstVftableFunction)) {

			recoveredClass.addDeletingDestructor(firstVftableFunction);
			recoveredClass.removeFromConstructorDestructorList(firstVftableFunction);
			recoveredClass.removeIndeterminateConstructorOrDestructor(firstVftableFunction);

			List<Address> vftableReferences = getVftableReferences(firstVftableFunction);
			if (vftableReferences == null) {
				return;
			}
			Iterator<Address> vftableReferencesIterator = vftableReferences.iterator();
			while (vftableReferencesIterator.hasNext()) {
				monitor.checkCanceled();
				Address vftableReference = vftableReferencesIterator.next();
				Address vftableAddress = getVftableAddress(vftableReference);
				if (vftableAddress == null) {
					continue;
				}
				// Type 1
				if (recoveredClass.getVftableAddresses().contains(vftableAddress)) {
					recoveredClass.addInlinedDestructor(firstVftableFunction);
				}
				// Type 2
				else {
					//RecoveredClass parentClass = vftableToClassMap.get(vftableAddress);
					RecoveredClass parentClass = getVftableClass(vftableAddress);
					parentClass.addInlinedDestructor(firstVftableFunction);
					parentClass.removeFromConstructorDestructorList(firstVftableFunction);
					parentClass.removeIndeterminateConstructorOrDestructor(firstVftableFunction);
				}
			}

		}
		// else, if first function pointed to by the vftable CALLS a function on the constructor/destructor list
		// then it is a deleting destructor and we have identified a destructor function for the class
		else {
			processClassDeletingDestructor(recoveredClass, firstVftableFunction);
		}

	}

	/**
	 * Method to find deleting destructors that are the first function in the class vftable
	 * and call the class destructor
	 * @param recoveredClass the current class
	 * @param firstVirtualFunction the first function referenced by the class virtual function table
	 * @throws CancelledException when cancelled
	 * @throws InvalidInputException if issue setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	private void processClassDeletingDestructor(RecoveredClass recoveredClass,
			Function firstVirtualFunction)
			throws CancelledException, InvalidInputException, DuplicateNameException {

		List<Function> classConstructorOrDestructorFunctions =
			recoveredClass.getConstructorOrDestructorFunctions();

		Iterator<Function> functionIterator = classConstructorOrDestructorFunctions.iterator();
		while (functionIterator.hasNext()) {
			monitor.checkCanceled();

			Function function = functionIterator.next();

			if (extraUtils.doesFunctionACallFunctionB(firstVirtualFunction, function)) {
				recoveredClass.addDeletingDestructor(firstVirtualFunction);
				addDestructorToClass(recoveredClass, function);
				recoveredClass.removeIndeterminateConstructorOrDestructor(function);

				if (!deletingDestructorsThatCallDestructor.contains(firstVirtualFunction)) {
					deletingDestructorsThatCallDestructor.add(firstVirtualFunction);
				}
			}
		}
	}

	/**
	 * Use the known parent class(es)to determine which possible constructor destructor
	 * functions are constructors and which are destructors
	 * @param recoveredClasses List of RecoveredClass objects
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	public void processRegularConstructorsAndDestructorsUsingCallOrder(
			List<RecoveredClass> recoveredClasses) throws CancelledException, InvalidInputException,
			DuplicateNameException, CircularDependencyException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			List<RecoveredClass> parentsToProcess = recoveredClass.getParentList();

			if (parentsToProcess.isEmpty()) {
				continue;
			}

			Iterator<RecoveredClass> parentsToProcessIterator = parentsToProcess.iterator();

			while (parentsToProcessIterator.hasNext()) {

				monitor.checkCanceled();

				RecoveredClass parentToProcess = parentsToProcessIterator.next();
				processConstructorsAndDestructorsUsingParent(recoveredClass, parentToProcess);
			}
		}

	}

	/**
	 * Use known ancestor class constructors and destructors to help classify indeterminate ones
	 * by who they call, ie constructors call parent (or grandparent) constructors and destructors 
	 * call parent (or grandparent) destructors so use this to help figure out if the given class's 
	 * indeterminate functions are constructors or destructors. 
	 * @param recoveredClasses List of class objects
	 * @throws CancelledException if cancelled
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if error setting return type
	 */
	public void findConstructorsAndDestructorsUsingAncestorClassFunctions(
			List<RecoveredClass> recoveredClasses) throws CancelledException, InvalidInputException,
			DuplicateNameException, CircularDependencyException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			List<Function> indeterminateList = recoveredClass.getIndeterminateList();
			if (indeterminateList.isEmpty()) {
				continue;
			}

			List<Function> allAncestorConstructors = getAllAncestorConstructors(recoveredClass);
			List<Function> allAncestorDestructors = getAncestorDestructors(recoveredClass);

			Iterator<Function> indeterminateIterator = indeterminateList.iterator();
			while (indeterminateIterator.hasNext()) {

				monitor.checkCanceled();

				Function indeterminateFunction = indeterminateIterator.next();

				List<Function> possibleAncestorConstructors =
					getPossibleParentConstructors(indeterminateFunction);
				Function ancestorConstructor =
					getFunctionOnBothLists(possibleAncestorConstructors, allAncestorConstructors);

				List<Function> possibleAncestorDestructors =
					getPossibleParentDestructors(indeterminateFunction);
				Function ancestorDestructor =
					getFunctionOnBothLists(possibleAncestorDestructors, allAncestorDestructors);

				// skip if both null - no results
				if (ancestorConstructor == null && ancestorDestructor == null) {
					continue;
				}

				// skip if neither null - conflicting results
				if (ancestorConstructor != null && ancestorDestructor != null) {
					continue;
				}

				if (ancestorConstructor != null) {
					addConstructorToClass(recoveredClass, indeterminateFunction);
					indeterminateIterator.remove();
				}

				if (ancestorDestructor != null) {
					addDestructorToClass(recoveredClass, indeterminateFunction);
					indeterminateIterator.remove();
				}
			}
		}

	}

	/**
	 * Method to classify indeterminate inline functions as either constructors or destructors
	 * using called ancestor information (may call parent or higher ancestor) or might be the same 
	 * as a descendant constructor/destructor (ie a parent or ancestor is inlined into an 
	 * indeterminate function so the same function is on both the parent inline list and the 
	 * descendant regular list. 
	 * @param recoveredClasses list of classes
	 * @throws CancelledException if cancelled
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws InvalidInputException if error setting return type
	 */
	public void findInlineConstructorsAndDestructorsUsingRelatedClassFunctions(
			List<RecoveredClass> recoveredClasses) throws CancelledException, InvalidInputException,
			DuplicateNameException, CircularDependencyException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			List<Function> indeterminateList =
				new ArrayList<Function>(recoveredClass.getIndeterminateInlineList());

			if (indeterminateList.isEmpty()) {
				continue;
			}

			List<Function> allRelatedConstructors = getAllAncestorConstructors(recoveredClass);
			List<Function> allRelatedDestructors = getAncestorDestructors(recoveredClass);

			Iterator<Function> indeterminateIterator = indeterminateList.iterator();
			while (indeterminateIterator.hasNext()) {
				monitor.checkCanceled();
				Function indeterminateFunction = indeterminateIterator.next();

				// get the addresses in the function that refer to classes either by 
				// referencing a vftable in a class or by calling a function in a class
				Map<Address, RecoveredClass> referenceToClassMap =
					getReferenceToClassMap(recoveredClass, indeterminateFunction);

				List<Function> allDescendantConstructors =
					getAllDescendantConstructors(recoveredClass);
				if (allDescendantConstructors.contains(indeterminateFunction)) {
					processInlineConstructor(recoveredClass, indeterminateFunction,
						referenceToClassMap);
					continue;
				}

				List<Function> allDescendantDestructors =
					getAllDescendantDestructors(recoveredClass);
				if (allDescendantDestructors.contains(indeterminateFunction)) {
					processInlineDestructor(recoveredClass, indeterminateFunction,
						referenceToClassMap);
					continue;
				}

				List<Function> possibleAncestorConstructors =
					getPossibleParentConstructors(indeterminateFunction);

				Function ancestorConstructor =
					getFunctionOnBothLists(possibleAncestorConstructors, allRelatedConstructors);

				List<Function> possibleAncestorDestructors =
					getPossibleParentDestructors(indeterminateFunction);
				Function ancestorDestructor =
					getFunctionOnBothLists(possibleAncestorDestructors, allRelatedDestructors);

				// skip if both null - no results
				if (ancestorConstructor == null && ancestorDestructor == null) {
					continue;
				}

				// skip if both null - conflicting results
				if (ancestorConstructor != null && ancestorDestructor != null) {
					continue;
				}

				if (ancestorConstructor != null) {
					processInlineConstructor(recoveredClass, indeterminateFunction,
						referenceToClassMap);
					continue;
				}

				if (ancestorDestructor != null) {
					processInlineDestructor(recoveredClass, indeterminateFunction,
						referenceToClassMap);
					continue;
				}

			}
		}

	}

	/**
	 * Method to find destructors using functions called by atexit. If they are on the list of 
	 * indeterminate constructors or destructors and are called by atexit, then they are a 
	 * destructor.
	 * @param recoveredClasses list of classes
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if error setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	public void findDestructorsUsingAtexitCalledFunctions(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			List<Function> indeterminateList = recoveredClass.getIndeterminateList();

			Iterator<Function> indeterminateIterator = indeterminateList.iterator();
			while (indeterminateIterator.hasNext()) {
				monitor.checkCanceled();
				Function indeterminateFunction = indeterminateIterator.next();
				if (atexitCalledFunctions.contains(indeterminateFunction)) {
					recoveredClass.addNonThisDestructor(indeterminateFunction);
					indeterminateIterator.remove();
				}
			}

			List<Function> indeterminateInlineList = recoveredClass.getIndeterminateInlineList();

			Iterator<Function> indeterminateInlineIterator = indeterminateInlineList.iterator();
			while (indeterminateInlineIterator.hasNext()) {
				monitor.checkCanceled();
				Function indeterminateFunction = indeterminateInlineIterator.next();
				if (atexitCalledFunctions.contains(indeterminateFunction)) {
					addInlinedDestructorToClass(recoveredClass, indeterminateFunction);
					indeterminateInlineIterator.remove();
				}
			}
		}
	}

	/**
	 * Method that calls various methods to find deleting destructor functions which help
	 * identify class destructors
	 * @param recoveredClasses List of all class objects
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting return value
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws Exception if issues making label
	 */
	public void findDeletingDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException, Exception {

		findFirstDeletingDestructors(recoveredClasses);
		findMoreDeletingDestructors(recoveredClasses);
		findDeletingDestructorsWithCallToDestructorWithNoVftableReference(recoveredClasses);

	}

	/**
	 * Figure out which of the destructors that do not reference vftable are vbase destructors and
	 * which are destructors. 
	 * @param recoveredClasses List of RecoveredClass objects
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if error setting return type
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 */
	public void findRealVBaseFunctions(List<RecoveredClass> recoveredClasses)
			throws CancelledException, InvalidInputException, DuplicateNameException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			Function vBaseDestructor = recoveredClass.getVBaseDestructor();
			if (vBaseDestructor == null) {
				continue;
			}
			if (!hasVbaseDestructor(recoveredClass)) {
				addDestructorToClass(recoveredClass, vBaseDestructor);
				recoveredClass.setVBaseDestructor(null);
			}

		}
	}

	/**
	 * Method to create <class_name>_data structure for given class
	 * @param recoveredClass the class
	 * @param classStructure the given class structure
	 * @param dataLen the length of data
	 * @param dataOffset the offset of data
	 * @return the <class_name>_data structure containing the given classes data members
	 * @throws CancelledException if cancelled
	 */
	public Structure createClassMemberDataStructure(RecoveredClass recoveredClass,
			Structure classStructure, int dataLen, int dataOffset) throws CancelledException {

		Structure classDataStructure = new StructureDataType(recoveredClass.getClassPath(),
			recoveredClass.getName() + CLASS_DATA_STRUCT_NAME, dataLen, dataTypeManager);

		Structure computedClassDataStructure;

		if (recoveredClass.hasExistingClassStructure()) {
			computedClassDataStructure = recoveredClass.getExistingClassStructure();
		}
		else {
			computedClassDataStructure = recoveredClass.getComputedClassStructure();
		}

		if (computedClassDataStructure == null || computedClassDataStructure.getLength() == 0) {
			classDataStructure = (Structure) dataTypeManager.addDataType(classDataStructure,
				DataTypeConflictHandler.DEFAULT_HANDLER);
			return classDataStructure;
		}

		DataTypeComponent[] definedComponents = computedClassDataStructure.getDefinedComponents();

		for (DataTypeComponent definedComponent : definedComponents) {

			monitor.checkCanceled();

			int offset = definedComponent.getOffset() - dataOffset;

			// skip any components that have offset less than the skip length
			// for classes without parents the skip is in general just the vftable ptr length
			// for classes with parents the skip is the entire parent(s) length
			if (offset < 0) {
				continue;
			}

			if (offset >= dataLen) {
				continue;
			}

			DataType dataType = definedComponent.getDataType();
			if (dataType.getName().equals("undefined") && dataType.getLength() == 1) {
				dataType = new Undefined1DataType();
			}

			String fieldName = new String();
			String comment = null;

			// if the computed class struct has field name (ie from pdb) use it otherwise create one 
			if (definedComponent.getFieldName() == null) {
				fieldName = "offset_" + extraUtils.toHexString(offset, false, true);
			}
			else {
				fieldName = definedComponent.getFieldName();
				comment = definedComponent.getComment();
			}

			classDataStructure.replaceAtOffset(offset, dataType, dataType.getLength(), fieldName,
				comment);
		}

		// only set alignment if all the offsets have been accounted for
		if (classDataStructure.getNumComponents() == classDataStructure.getNumDefinedComponents()) {
			classDataStructure.setPackingEnabled(true);
		}
		classDataStructure = (Structure) dataTypeManager.addDataType(classDataStructure,
			DataTypeConflictHandler.DEFAULT_HANDLER);

		return classDataStructure;
	}

	/**
	 * Method to use the computed or existing class structure contents for the main class structure.
	 * This is called when there is not enough information to create a full structure.
	 * @param computedClassStructure the structure computed using pcode store information or using pdb information
	 * @param classStructureDataType the structure that is getting created in the data type manager
	 * @return the default class structure for this class
	 * @throws CancelledException if cancelled
	 */
	public Structure createDefaultStructure(Structure computedClassStructure,
			Structure classStructureDataType) throws CancelledException {

		DataTypeComponent[] definedComponents = computedClassStructure.getDefinedComponents();
		for (DataTypeComponent component : definedComponents) {
			monitor.checkCanceled();

			classStructureDataType = structUtils.addDataTypeToStructure(
				classStructureDataType, component.getOffset(), component.getDataType(),
				component.getFieldName(), monitor);
		}
		classStructureDataType = (Structure) dataTypeManager.addDataType(classStructureDataType,
			DataTypeConflictHandler.DEFAULT_HANDLER);

		return classStructureDataType;
	}

	/**
	 * Method to find the purecall function. 
	 * @param recoveredClasses List of RecoveredClass objects
	 * @throws CancelledException when cancelled
	 * @throws Exception when issue making label
	 */
	public void identifyPureVirtualFunction(List<RecoveredClass> recoveredClasses)
			throws CancelledException, Exception {

		Function possiblePureCall = null;

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			if (recoveredClass.hasChildClass()) {
				Function sameFunction = null;
				List<Function> deletingDestructors = recoveredClass.getDeletingDestructors();
				List<Function> virtualFunctions = recoveredClass.getAllVirtualFunctions();
				if (virtualFunctions.size() < 3) {
					continue;
				}
				Iterator<Function> vfunctionIterator = virtualFunctions.iterator();
				while (vfunctionIterator.hasNext()) {
					monitor.checkCanceled();
					Function vfunction = vfunctionIterator.next();
					// skip the deleting destructors
					if (deletingDestructors.contains(vfunction)) {
						continue;
					}
					if (sameFunction == null) {
						sameFunction = vfunction;
					}
					else if (!sameFunction.equals(vfunction)) {
						sameFunction = null;
						break;
					}

				}

				if (sameFunction == null) {
					continue;
				}

				// if we didn't already assign it, do it here
				if (possiblePureCall == null) {
					possiblePureCall = sameFunction;
				}
				// if they ever don't match return 
				else if (!possiblePureCall.equals(sameFunction)) {
					if (DEBUG) {
						Msg.debug(this, "Could not identify pure call. ");
					}
					return;
				}
			}
		}

		// If we get this far then we are sure the purecall function
		// is correct so assign the global variable to it
		if (possiblePureCall != null) {
			purecall = possiblePureCall;
			if (possiblePureCall.getSymbol().getSource() == SourceType.DEFAULT) {
				Msg.debug(this, "Found unlabeled purecall function: " +
					possiblePureCall.getEntryPoint().toString() + ". Creating label there.");
				api.createLabel(possiblePureCall.getEntryPoint(), "purecall", true);
			}
		}
	}

	/**
	 * Method to remove duplicate functions from the given list
	 * @param list the given list of functions
	 * @return the deduped list of functions
	 * @throws CancelledException if cancelled
	 */
	public List<Function> removeDuplicateFunctions(List<Function> list) throws CancelledException {

		List<Function> listOfUniqueFunctions = new ArrayList<Function>();

		Iterator<Function> listIterator = list.iterator();
		while (listIterator.hasNext()) {
			monitor.checkCanceled();
			Function function = listIterator.next();
			if (!listOfUniqueFunctions.contains(function)) {
				listOfUniqueFunctions.add(function);
			}
		}
		return listOfUniqueFunctions;
	}

	/**
	 * Method to remove duplicate addresses from the given list
	 * @param list the given list of functions
	 * @return the deduped list of functions
	 * @throws CancelledException if cancelled
	 */
	public List<Address> removeDuplicateAddresses(List<Address> list) throws CancelledException {

		List<Address> listOfUniqueAddresses = new ArrayList<Address>();

		Iterator<Address> listIterator = list.iterator();
		while (listIterator.hasNext()) {
			monitor.checkCanceled();
			Address address = listIterator.next();
			if (!listOfUniqueAddresses.contains(address)) {
				listOfUniqueAddresses.add(address);
			}
		}
		return listOfUniqueAddresses;
	}

	public List<Object> applyNewFunctionSignatures(Namespace classNamespace,
			List<Symbol> classVftableSymbols) throws CancelledException, DuplicateNameException,
			DataTypeDependencyException, InvalidInputException {

		List<Object> changedItems = new ArrayList<Object>();

		Iterator<Symbol> vftableIterator = classVftableSymbols.iterator();
		while (vftableIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol vftableSymbol = vftableIterator.next();
			Address vftableAddress = vftableSymbol.getAddress();
			Data data = api.getDataAt(vftableAddress);
			if (data == null) {
				continue;
			}
			DataType baseDataType = data.getBaseDataType();
			if (!(baseDataType instanceof Structure)) {
				continue;
			}

			Structure vfunctionStructure = (Structure) baseDataType;

			Category category = getDataTypeCategory(vfunctionStructure);

			if (category == null) {
				continue;
			}

			String classNameWithNamespace = classNamespace.getName(true);
			CategoryPath classPath = extraUtils.createDataTypeCategoryPath(
				classDataTypesCategoryPath, classNameWithNamespace);

			// check that the given vftable data type is in the right ClassDataTypes/<class_folder>
			// path
			if (!category.getCategoryPath().equals(classPath)) {
				continue;
			}

			if (vfunctionStructure.getName().startsWith(classNamespace.getName() + "_vftable")) {
				List<Object> newChangedItems =
					updateVfunctionDataTypes(data, vfunctionStructure, vftableAddress);
				changedItems = updateList(changedItems, newChangedItems);
			}
		}
		return changedItems;
	}

	/**
	 * Method to find any function signatures in the given vfunction structure that have changed
	 * and update the corresponding function definition data types
	 * @throws DuplicateNameException if duplicate name
	 * @throws DataTypeDependencyException if data dependency exception
	 * @throws InvalidInputException if invalid input in setName of function
	 * @throws CancelledException if cancelled
	 */
	private List<Object> updateVfunctionDataTypes(Data structureAtAddress,
			Structure vfunctionStructure,
			Address vftableAddress) throws DuplicateNameException, DataTypeDependencyException,
			InvalidInputException, CancelledException {

		List<Object> changedItems = new ArrayList<Object>();

		int numVfunctions = structureAtAddress.getNumComponents();

		for (int vfunctionIndex = 0; vfunctionIndex < numVfunctions; vfunctionIndex++) {
			Data dataComponent = structureAtAddress.getComponent(vfunctionIndex);

			Reference[] referencesFrom = dataComponent.getReferencesFrom();
			if (referencesFrom.length != 1) {
				continue;
			}
			Address functionAddress = referencesFrom[0].getToAddress();
			Function vfunction = api.getFunctionAt(functionAddress);
			if (vfunction == null) {
				continue;
			}
			if (vfunction.isThunk()) {
				Function thunkedFunction = vfunction.getThunkedFunction(true);
				vfunction = thunkedFunction;
			}

			FunctionSignature listingFunctionSignature = vfunction.getSignature();

			DataTypeComponent structureComponent = vfunctionStructure.getComponent(vfunctionIndex);

			FunctionDefinition componentFunctionDefinition =
				getComponentFunctionDefinition(structureComponent);
			if (componentFunctionDefinition == null) {
				return null;
			}

			// change to pass into method as fd
			FunctionDefinition newFunctionDefinition =
				(FunctionDefinition) listingFunctionSignature;

			if (!areEquivalentFunctionSignatures(componentFunctionDefinition,
				listingFunctionSignature)) {

				List<Object> changedStructs =
					applyNewFunctionDefinitionToComponents(structureComponent,
						newFunctionDefinition);
				if (changedStructs.isEmpty()) {
					continue;
				}

				changedItems = updateList(changedItems, changedStructs);

				// now update the listing function signatures for the items on the changed list
				List<Object> newChangedItems =
					updateFunctionSignaturesForChangedDefinitions(changedItems);
				changedItems = updateList(changedItems, newChangedItems);

			}
		}

		return changedItems;

	}

	private List<Object> updateFunctionSignaturesForChangedDefinitions(List<Object> changedItems)
			throws CancelledException {

		List<Object> newChangedItems = new ArrayList<>();

		if (changedItems.isEmpty()) {
			return newChangedItems;
		}

		for (Object changedItem : changedItems) {
			monitor.checkCanceled();
			if (changedItem instanceof DataTypeComponent) {
				DataTypeComponent changedStructureComponent = (DataTypeComponent) changedItem;

				DataType changedDataType = changedStructureComponent.getParent();
				if (!(changedDataType instanceof Structure)) {
					continue;
				}
				Structure changedStructure = (Structure) changedDataType;
				if (!changedStructure.getName().contains(VFTABLE_LABEL)) {
					continue;
				}

				Address vftableAddr;
				try {
					vftableAddr = getVftableAddress(changedStructure);
					if (vftableAddr == null) {
						continue;
					}

					Data vftableData = program.getListing().getDataAt(vftableAddr);
					if (vftableData == null) {
						continue;
					}

					changedItem = updateListingVfunctionSignature(vftableData,
						changedStructureComponent, vftableAddr);
					if (changedItem != null && !newChangedItems.contains(changedItem)) {
						newChangedItems.add(changedItem);
					}
				}

				catch (DuplicateNameException e) {
					continue;
				}
				catch (InvalidInputException e) {
					continue;
				}
				catch (DataTypeDependencyException e) {
					continue;
				}

			}

		}
		return newChangedItems;
	}

	private FunctionDefinition getComponentFunctionDefinition(
			DataTypeComponent structureComponent) {

		DataType componentDataType = structureComponent.getDataType();
		if (!(componentDataType instanceof Pointer)) {
			return null;
		}

		Pointer pointer = (Pointer) componentDataType;
		DataType pointedToDataType = pointer.getDataType();

		if (!(pointedToDataType instanceof FunctionDefinition)) {
			return null;
		}
		FunctionDefinition componentFunctionDefinition = (FunctionDefinition) pointedToDataType;
		return componentFunctionDefinition;
	}

	//TODO: use the below to find the dt's I need in the other methods
	//dataTypeManager.findDataTypes(name, list, caseSensitive, monitor);
	private Address getVftableAddress(Structure vftableStructure) throws CancelledException {

		SymbolIterator symbolIterator =
			symbolTable.getSymbolIterator("*" + VFTABLE_LABEL + "*", true);
		while (symbolIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol symbol = symbolIterator.next();
			Address address = symbol.getAddress();
			Data dataAt = program.getListing().getDataAt(address);
			if (dataAt.getDataType().equals(vftableStructure)) {
				return address;
			}
		}
		return null;
	}

	/**
	 * Method to get the FunctionDefinition data type pointed to by the given structure component
	 * @param structureComponent the given structure component
	 * @return the FunctionDefinition data type pointed to by the given structure component or null
	 * @throws DataTypeDependencyException if any data type dependency issues
	 * @throws CancelledException if cancelled
	 * @throws DuplicateNameException if duplicate data name
	 */
	private List<Object> applyNewFunctionDefinitionToComponents(
			DataTypeComponent structureComponent, FunctionDefinition newFunctionDefinition)
			throws DataTypeDependencyException, DuplicateNameException, CancelledException {

		List<Object> changedItems = new ArrayList<Object>();

		DataTypeComponent topParentComponent = getTopParentComponent(structureComponent);
		if (topParentComponent == null) {
			return changedItems;
		}

		try {
			List<Object> newItems =
				updateComponentFieldName(topParentComponent, newFunctionDefinition);
			if (newItems != null) {
				changedItems = updateList(changedItems, newItems);
			}
		}
		catch (DuplicateNameException e) {
			// do nothing
		}

		List<Object> newChangedItems =
			applyNewFunctionDefinition(topParentComponent, newFunctionDefinition);
		changedItems = updateList(changedItems, newChangedItems);

		Structure topParentVftableStructure = (Structure) topParentComponent.getParent();

		List<Object> updatedChildComponents = updateChildComponents(topParentVftableStructure,
			topParentComponent.getOrdinal(), newFunctionDefinition);

		changedItems = updateList(changedItems, updatedChildComponents);

		return changedItems;

	}

	private List<Object> updateChildComponents(Structure parentVftableStructure,
			int componentOrdinal, FunctionDefinition newFunctionDefinition)
			throws CancelledException {

		List<Object> changedItems = new ArrayList<Object>();
		List<Structure> childClassStructures = getChildClassStructures(parentVftableStructure);
		// get child classes only in this purecall case (other child cases will be handled below)
		// since they are the ones that have real function signature pointers then recursively 
		// call this method for them
		if (childClassStructures.isEmpty()) {
			return changedItems;
		}
		Structure parentClassStructure = getClassStructure(parentVftableStructure);
		for (Structure childClassStructure : childClassStructures) {
			monitor.checkCanceled();

			// use the category path to get the vftables in child class
			List<Structure> childVftableStructures =
				getVftableStructuresInClass(childClassStructure.getCategoryPath());

			Structure childVftableStruct =
				getCorrectChildVftableStruct(parentClassStructure, childVftableStructures);
			if (childVftableStruct == null) {
				continue;
			}

			// should always be big enough since it is inherited child but check anyway

			if (childVftableStruct.getNumComponents() - 1 < componentOrdinal) {
				continue;
			}
			DataTypeComponent childComponent = childVftableStruct.getComponent(componentOrdinal);
			List<Object> newChangedItems =
				applyNewFunctionDefinition(childComponent, newFunctionDefinition);
			changedItems = updateList(changedItems, newChangedItems);

//			try {
//				List<Object> newItems =
//					updateComponentFieldName(childComponent, newFunctionDefinition);
//				if (newItems != null) {
//					changedItems = updateList(changedItems, newItems);
//				}
//			}
//			catch (DuplicateNameException e) {
//				// do nothing
//			}

			// recursively call same method for children of child
			List<Object> newChildChangedItems =
				updateChildComponents(childVftableStruct, componentOrdinal, newFunctionDefinition);
			changedItems = updateList(changedItems, newChildChangedItems);
		}
		return changedItems;
	}

	private List<Object> applyNewFunctionDefinition(DataTypeComponent structureComponent,
			FunctionDefinition newFunctionDefinition) {

		List<Object> changedItems = new ArrayList<Object>();

		DataType componentDataType = structureComponent.getDataType();
		if (!(componentDataType instanceof Pointer)) {
			return changedItems;
		}

		Pointer pointer = (Pointer) componentDataType;
		DataType pointedToDataType = pointer.getDataType();

		if (!(pointedToDataType instanceof FunctionDefinition)) {
			return changedItems;
		}
		FunctionDefinition componentFunctionDefinition = (FunctionDefinition) pointedToDataType;

		if (!componentFunctionDefinition.isEquivalent(newFunctionDefinition)) {
			// if it is a purecall then don't update the function definition as it will always point
			// to the purecall function and we don't want to rename that function to the new name
			// since anyone calling purecall will call it
			if (!componentFunctionDefinition.getName().contains("purecall")) {
				// otherwise update data type with new new signature
				boolean changed =
					updateFunctionDefinition(componentFunctionDefinition, newFunctionDefinition);
				if (changed) {
					changedItems.add(componentFunctionDefinition);
				}
			}
		}

		// even if function defs are equal, the field name needs to be checked and updated
		String newFieldName = newFunctionDefinition.getName();
		if (!structureComponent.getFieldName().equals(newFieldName)) {
			try {
				structureComponent.setFieldName(newFieldName);
				Structure parentVftableStructure = (Structure) structureComponent.getParent();
				changedItems.add(parentVftableStructure);
				changedItems.add(structureComponent);
			}
			catch (DuplicateNameException e) {
				// don't add changed item
			}
		}

		if (componentFunctionDefinition.isEquivalent(newFunctionDefinition)) {
			return changedItems;
		}

		return changedItems;
	}

	private boolean updateFunctionDefinition(FunctionDefinition functionDefinition,
			FunctionDefinition newFunctionDefinition) {

		boolean changed = false;

		if (!functionDefinition.getName().equals(newFunctionDefinition.getName())) {
			try {
				functionDefinition.setName(newFunctionDefinition.getName());
				changed = true;
			}
			catch (InvalidNameException | DuplicateNameException e) {
				// don't update if an exception
			}

		}

		ParameterDefinition[] currentArgs = functionDefinition.getArguments();
		ParameterDefinition[] changedArgs = newFunctionDefinition.getArguments();

		// only update if there are differences and the func sigs have same length
		// if they don't have same length then something was possibly overridden in a child and
		// it needs to stay the same as it was except the name 

		if (!currentArgs.equals(changedArgs) && (currentArgs.length == changedArgs.length)) {
			ParameterDefinition[] newArgs = new ParameterDefinition[currentArgs.length];
			for (int i = 0; i < currentArgs.length; i++) {
				if (currentArgs[i].getName().equals("this") ||
					currentArgs[i].equals(changedArgs[i])) {
					newArgs[i] = currentArgs[i];
				}
				else {
					newArgs[i] = changedArgs[i];
					changed = true;
				}
			}
			if (changed) {
				functionDefinition.setArguments(newArgs);
			}

		}

		if (!functionDefinition.getReturnType().equals(newFunctionDefinition.getReturnType())) {
			functionDefinition.setReturnType(newFunctionDefinition.getReturnType());
			changed = true;
		}
		return changed;

	}

	/**
	 * Method to get the correct child vftable structure corresponding to the given parent structure
	 * @param parentStructure the given parent structure
	 * @param childVftableStructs the list of possible childVftable structures
	 * @return the child vftable structure corresponding to the given parent structure
	 * @throws CancelledException if cancelled
	 */
	private Structure getCorrectChildVftableStruct(Structure parentStructure,
			List<Structure> childVftableStructs) throws CancelledException {

		if (childVftableStructs.isEmpty()) {
			return null;
		}
		if (childVftableStructs.size() == 1) {
			return childVftableStructs.get(0);
		}
		// otherwise, use the name of the vftableStructure to verify parent
		for (Structure vftableStructure : childVftableStructs) {
			monitor.checkCanceled();
			String vftableSuffix = getForClassSuffix(vftableStructure.getName());
			String parentName = getParentClassNameFromForClassSuffix(vftableSuffix);

			if (parentStructure.getName().equals(parentName)) {
				return vftableStructure;
			}
		}
		return null;

	}

	private List<Structure> getChildClassStructures(Structure parentVftableStructure)
			throws CancelledException {

		Structure parentClassStructure = getClassStructure(parentVftableStructure);
		List<Structure> childClassStructures = new ArrayList<Structure>();

		Iterator<Structure> allStructures = dataTypeManager.getAllStructures();
		while (allStructures.hasNext()) {
			monitor.checkCanceled();

			Structure structure = allStructures.next();
			List<String> parentNames =
				getParentNamesFromClassStructureDescription(structure.getDescription());
			if (parentNames.isEmpty()) {
				continue;
			}
			if (parentNames.contains(parentClassStructure.getName())) {
				childClassStructures.add(structure);
			}

		}
		return childClassStructures;
	}

	/**
	 * Method to get the vftable structures in the given data type manager category path
	 * @param categoryPath the given data type manager category path
	 * @return the vftable structures in the given data type manager category path
	 * @throws CancelledException if cancelled
	 */
	private List<Structure> getVftableStructuresInClass(CategoryPath categoryPath)
			throws CancelledException {

		List<Structure> vftableStructures = new ArrayList<Structure>();
		Iterator<Structure> allStructures = dataTypeManager.getAllStructures();
		while (allStructures.hasNext()) {
			monitor.checkCanceled();
			Structure structure = allStructures.next();
			if (structure.getCategoryPath().equals(categoryPath) &&
				structure.getName().contains(VFTABLE_LABEL)) {
				vftableStructures.add(structure);
			}
		}
		return vftableStructures;
	}

	/**
	 * Method to get the class structure given a class's vftableStructure
	 * @param vftableStructure the given vftable structure
	 * @return the class structure associated with the given vftableStructure
	 */
	private Structure getClassStructure(Structure vftableStructure) {
		CategoryPath categoryPath = vftableStructure.getCategoryPath();
		int endingIndex = vftableStructure.getName().indexOf('_');
		String className = vftableStructure.getName().substring(0, endingIndex);
		Structure classStructure = (Structure) dataTypeManager.getDataType(categoryPath, className);
		return classStructure;

	}

	private DataTypeComponent getTopParentComponent(DataTypeComponent component)
			throws CancelledException {

		DataTypeComponent currentTopComponent = getParentComponent(component);
		if (currentTopComponent == null) {
			return component;
		}

		DataTypeComponent nextTopComponent = currentTopComponent;
		// if the first one is null return that null
		// otherwise, return the last one before a null is reached
		while (true) {
			monitor.checkCanceled();
			if (nextTopComponent == null) {
				return currentTopComponent;
			}
			nextTopComponent = getParentComponent(currentTopComponent);
		}

	}

	/**
	 * Method to get the parent component associated with the given component or null if there isn't one
	 * @param component the given vftable component
	 * @return the associated parent vftable component or null if doesn't exist or cannot be determined
	 * @throws CancelledException if cancelled
	 */
	private DataTypeComponent getParentComponent(DataTypeComponent component)
			throws CancelledException {

		DataType vftableDataType = component.getParent();
		if (!vftableDataType.getName().contains(VFTABLE_LABEL)) {
			return null;
		}

		if (!(vftableDataType instanceof Structure)) {
			return null;
		}

		Structure vftableStructure = (Structure) vftableDataType;

		Structure classStructure = getClassStructure(vftableStructure);

		if (classStructure == null) {
			return null;
		}

		// parse the description to get class parent names
		List<String> parentNames =
			getParentNamesFromClassStructureDescription(classStructure.getDescription());
		if (parentNames.isEmpty()) {
			return null;
		}

		String parentName = new String();
		if (parentNames.size() == 1) {
			parentName = parentNames.get(0);
		}
		else {
			// otherwise, use the name of the vftableStructure to get the correct parent
			String vftableSuffix = getForClassSuffix(vftableStructure.getName());
			String possibleParentName = getParentClassNameFromForClassSuffix(vftableSuffix);
			if (parentNames.contains(possibleParentName)) {
				parentName = possibleParentName;
			}
		}

		if (parentName.isEmpty()) {
			return null;
		}

		Structure parentStructure = getParentClassStructure(classStructure, parentName);

		CategoryPath parentCategoryPath = parentStructure.getCategoryPath();

		List<Structure> parentVftableStructs = getVftableStructuresInClass(parentCategoryPath);
		if (parentVftableStructs.size() != 1) {
			// either no vftable so can't get a component or more than one and we can't determine
			// which is the correct vftable
			// TODO: investigate how to determine correct vftable if parent has more than one
			return null;
		}

		if (parentVftableStructs.get(0).getNumComponents() - 1 >= component.getOrdinal()) {
			return parentVftableStructs.get(0).getComponent(component.getOrdinal());
		}
		return null;

	}

	/**
	 * Method to get parent names out of class structure description field
	 * @param description the string containing the class structure description field contents
	 * @return a list of parent names contained in the class structure description
	 * @throws CancelledException if cancelled
	 */
	private List<String> getParentNamesFromClassStructureDescription(String description)
			throws CancelledException {

		List<String> parentNames = new ArrayList<String>();
		while (description.contains(":")) {
			monitor.checkCanceled();

			int indexOfColon = description.indexOf(":", 0);

			description = description.substring(indexOfColon + 1);

			int endOfBlock = description.indexOf(":", 0);
			if (endOfBlock == -1) {
				endOfBlock = description.length();
			}

			String parentName = description.substring(0, endOfBlock);

			description = description.substring(endOfBlock);

			parentName = parentName.replace("virtual", "");
			parentName = parentName.replace(" ", "");
			parentNames.add(parentName);
		}
		return parentNames;
	}

	private Structure getParentClassStructure(Structure childClassStructure, String nameOfParent)
			throws CancelledException {

		DataTypeComponent[] components = childClassStructure.getComponents();
		for (DataTypeComponent component : components) {
			monitor.checkCanceled();
			DataType componentDataType = component.getDataType();
			if (componentDataType.getName().equals(nameOfParent)) {
				return (Structure) componentDataType;
			}
		}
		return null;
	}

	private List<Object> updateList(List<Object> mainList, List<Object> itemsToAdd)
			throws CancelledException {

		if (itemsToAdd.isEmpty()) {
			return mainList;
		}

		for (Object item : itemsToAdd) {
			monitor.checkCanceled();
			if (!mainList.contains(item)) {
				mainList.add(item);
			}
		}
		return mainList;
	}

	public List<Structure> getStructuresOnList(List<Object> list) throws CancelledException {

		List<Structure> structures = new ArrayList<Structure>();
		for (Object item : list) {
			monitor.checkCanceled();
			if (item instanceof Structure) {
				structures.add((Structure) item);
			}
		}
		return structures;
	}

	public List<FunctionDefinition> getFunctionDefinitionsOnList(List<Object> list)
			throws CancelledException {

		List<FunctionDefinition> functionDefs = new ArrayList<FunctionDefinition>();
		for (Object item : list) {
			monitor.checkCanceled();
			if (item instanceof FunctionDefinition) {
				functionDefs.add((FunctionDefinition) item);
			}
		}
		return functionDefs;
	}

	public List<Function> getFunctionsOnList(List<Object> list) throws CancelledException {

		List<Function> functions = new ArrayList<Function>();
		for (Object item : list) {
			monitor.checkCanceled();
			if (item instanceof Function) {
				functions.add((Function) item);
			}
		}
		return functions;
	}

	public List<Object> applyNewFunctionDefinitions(Namespace classNamespace,
			List<Symbol> classVftableSymbols) throws CancelledException, DuplicateNameException,
			DataTypeDependencyException, InvalidInputException {

		List<Object> changedItems = new ArrayList<Object>();

		Iterator<Symbol> vftableIterator = classVftableSymbols.iterator();
		while (vftableIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol vftableSymbol = vftableIterator.next();
			Address vftableAddress = vftableSymbol.getAddress();
			Data data = api.getDataAt(vftableAddress);
			if (data == null) {
				continue;
			}
			DataType baseDataType = data.getBaseDataType();
			if (!(baseDataType instanceof Structure)) {
				continue;
			}

			Structure vfunctionStructure = (Structure) baseDataType;

			Category category = getDataTypeCategory(vfunctionStructure);

			if (category == null) {
				continue;
			}

			// check that the structure name starts with <classname>_vtable and that it is in 
			// the dt folder with name <classname>
			if (category.getName().equals(classNamespace.getName()) &&
				vfunctionStructure.getName().startsWith(classNamespace.getName() + "_vftable")) {

				DataTypeComponent[] vfunctionComponents = vfunctionStructure.getComponents();
				for (DataTypeComponent vfunctionComponent : vfunctionComponents) {
					monitor.checkCanceled();
					Object changedItem =
						updateListingVfunctionSignature(data, vfunctionComponent, vftableAddress);
					if (changedItem != null && !changedItems.contains(changedItem)) {
						changedItems.add(changedItem);

						FunctionDefinition newFunctionDefinition =
							getComponentFunctionDefinition(vfunctionComponent);
						if (newFunctionDefinition == null) {
							continue;
						}

						List<Object> changedStructs =
							applyNewFunctionDefinitionToComponents(vfunctionComponent,
								newFunctionDefinition);
						if (changedStructs.isEmpty()) {
							continue;
						}

						changedItems = updateList(changedItems, changedStructs);
					}
				}
			}
		}
		List<Object> newChangedItems = updateFunctionSignaturesForChangedDefinitions(changedItems);
		changedItems = updateList(changedItems, newChangedItems);

		return changedItems;

	}

	/**
	 * Method to find any function definitions in the given vfunction structure that have changed
	 * and update the function signature data types
	 * @throws DuplicateNameException if try to rename with a duplicate name
	 * @throws DataTypeDependencyException if data type dependency error
	 * @throws InvalidInputException  if invalid name input
	 * @throws CancelledException if cancelled
	 */
	private Object updateListingVfunctionSignature(Data listingVftable,
			DataTypeComponent structureComponent,
			Address vftableAddress) throws DuplicateNameException, DataTypeDependencyException,
			InvalidInputException, CancelledException {

		int numVfunctions = listingVftable.getNumComponents();

		int newComponentOrdinal = structureComponent.getOrdinal();
		if (newComponentOrdinal > numVfunctions - 1) {
			return null;
		}

		Data dataComponent = listingVftable.getComponent(newComponentOrdinal);

		Reference[] referencesFrom = dataComponent.getReferencesFrom();
		if (referencesFrom.length != 1) {
			return null;
		}
		Address functionAddress = referencesFrom[0].getToAddress();
		Function vfunction = api.getFunctionAt(functionAddress);
		if (vfunction == null) {
			return null;
		}

		if (vfunction.isThunk()) {
			vfunction = vfunction.getThunkedFunction(true);
		}

		FunctionSignature listingFunctionSignature = vfunction.getSignature();

		DataType componentDataType = structureComponent.getDataType();
		if (!(componentDataType instanceof Pointer)) {
			return null;
		}

		Pointer pointer = (Pointer) componentDataType;
		DataType pointedToDataType = pointer.getDataType();

		if (!(pointedToDataType instanceof FunctionDefinition)) {
			return null;
		}

		FunctionDefinition newFunctionDefinition = (FunctionDefinition) pointedToDataType;

		if (areEquivalentFunctionSignatures(newFunctionDefinition, listingFunctionSignature)) {
			return null;
		}

		boolean changed = updateFunctionSignature(vfunction, newFunctionDefinition);
		if (changed) {
			return vfunction;
		}

		return null;

	}

	private boolean updateFunctionSignature(Function function,
			FunctionDefinition newFunctionDefinition) {

		if (!newFunctionDefinition.getName().equals(function.getName())) {
			try {
				function.setName(newFunctionDefinition.getName(), SourceType.USER_DEFINED);
				return true;
			}
			catch (DuplicateNameException | InvalidInputException e) {
				return false;
			}
		}

		// update function signature at vfunction address with the function signature in the structure
		AddressSet functionStart =
			new AddressSet(function.getEntryPoint(), function.getEntryPoint());
		List<DataTypeManager> dataTypeManagers = new ArrayList<>();
		dataTypeManagers.add(program.getDataTypeManager());
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(dataTypeManagers,
			functionStart,
			SourceType.USER_DEFINED, true, false);
		cmd.applyTo(program);
		return true;
	}

	/**
	 * Method to compare the given FunctionDefinition data type with the given FunctionSignature to
	 * see if they are equivalent (ie same name, same return type, same param types, same param names, 
	 * same calling convention, same hasVarArgs flag ...
	 * @param definition the given FunctionDefinition data type
	 * @param signature the given FunctionSignature
	 * @return true if the two are equivalent, false other wise
	 */
	public boolean areEquivalentFunctionSignatures(FunctionDefinition definition,
			FunctionSignature signature) {

		if ((DataTypeUtilities.equalsIgnoreConflict(signature.getName(), definition.getName())) &&
			DataTypeUtilities.isSameOrEquivalentDataType(definition.getReturnType(),
				signature.getReturnType()) &&
			(definition.getGenericCallingConvention() == signature.getGenericCallingConvention()) &&
			(definition.hasVarArgs() == signature.hasVarArgs())) {
			ParameterDefinition[] sigargs = signature.getArguments();
			ParameterDefinition[] defArgs = definition.getArguments();
			if (sigargs.length == defArgs.length) {
				for (int i = 0; i < sigargs.length; i++) {
					if (!defArgs[i].isEquivalent(sigargs[i])) {
						return false;
					}
					if (!defArgs[i].getName().equals(sigargs[i].getName())) {
						return false;
					}
				}
				return true;
			}
		}
		return false;
	}

	private List<Object> updateComponentFieldName(DataTypeComponent structureComponent,
			FunctionDefinition newFunctionSignature)
			throws DuplicateNameException {

		List<Object> changedItems = new ArrayList<Object>();
		if (!structureComponent.getFieldName().equals(newFunctionSignature.getName())) {
			structureComponent.setFieldName(newFunctionSignature.getName());
			changedItems.add(structureComponent);
			changedItems.add(structureComponent.getParent());
			return changedItems;
		}
		return null;
	}

	public List<Symbol> getClassVftableSymbols(Namespace classNamespace)
			throws CancelledException {

		List<Symbol> vftableSymbols = new ArrayList<Symbol>();

		SymbolIterator symbols = symbolTable.getSymbols(classNamespace);
		while (symbols.hasNext()) {

			monitor.checkCanceled();
			Symbol symbol = symbols.next();
			if (symbol.getName().equals("vftable") ||
				symbol.getName().substring(1).startsWith("vftable")) {
				vftableSymbols.add(symbol);
			}

		}
		return vftableSymbols;
	}

	public Namespace getClassNamespace(Address address) {
		Symbol primarySymbol = symbolTable.getPrimarySymbol(address);

		if (primarySymbol == null) {
			Function functionContaining = api.getFunctionContaining(address);
			if (functionContaining != null) {
				primarySymbol =
					program.getSymbolTable().getPrimarySymbol(functionContaining.getEntryPoint());
			}
			else {
				Data dataContaining = api.getDataContaining(address);
				if (dataContaining != null) {
					primarySymbol =
						program.getSymbolTable().getPrimarySymbol(dataContaining.getMinAddress());
				}
			}
			if (primarySymbol == null) {
				return null;
			}
		}

		Namespace classNamespace = primarySymbol.getParentNamespace();
		if (classNamespace.isGlobal()) {
			return null;
		}

		return classNamespace;
	}

	private Category getDataTypeCategory(DataType dataType) {

		CategoryPath originalPath = dataType.getCategoryPath();
		Category category = dataTypeManager.getCategory(originalPath);

		return category;
	}

}
