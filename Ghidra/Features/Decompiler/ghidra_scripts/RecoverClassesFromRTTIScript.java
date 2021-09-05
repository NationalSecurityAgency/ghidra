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
// PROTOTYPE Script to recover class information using RTTI structures.  
// Note: This script does not compile on versions of Ghidra prior to 9.2 or in 9.2.1.
// This script uses information found in RTTI structures to figure out
// class hierarchy, inheritance types, constructors and destructors, class data types, and more.
// If program has pdb information, it uses it to help fill in class structures with known names
// and types for class member data. 
// If program does not have pdb, or incomplete pdb data types, it uses the decompiler pcode store
// information to fill in class structures with assumed data types for class member data. These
// data types are not always complete and may be filled in with undefined place holders of
// the same size as the associated data.
// There are many options that can be changed by editing flags at the top of the script.
// There are options to find missing functions that have not been disassembled, print or output 
// class information in various formats, and to graph the class hierarchies. 
// To best see the results of this script, look in the SymbolTree in the Classes folder. If a class
// has RTTI, you will see the class functions, vftable(s), and more there. Click on class functions
// and look at them in the decompiler to see how the class data types have improved the decompiler
// results. To see class data definitions, either hover on the this param in the decompiler or look
// in the DataTypeManager/<program_name>/ClassDataTypes/<class_name> folder. 
// NOTE: As this is a prototype script, the location, names, and design of data types created by 
// this script and default vfunctions named by this script are likely to change in the future 
// once an official design for Object Oriented representation is determined.  
// NOTE: Windows class recovery is more complete and tested than gcc class recovery, which is still 
// in early stages of development. Gcc class data types are only recovered for classes without multiple or
// virtual inheritance but if the program contains DWARF, there will be some amount of data recovered 
// by the DWARF analyzer.
// NOTE: For likely the best results, run this script on freshly analyzed programs. No testing has been 
// done on user marked-up programs. 
// NOTE: After running this script if you edit function signatures in the listing for a particular
// class and wish to update the corresponding class data function definition data types (vftable 
// structure field names, ...) then you can run the ApplyClassFunctionSignatureUpdatesScript.java 
// to have it do so for you. See that script's description for more info.
// Conversely, if you update a particular class's function definitions in the data type manager and  
// wish to have related function signatures in the listing updated, as well as other data types that 
// are related, then run the ApplyClassFunctionDefinitionsUpdatesScript.java to do so. See that script's
// description for more info. At some point, the Ghidra API will be updated to do the updates 
// automatically instead of needing the mentioned scripts to do so. 

//@category C++

import java.io.File;
import java.io.PrintWriter;
import java.util.*;
import java.util.stream.Collectors;

import classrecovery.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.core.analysis.DecompilerFunctionAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunctionImporter;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

public class RecoverClassesFromRTTIScript extends GhidraScript {

	// print c-like class definitions to the console
	private static final boolean PRINT_CLASS_DEFINITIONS = false;

	// print class information (parent class, children classes, vfunctions, member data) to console
	private static final boolean PRINT_CLASS_INFO = false;

	// print class parent(s) and children classes to console 
	private static final boolean PRINT_CLASS_PARENTS_AND_CHILDREN = false;

	// print one line hierarchy for each class with no children (child : parent : grandparent: ...)
	// if multiple inheritance print multiple parents on new line directly below end of their child 
	private static final boolean PRINT_CLASS_HIERARCHIES = false;

	// these do the same as above but print to a file
	private static final boolean OUTPUT_CLASS_DEFINITIONS = false;
	private static final boolean OUTPUT_CLASS_INFO = false;
	private static final boolean OUTPUT_CLASS_PARENTS_AND_CHILDREN = false;
	private static final boolean OUTPUT_SIMPLE_CLASS_HIERARCHIES = false;

	// print counts of found items
	private static final boolean PRINT_COUNTS = true;

	// recommended to find missing RTTI structure info in older programs and to find any missing 
	// potential constructor destructor functions because analysis did not make them functions yet. 
	// They are either undefined bytes or code that is not in a function. 
	private static final boolean FIXUP_PROGRAM = true;

	// bookmark all constructor/destructor functions figured out by this script
	private static final boolean BOOKMARK_FOUND_FUNCTIONS = true;

	// show a graph of class hierarchies after script is complete
	// no parent = blue vertex
	// single parent = green vertex
	// multiple parents = red vertex
	// edge between child and parent is orange if child inherits the parent virtually
	// edge between child and parent is lime green if child inherits the parent non-virtually
	private static final boolean GRAPH_CLASS_HIERARCHIES = false;

	// show shortened class template names in class structure field names
	private static final boolean USE_SHORT_TEMPLATE_NAMES_IN_STRUCTURE_FIELDS = true;

	private static final String CLASS_DATA_STRUCT_NAME = "_data";

	private static final String CONSTRUCTOR_BOOKMARK = "CONSTRUCTOR";
	private static final String DESTRUCTOR_BOOKMARK = "DESTRUCTOR";

	private static final String INDETERMINATE_BOOKMARK = "INDETERMINATE";

	boolean programHasRTTIApplied = false;
	boolean hasDebugSymbols;
	boolean isGcc = false;
	boolean isWindows = false;
	String ghidraVersion = null;

	DecompilerScriptUtils decompilerUtils;
	DataTypeManager dataTypeManager;

	int defaultPointerSize;

	RTTIClassRecoverer recoverClassesFromRTTI;

	ExtraScriptUtils extraUtils;

	boolean nameVfunctions = false;

	@Override
	public void run() throws Exception {

		String errorMsg = validate();
		if (!errorMsg.isEmpty()) {
			println(errorMsg);
			return;
		}


		if (isWindows()) {

			hasDebugSymbols = isPDBLoadedInProgram();
			nameVfunctions = !hasDebugSymbols;
			recoverClassesFromRTTI = new RTTIWindowsClassRecoverer(currentProgram,
				currentLocation, state.getTool(), this, BOOKMARK_FOUND_FUNCTIONS,
				USE_SHORT_TEMPLATE_NAMES_IN_STRUCTURE_FIELDS, nameVfunctions, hasDebugSymbols,
				monitor);
		}
		else if (isGcc()) {

			boolean runGcc = askYesNo("GCC Class Recovery Still Under Development",
				"I understand that gcc class recovery is still under development and my results will be incomplete but want to run this anyway.");
			if (!runGcc) {
				return;
			}

			hasDebugSymbols = isDwarfLoadedInProgram();
			if (hasDwarf() && !hasDebugSymbols) {
				println(
					"The program contains DWARF but the DWARF analyzer has not been run. Please run the DWARF analyzer to get best results from this script.");
				return;
			}
			nameVfunctions = !hasDebugSymbols;
			recoverClassesFromRTTI = new RTTIGccClassRecoverer(currentProgram, currentLocation,
				state.getTool(), this, BOOKMARK_FOUND_FUNCTIONS,
				USE_SHORT_TEMPLATE_NAMES_IN_STRUCTURE_FIELDS, nameVfunctions, hasDebugSymbols,
				monitor);
		}
		else {
			println("This script will not work on this program type");
			return;
		}

		if (!recoverClassesFromRTTI.containsRTTI()) {
			println(
				"This program does not appear to contain any processed RTTI information. Either it does not contain any or the RTTI Analyzer was not run.");
			return;
		}

		if (!recoverClassesFromRTTI.isValidProgramType()) {
			println("This script will not work on this program type");
			return;
		}

		if (!recoverClassesFromRTTI.isValidProgramSize()) {
			println("This program is not a valid program address size.");
			return;
		}

		decompilerUtils = recoverClassesFromRTTI.getDecompilerUtils();
		DecompInterface decompInterface = decompilerUtils.getDecompilerInterface();

		if (decompInterface.getProgram() == null) {
			println("The decompiler interface cannot open the current program: " +
				decompInterface.getLastMessage());
			return;
		}

		defaultPointerSize = recoverClassesFromRTTI.getDefaultPointerSize();
		dataTypeManager = recoverClassesFromRTTI.getDataTypeManager();

		PrintWriter out = null;

		boolean doOutput = shouldDoOutput();

		if (doOutput) {
			File outputFile = askFile("Choose Output File", "Please choose an output file");
			out = new PrintWriter(outputFile);
		}

		if (FIXUP_PROGRAM) {
			println(
				"Checking for missing RTTI information and undefined constructor/destructor functions and creating if possible " +
					"to find entry point...");
			AddressSetView beforeScriptChanges = currentProgram.getChanges().getAddressSet();
			recoverClassesFromRTTI.fixUpProgram();
			analyzeProgramChanges(beforeScriptChanges);
		}

		println("Recovering classes using RTTI...");
		List<RecoveredClass> recoveredClasses = recoverClassesFromRTTI.createRecoveredClasses();

		if (recoveredClasses == null) {
			println("Error recovering classes");
			return;
		}

		if (recoveredClasses.isEmpty()) {
			println("No new classes recovered.");
			if (doOutput) {
				out.close();
			}
			return;
		}

		println("Identified " + recoveredClasses.size() + " classes to process and " +
			getNumberOfConstructorsOrDestructors(recoveredClasses) +
			" class member functions to assign.");


		if (!hasDebugSymbols) {

			if (BOOKMARK_FOUND_FUNCTIONS) {
				bookmarkFunctions(recoveredClasses);
				println("See Bookmark Manager for a list of functions by type.");
			}
		}

		callOptionalOutputMethods(recoveredClasses, out);

		if (doOutput) {
			out.close();
		}

		if (GRAPH_CLASS_HIERARCHIES) {
			AttributedGraph graph = createGraph(recoveredClasses);
			showGraph(graph);
		}


		decompilerUtils.disposeDecompilerInterface();
	}

	private boolean hasDwarf() {
		return DWARFProgram.isDWARF(currentProgram);
	}

	/**
	 * Method to determine if pdb info has been applied to the program
	 * @return true if pdb info has been applied to program
	 */
	private boolean isPDBLoadedInProgram() {
		Options options = currentProgram.getOptions(Program.PROGRAM_INFO);
		return options.getBoolean(PdbParserConstants.PDB_LOADED, false);
	}

	private boolean isDwarfLoadedInProgram() {

		return DWARFFunctionImporter.hasDWARFProgModule(currentProgram,
			DWARFProgram.DWARF_ROOT_NAME);
	}

	public String validate() {

		if (currentProgram == null) {
			return ("There is no open program");
		}

		if (!checkGhidraVersion()) {
			return ("This script only works with Ghidra version 9.2, 9.2.2 and later. It does not work on Ghidra 9.2.1 or on versions prior to 9.2");
		}

		if (!isGcc() && !isWindows()) {
			return ("This script only handles Windows and gcc programs");

		}

		defaultPointerSize = currentProgram.getDefaultPointerSize();
		if (defaultPointerSize != 4 && defaultPointerSize != 8) {
			return ("This script only works on 32 or 64 bit programs");
		}
		return new String();
	}

	private void analyzeProgramChanges(AddressSetView beforeChanges) throws Exception {

		AddressSetView addressSet = currentProgram.getChanges().getAddressSet();
		addressSet = addressSet.subtract(beforeChanges);
		if (!addressSet.isEmpty()) {
			println("analyzing program changes ...");
			setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true");
			analyzeChanges(currentProgram);
			addressSet = currentProgram.getChanges().getAddressSet();
			analyzeChangesWithDecompilerFunctionAnalyzer(
				currentProgram.getChanges().getAddressSet());
		}
	}

	@Override
	public AnalysisMode getScriptAnalysisMode() {

		return AnalysisMode.SUSPENDED;

	}


	/**
	 * Method to create a class hierarchy graph where the parents are at the top of the graph and 
	 * the children at the bottom. Classes with no parents have blue nodes. Classes with a single 
	 * parent have green nodes. Classes with multiple parents have red nodes. Classes with virtual 
	 * inheritance have orange edges between parent and child. Classes with non-virtual inheritance 
	 * have lime green edges between parent and child.   
	 * @param recoveredClasses the list of classes
	 * @return a hierarchy graph for the given list of classes
	 * @throws CancelledException if cancelled
	 */
	private AttributedGraph createGraph(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		AttributedGraph g = new AttributedGraph("Test Graph", new EmptyGraphType());

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();
		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();

			AttributedVertex classVertex =
				g.addVertex(recoveredClass.getClassPath().getPath(), recoveredClass.getName());

			Map<RecoveredClass, List<RecoveredClass>> classHierarchyMap =
				recoveredClass.getClassHierarchyMap();

			// no parent = blue vertex
			if (classHierarchyMap.isEmpty()) {
				classVertex.setAttribute("Color", "Blue");
				classVertex.setDescription(recoveredClass.getClassPath().getPath());
				continue;
			}

			Set<RecoveredClass> parents = classHierarchyMap.keySet();

			// single parent = green vertex
			if (parents.size() == 1) {
				classVertex.setAttribute("Color", "Green");
			}
			// multiple parents = red vertex
			else {
				classVertex.setAttribute("Color", "Red");
			}

			classVertex.setDescription(recoveredClass.getClassPath().getPath());

			Map<RecoveredClass, Boolean> parentToBaseTypeMap =
				recoveredClass.getParentToBaseTypeMap();

			Iterator<RecoveredClass> parentIterator = parents.iterator();
			while (parentIterator.hasNext()) {
				monitor.checkCanceled();
				RecoveredClass parent = parentIterator.next();

				AttributedVertex parentVertex =
					g.addVertex(parent.getClassPath().getPath(), parent.getName());

				parentVertex.setDescription(parent.getClassPath().getPath());

				AttributedEdge edge = g.addEdge(parentVertex, classVertex);

				Boolean isVirtualParent = parentToBaseTypeMap.get(parent);
				if (isVirtualParent == null) {
					continue;
				}

				// edge between child and parent is orange if child inherits the parent virtually
				if (isVirtualParent) {
					edge.setAttribute("Color", "Orange");
				}
				// else edge between child and parent is lime green if child inherits the parent non-virtually

			}
		}

		return g;
	}

	/**
	 * Method to display the given graph
	 * @param graph the given graph
	 * @throws GraphException if the graph service cannot get the graph display
	 * @throws CancelledException if drawing the graph is cancelled
	 */
	private void showGraph(AttributedGraph graph) throws GraphException, CancelledException {

		GraphDisplay display;
		PluginTool tool = state.getTool();
		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider service = broker.getGraphDisplayProvider("Default Graph Display");
		display = service.getGraphDisplay(false, TaskMonitor.DUMMY);
		display.setGraph(graph, "test graph", false, TaskMonitor.DUMMY);
	}

	/**
	 * Method to determine, based on the script's output settings, if the script will do any output
	 * @return true if the script will do output, false otherwise
	 */
	private boolean shouldDoOutput() {

		boolean doOutput = OUTPUT_CLASS_DEFINITIONS || OUTPUT_CLASS_INFO ||
			OUTPUT_CLASS_PARENTS_AND_CHILDREN || OUTPUT_SIMPLE_CLASS_HIERARCHIES;

		return doOutput;
	}


	private void printClassHierarchyLists(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();

			RecoveredClass recoveredClass = recoveredClassIterator.next();
			List<RecoveredClass> classHierarchyList = recoveredClass.getClassHierarchy();
			Iterator<RecoveredClass> classHierarchyIterator = classHierarchyList.iterator();
			while (classHierarchyIterator.hasNext()) {
				monitor.checkCanceled();
				RecoveredClass currentClass = classHierarchyIterator.next();
				println(currentClass.getName());
			}

			println("***");
		}
	}




	/**
	 * Script works on versions of ghidra including and after 9.2 except for 9.2.1 because a method 
	 * was accidentally removed from FillOutStructureCmd that is needed
	 * @return true if script will work and false otherwise
	 */
	private boolean checkGhidraVersion() {

		ghidraVersion = getVersionOfGhidra();

		if (ghidraVersion.compareTo("9.3") <= 0 && !ghidraVersion.equals("9.2.1")) {
			return true;
		}
		return false;
	}

	/**
	 * Method to set the global variable isGcc
	 */
	private boolean isGcc() {

		boolean isELF = currentProgram.getExecutableFormat().contains("ELF");
		if (!isELF) {
			return false;
		}

		boolean isCompilerSpecGcc =
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().equalsIgnoreCase(
				"gcc");
		if (isCompilerSpecGcc) {
			return true;
		}

		MemoryBlock commentBlock = currentProgram.getMemory().getBlock(".comment");
		if (commentBlock == null) {
			return false;
		}

		if (!commentBlock.isLoaded()) {
			return false;
		}


		// check memory bytes in block for GCC: bytes
		byte[] gccBytes = { (byte) 0x47, (byte) 0x43, (byte) 0x43, (byte) 0x3a };
		byte[] maskBytes = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

		Address found = currentProgram.getMemory().findBytes(commentBlock.getStart(),
				commentBlock.getEnd(), gccBytes, maskBytes, true, monitor);
		if (found == null) {
			isGcc = false;
		}
		else {
			isGcc = true;
		}

		return isGcc;
	}

	/**
	 * Method to set the global variable isWindows
	 */
	private boolean isWindows() {

		String compilerID =
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		isWindows = compilerID.contains("windows");
		return isWindows;
	}



	/**
	 * Method to determine if somehow the constructor list and destructor list for a class contain 
	 * overlapping functions
	 * @param recoveredClass the given class
	 * @return true if there is a discrepancy in the constructor/destructor lists
	 */
	private boolean hasConstructorDestructorDiscrepancy(RecoveredClass recoveredClass) {

		List<Function> allClassConstructors =
			recoverClassesFromRTTI.getAllClassConstructors(recoveredClass);
		List<Function> allClassDestructors =
			recoverClassesFromRTTI.getAllClassDestructors(recoveredClass);

		List<Function> commonFunctions1 =
			allClassConstructors.stream().distinct().filter(allClassDestructors::contains).collect(
				Collectors.toList());

		List<Function> commonFunctions2 =
			allClassDestructors.stream().distinct().filter(allClassConstructors::contains).collect(
				Collectors.toList());

		if (commonFunctions1.isEmpty() && commonFunctions2.isEmpty()) {
			return false;
		}
		return true;
	}

	/**
	 * Method to analyze the program changes with the decompiler parameter ID analyzer
	 * @param set the set of addresses to analyze
	 * @throws Exception if the analyzer throws an exception
	 */
	private void analyzeChangesWithDecompilerFunctionAnalyzer(AddressSetView set) throws Exception {

		Analyzer analyzer = new DecompilerFunctionAnalyzer();
		analyzer.added(currentProgram, set, monitor, new MessageLog());
	}



	/**
	 * Get the version of Ghidra that was used to analyze this program
	 * @return a string containing the version number of Ghidra used to analyze the current program
	 */
	private String getVersionOfGhidra() {

		Options options = currentProgram.getOptions("Program Information");
		return options.getString("Created With Ghidra Version", null);
	}


	/**
	 * Method to bookmark all of the constructor/destructor/indeterminate functions
	 * @param recoveredClasses List of classes
	 * @throws CancelledException if cancelled
	 */
	private void bookmarkFunctions(List<RecoveredClass> recoveredClasses)
			throws CancelledException {
		bookmarkConstructors(recoveredClasses);
		bookmarkDestructors(recoveredClasses);
		bookmarkRemainingIndeterminateConstructorsAndDestructors(recoveredClasses);
	}


	/**
	 * Method to print class hierarchy of the form child : parent: grandparent : etc...
	 * @param stringBuffer the buffer to add the newly created string to
	 * @param recoveredClass the current class to process
	 * @throws CancelledException when cancelled
	 */
	private StringBuffer getSimpleClassHierarchyString(StringBuffer stringBuffer,
			RecoveredClass recoveredClass) throws CancelledException {

		// print class
		stringBuffer.append(recoveredClass.getName());

		if (!recoveredClass.hasParentClass()) {
			return stringBuffer;
		}

		// if class has parents, print parents in order
		Map<RecoveredClass, List<RecoveredClass>> classHierarchyMap =
			recoveredClass.getClassHierarchyMap();

		List<RecoveredClass> parents = new ArrayList<RecoveredClass>(classHierarchyMap.keySet());

		// if single inheritance - simple linear case
		if (recoveredClass.hasSingleInheritance()) {
			stringBuffer.append(" : ");
			getSimpleClassHierarchyString(stringBuffer, parents.get(0));
		}
		// otherwise have to split into various lines for the multiple parents
		else {
			Iterator<RecoveredClass> parentIterator = classHierarchyMap.keySet().iterator();
			stringBuffer.append(" : ");
			int lastColon = stringBuffer.lastIndexOf(":");
			while (parentIterator.hasNext()) {
				monitor.checkCanceled();
				RecoveredClass parentClass = parentIterator.next();
				if (classHierarchyMap.size() == 1) {
					//stringBuffer.append(" : ");
					getSimpleClassHierarchyString(stringBuffer, parentClass);
					continue;
				}

				stringBuffer.append("\r\n");

				//int lastColon = stringBuffer.lastIndexOf(":");
				for (int i = 0; i <= lastColon; i++) {
					monitor.checkCanceled();
					stringBuffer.append(" ");
				}
				getSimpleClassHierarchyString(stringBuffer, parentClass);
			}

		}

		return stringBuffer;

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



	/**
	 * Method to bookmark found constructor functions
	 * @param recoveredClasses List of classes
	 * @throws CancelledException if cancelled
	 */
	private void bookmarkConstructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		Iterator<RecoveredClass> recoveredClassesIterator = recoveredClasses.iterator();

		while (recoveredClassesIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassesIterator.next();
			bookmarkFunctionsOnList(recoveredClass.getConstructorList(), CONSTRUCTOR_BOOKMARK);
		}
	}

	/**
	 * Method to bookmark found constructor functions
	 * @param recoveredClasses List of classes
	 * @throws CancelledException if cancelled
	 */
	private void bookmarkDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		Iterator<RecoveredClass> recoveredClassesIterator = recoveredClasses.iterator();

		while (recoveredClassesIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassesIterator.next();
			bookmarkFunctionsOnList(recoveredClass.getDestructorList(), DESTRUCTOR_BOOKMARK);
			bookmarkFunctionsOnList(recoveredClass.getNonThisDestructors(), DESTRUCTOR_BOOKMARK);
		}
	}

	/**
	 * Method to bookmark indeterminate constructor/destructor functions
	 * @param recoveredClasses List of classes
	 * @throws CancelledException if cancelled
	 */
	private void bookmarkRemainingIndeterminateConstructorsAndDestructors(
			List<RecoveredClass> recoveredClasses) throws CancelledException {

		Iterator<RecoveredClass> recoveredClassesIterator = recoveredClasses.iterator();

		while (recoveredClassesIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassesIterator.next();

			bookmarkFunctionsOnList(recoveredClass.getIndeterminateList(), INDETERMINATE_BOOKMARK);
		}
	}


	/**
	 * Method to add/append analysis bookmarks with the given comment to the given list of functions
	 * @param functions List of functions
	 * @param comment the bookmark comment to add
	 * @throws CancelledException when script is cancelled
	 */
	private void bookmarkFunctionsOnList(List<Function> functions, String comment)
			throws CancelledException {

		if (functions.size() == 0) {
			return;
		}

		Iterator<Function> functionIterator = functions.iterator();
		while (functionIterator.hasNext()) {
			monitor.checkCanceled();
			Function function = functionIterator.next();
			Address address = function.getEntryPoint();
			recoverClassesFromRTTI.bookmarkAddress(address, comment);
		}
	}


	/**
	 * Method to optionally print to console or output to file various types of class information
	 * depending on the options set at top of script
	 * @param recoveredClasses List of classes
	 * @param out output mechanism
	 * @throws CancelledException if cancelled
	 */
	private void callOptionalOutputMethods(List<RecoveredClass> recoveredClasses, PrintWriter out)
			throws CancelledException {

		if (PRINT_COUNTS) {
			printCounts(recoveredClasses);
		}

		if (PRINT_CLASS_HIERARCHIES) {
			printClassHierarchiesFromLowestChildren(recoveredClasses);
		}

		if (PRINT_CLASS_DEFINITIONS) {
			printClassDefinitions(recoveredClasses);
		}

		if (PRINT_CLASS_PARENTS_AND_CHILDREN) {
			printClassesParentsAndChilren(recoveredClasses);
		}

		if (PRINT_CLASS_INFO) {
			printClassInfo(recoveredClasses);
		}

		if (OUTPUT_CLASS_DEFINITIONS) {
			outputClassDefinitions(recoveredClasses, out);
		}
		if (OUTPUT_CLASS_INFO) {
			outputClassInfo(recoveredClasses, out);
		}

		if (OUTPUT_CLASS_PARENTS_AND_CHILDREN) {
			outputClassParentsAndChildren(recoveredClasses, out);
		}
		if (OUTPUT_SIMPLE_CLASS_HIERARCHIES) {
			outputSimpleClassHierarchies(recoveredClasses, out);
		}

	}

	/**
	 * Method to print class definitions given information discovered about each class.
	 * Start with top parents and recurse over their children
	 * @param recoveredClasses List of classes
	 * @throws CancelledException when cancelled
	 */
	private void printClassDefinitions(List<RecoveredClass> recoveredClasses)
			throws CancelledException {
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			if (!recoveredClass.hasParentClass()) {
				println(createClassDefinitionString(recoveredClass).toString());
			}
		}
	}


	private void outputClassDefinitions(List<RecoveredClass> recoveredClasses, PrintWriter out)
			throws CancelledException {
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			if (!recoveredClass.hasParentClass()) {
				out.append(createClassDefinitionString(recoveredClass));
			}
		}


	}

	/**
	 * Method to print class info for each of the classes on the given list, starting with classes with no parents then 
	 * recursively printing infor for their child classes
	 * @param recoveredClasses the list of classes
	 * @throws CancelledException if cancelled
	 */
	private void printClassInfo(List<RecoveredClass> recoveredClasses) throws CancelledException {
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			if (!recoveredClass.hasParentClass()) {
				println(createClassInfoString(recoveredClass).toString());
			}
		}
	}

	private void printClassParents(List<RecoveredClass> recoveredClasses)
			throws CancelledException {
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			String printString = new String("\n" + recoveredClass.getName() + "\n");
			if (recoveredClass.hasParentClass()) {
				List<RecoveredClass> parentList = recoveredClass.getParentList();
				Iterator<RecoveredClass> parentIterator = parentList.iterator();
				while (parentIterator.hasNext()) {
					monitor.checkCanceled();
					RecoveredClass parent = parentIterator.next();
					printString = printString.concat("\t" + parent.getName() + "\n");
				}
			}
			println(printString);
		}
	}


	/**
	 * Method to print class hierarchies for the given list of classes starting with the lowest child classes in each family of classes
	 * @param recoveredClasses the list of classes
	 * @throws CancelledException if cancelled
	 */
	private void printClassHierarchiesFromLowestChildren(
			List<RecoveredClass> recoveredClasses) throws CancelledException {


		StringBuffer wholeBuffer = new StringBuffer();
		wholeBuffer.append("\r\n");
		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();

			if (!recoveredClass.hasChildClass()) {

				StringBuffer stringBuffer = new StringBuffer();

				wholeBuffer.append(
					getSimpleClassHierarchyString(stringBuffer, recoveredClass).toString() +
						"\r\n\r\n");
			}
		}
		println(wholeBuffer.toString());

	}

	/**
	 * Method to output simple class hierarchies for the given classes to the given output writer
	 * @param recoveredClasses the list of classes
	 * @param out the output writer
	 * @throws CancelledException if cancelled
	 */
	private void outputSimpleClassHierarchies(List<RecoveredClass> recoveredClasses,
			PrintWriter out) throws CancelledException {

		StringBuffer wholeBuffer = new StringBuffer();
		wholeBuffer.append("\r\n");

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			if (!recoveredClass.hasChildClass()) {
				StringBuffer stringBuffer = new StringBuffer();
				wholeBuffer.append(
					getSimpleClassHierarchyString(stringBuffer, recoveredClass).toString() +
						"\r\n");
			}
		}
		out.append(wholeBuffer);
	}

	/**
	 * Method to output class info for the given list of classes
	 * @param recoveredClasses the list of classes
	 * @param out the output writer
	 * @throws CancelledException if cancelled
	 */
	private void outputClassInfo(List<RecoveredClass> recoveredClasses, PrintWriter out)
			throws CancelledException {

		Iterator<RecoveredClass> recoveredClassIterator = recoveredClasses.iterator();

		while (recoveredClassIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = recoveredClassIterator.next();
			if (!recoveredClass.hasParentClass()) {
				out.append(createClassInfoString(recoveredClass).toString());
			}
		}
	}


	/**
	 * Method to print counts of various class items for the given classes, such as number of constructors, destructors, etc...
	 * @param recoveredClasses list of classes
	 * @throws CancelledException if cancelled
	 */
	private void printCounts(List<RecoveredClass> recoveredClasses) throws CancelledException {


		println("Total number of constructors: " +
			recoverClassesFromRTTI.getNumberOfConstructors(recoveredClasses));
		println("Total number of inlined constructors: " +
			getNumberOfInlinedConstructors(recoveredClasses));
		println(
			"Total number of destructors: " +
				recoverClassesFromRTTI.getNumberOfDestructors(recoveredClasses));
		println("Total number of inlined destructors: " +
			recoverClassesFromRTTI.getNumberOfInlineDestructors(recoveredClasses));
		println(
			"Total number of virtual functions: " +
				recoverClassesFromRTTI.getNumberOfVirtualFunctions(recoveredClasses));
		println("Total number of virtual functions that are deleting destructors: " +
			recoverClassesFromRTTI.getNumberOfDeletingDestructors(recoveredClasses));

		println("Total number of virtual functions that are clone functions: " +
			recoverClassesFromRTTI.getNumberOfCloneFunctions(recoveredClasses));

		println("Total number of virtual functions that are vbase_destructors: " +
			recoverClassesFromRTTI.getNumberOfVBaseFunctions(recoveredClasses));

		List<Function> remainingIndeterminates =
			recoverClassesFromRTTI.getRemainingIndeterminates(recoveredClasses);
		println("Total number of indetermined constructor/destructors: " +
			remainingIndeterminates.size());

		println("Total fixed incorrect FID functions: " +
			recoverClassesFromRTTI.getBadFIDFunctions().size());
		println("Total resolved functions that had multiple FID possiblities: " +
			recoverClassesFromRTTI.getResolvedFIDFunctions().size());
		println("Total fixed functions that had incorrect data types due to incorrect FID: " +
			recoverClassesFromRTTI.getFixedFIDFunctions().size());

	}


	/**
	 * Method to get the total number of 
	 * @param recoveredClasses list of classes
	 * @return the total number of constructors and destructors in the given list of classes
	 * @throws CancelledException if cancelled
	 */
	private int getNumberOfConstructorsOrDestructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();
			List<Function> constructorList = recoveredClass.getConstructorOrDestructorFunctions();
			total += constructorList.size();
		}
		return total;
	}

	/**
	 * Method to get the total number of inlined constructors in the given list of classes
	 * @param recoveredClasses list of classes
	 * @return total number of inlined constructors in the given list of classes
	 * @throws CancelledException if cancelled
	 */
	private int getNumberOfInlinedConstructors(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		int total = 0;
		Iterator<RecoveredClass> classIterator = recoveredClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = classIterator.next();
			List<Function> inlineList = recoveredClass.getInlinedConstructorList();
			total += inlineList.size();
		}
		return total;
	}

	/**
	 * Method to print the given list of addresses 
	 * @param addresses the list of addresses to print
	 * @throws CancelledException if cancelled
	 */
	private void printAddresses(List<Address> addresses) throws CancelledException {
		Iterator<Address> iterator = addresses.iterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			println(iterator.next().toString());
		}
	}


	/**
	 * Method to output the class, it's parents and it's children for each of the listed classes
	 * @param recoveredClasses the given classes
	 * @param out the output writer
	 * @throws CancelledException if cancelled
	 */
	private void outputClassParentsAndChildren(List<RecoveredClass> recoveredClasses,
			PrintWriter out) throws CancelledException {

		Iterator<RecoveredClass> iterator = recoveredClasses.iterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = iterator.next();
			out.append(printClassParentsandChildren(recoveredClass));
		}
	}

	/**
	 * Method to print the class, it's parents and it's children for each of the listed classes
	 * @param recoveredClasses the given classes
	 * @throws CancelledException if cancelled
	 */
	private void printClassesParentsAndChilren(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		Iterator<RecoveredClass> iterator = recoveredClasses.iterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			RecoveredClass recoveredClass = iterator.next();
			println(printClassParentsandChildren(recoveredClass).toString());
		}
	}

	/**
	 * Method to get formatted string containing the given class, it's parents and it's children 
	 * @param recoveredClass the given classes
	 * @return StringBuffer containing the formatted string containing the given class, it's parents and it's children 
	 * @throws CancelledException if cancelled
	 */
	private StringBuffer printClassParentsandChildren(RecoveredClass recoveredClass)
			throws CancelledException {
		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append("\r\n");
		stringBuffer.append("\r\n");

		stringBuffer.append("*** Recovered Class:  " + recoveredClass.getName() + "  ***\r\n");
		stringBuffer.append("\r\n");

		// print parent classes
		stringBuffer.append("parent class(es):\r\n");
		if (recoveredClass.hasParentClass()) {
			Set<RecoveredClass> keySet = recoveredClass.getClassHierarchyMap().keySet();
			Iterator<RecoveredClass> parentIterator = keySet.iterator();
			while (parentIterator.hasNext()) {
				monitor.checkCanceled();
				RecoveredClass parent = parentIterator.next();
				stringBuffer.append("\t" + parent.getName() + "\r\n");
			}
		}

		// print child classes
		stringBuffer.append("\r\n");
		stringBuffer.append("child class(es):\r\n");
		if (recoveredClass.hasChildClass()) {
			List<RecoveredClass> childClasses = recoveredClass.getChildClasses();
			Iterator<RecoveredClass> childClassIterator = childClasses.iterator();
			while (childClassIterator.hasNext()) {
				monitor.checkCanceled();
				stringBuffer.append("\t" + childClassIterator.next().getName() + "\r\n");
			}

		}
		return stringBuffer;

	}

	/**
	 * Method to create a string containing class info for the given class including parents, children, constructors, destructors
	 * inlined constructors, inlined destructors, member functions, member data and the same info for each child class
	 * @param recoveredClass the given class
	 * @return string buffer containing class info for the given class
	 * @throws CancelledException if cancelled
	 */
	private StringBuffer createClassInfoString(RecoveredClass recoveredClass)
			throws CancelledException {

		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append("\r\n");
		stringBuffer.append("\r\n");

		stringBuffer.append("*** Recovered Class:  " + recoveredClass.getName() + "  ***\r\n");
		stringBuffer.append("\r\n");

		// print parent classes
		stringBuffer.append("parent class(es):\r\n");
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
						stringBuffer.append(
							"\t virtual " + ancestor.getName() + "\r\n");
					}
					else {
						stringBuffer.append(
							"\t" + ancestor.getName() + "\r\n");
					}
				}
			}
		}
		else {
			stringBuffer.append("\tNone\r\n");
		}


		// print child classes
		stringBuffer.append("\r\n");
		stringBuffer.append("child class(es):\r\n");
		if (recoveredClass.hasChildClass()) {
			List<RecoveredClass> childClasses = recoveredClass.getChildClasses();
			Iterator<RecoveredClass> childClassIterator = childClasses.iterator();
			while (childClassIterator.hasNext()) {
				monitor.checkCanceled();
				stringBuffer.append("\t" + childClassIterator.next().getName() + "\r\n");
			}

		}
		stringBuffer.append("\r\n");

		// print constructors
		stringBuffer.append("constructor(s):\r\n");
		List<Function> constructorList = recoveredClass.getConstructorList();
		Iterator<Function> constructorIterator = constructorList.iterator();
		while (constructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function constructorFunction = constructorIterator.next();
			stringBuffer.append("\t" + constructorFunction.getName() + " " +
				constructorFunction.getEntryPoint().toString() + "\r\n");
		}
		stringBuffer.append("\r\n");

		// print inlined constructors
		List<Function> inlinedConstructorList = recoveredClass.getInlinedConstructorList();
		if (inlinedConstructorList.size() > 0) {
			stringBuffer.append("inlined constructor(s):\r\n");
			Iterator<Function> inlinedConstructorIterator = inlinedConstructorList.iterator();
			while (inlinedConstructorIterator.hasNext()) {
				monitor.checkCanceled();
				Function inlinedConstructorFunction = inlinedConstructorIterator.next();
				stringBuffer.append("\t" + inlinedConstructorFunction.getName() + " " +
					inlinedConstructorFunction.getEntryPoint().toString() + "\r\n");
			}
		}
		stringBuffer.append("\r\n");

		// print destructors
		stringBuffer.append("destructor(s):\r\n");
		List<Function> destructorList = recoveredClass.getDestructorList();
		Iterator<Function> destructorIterator = destructorList.iterator();
		while (destructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function destructorFunction = destructorIterator.next();
			stringBuffer.append("\t" + destructorFunction.getName() + " " +
				destructorFunction.getEntryPoint().toString() + "\r\n");
		}
		stringBuffer.append("\r\n");

		// print inlined destructors
		List<Function> inlinedDestructorList = recoveredClass.getInlinedDestructorList();
		if (inlinedDestructorList.size() > 0) {
			stringBuffer.append("inlined destructor(s):\r\n");
			Iterator<Function> inlinedDestructorIterator = inlinedDestructorList.iterator();
			while (inlinedDestructorIterator.hasNext()) {
				monitor.checkCanceled();
				Function inlinedDestructorFunction = inlinedDestructorIterator.next();
				stringBuffer.append("\t" + inlinedDestructorFunction.getName() + " " +
					inlinedDestructorFunction.getEntryPoint().toString() + "\r\n");
			}
		}

		// print const/dest that couldn't be classified correctly
		List<Function> indeterminateList = recoveredClass.getIndeterminateList();
		if (indeterminateList.size() > 0) {
		stringBuffer.append("\r\nindeterminate constructor(s) or destructor(s):\r\n");
			Iterator<Function> indeterminateIterator = indeterminateList.iterator();
			while (indeterminateIterator.hasNext()) {
				monitor.checkCanceled();
				Function indeterminateFunction = indeterminateIterator.next();
				stringBuffer.append("\t" + indeterminateFunction.getName() + " " +
					indeterminateFunction.getEntryPoint().toString() + "\r\n");
			}
			stringBuffer.append("\r\n");
		}
		stringBuffer.append("\r\n");

		// print virtual function signatures
		stringBuffer.append("member function(s):\r\n");
		List<Function> virtualFunctions = recoveredClass.getAllVirtualFunctions();
		//List<Function> dedupedVirtualFunctions = removeDuplicateFunctions(virtualFunctions);
		Iterator<Function> vfunctionIter = virtualFunctions.iterator();
		while (vfunctionIter.hasNext()) {
			monitor.checkCanceled();
			Function vfunction = vfunctionIter.next();
			stringBuffer.append("\t" + vfunction.getName() + " " +
				vfunction.getEntryPoint().toString() + "\r\n");
		}
		stringBuffer.append("\r\n");

		// print class member data
		stringBuffer.append("member data:\r\n");

		DataType classMemberDataType = dataTypeManager.getDataType(recoveredClass.getClassPath(),
			recoveredClass.getName() + CLASS_DATA_STRUCT_NAME);

		if (classMemberDataType != null && classMemberDataType instanceof Structure) {

			Structure memberDataStructure = (Structure) classMemberDataType;
			int numDefinedComponents = memberDataStructure.getNumDefinedComponents();

			DataTypeComponent[] definedComponents = memberDataStructure.getDefinedComponents();
			for (int i = 0; i < numDefinedComponents; i++) {
				monitor.checkCanceled();

				stringBuffer.append("\t" + definedComponents[i].getDataType() + " " +
					definedComponents[i].getFieldName() + "\r\n");
			}
		}
		stringBuffer.append("\r\n");

		// Then recursively process the child classes
		if (recoveredClass.hasChildClass()) {
			List<RecoveredClass> childClasses = recoveredClass.getChildClasses();
			Iterator<RecoveredClass> childClassIterator = childClasses.iterator();
			while (childClassIterator.hasNext()) {
				monitor.checkCanceled();
				stringBuffer.append(createClassInfoString(childClassIterator.next()));
			}
		}

		return stringBuffer;
	}


	/**
	 * Method to get the function signature string, from the decompiler if possible, otherwise from 
	 * the listing
	 * @param function the given function
	 * @param includeReturn if true, include the return type in the string
	 * @return the function signature string
	 * @throws CancelledException if cancelled
	 */
	private String getFunctionSignatureString(Function function, boolean includeReturn)
			throws CancelledException {

		if (function == null) {
			return "";
		}

		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append("\t");

		String functionSignatureString =
			decompilerUtils.getFunctionSignatureString(function, includeReturn);

		if (functionSignatureString != null) {
			stringBuffer = stringBuffer.append(functionSignatureString.toString());
			return stringBuffer.toString();
		}

		// if can't get it from decompiler then use the listing one
		if (includeReturn) {
			stringBuffer.append(function.getReturnType().getDisplayName() + " ");
		}

		stringBuffer.append(function.getName() + "(");
		int paramCount = function.getParameterCount();
		int autoParamCount = function.getAutoParameterCount();
		if (paramCount - autoParamCount <= 0) {
			stringBuffer.append(");");
		}
		else {
			for (int i = autoParamCount - 1; i < paramCount; i++) {
				monitor.checkCanceled();
				Parameter param = function.getParameter(i);
				stringBuffer.append(param.getDataType().getDisplayName() + " " + param.getName());
				if (i == paramCount) {
					stringBuffer.append(");");
				}
				else {
					stringBuffer.append(", ");
				}
			}
		}

		return stringBuffer.toString();
	}


	/**
	 * Method to create a string containing a C++-like representation of the given class
	 * @param recoveredClass the given class
	 * @return string containing a C++-like representation of the given class
	 * @throws CancelledException if cancelled
	 */
	private StringBuffer createClassDefinitionString(RecoveredClass recoveredClass)
			throws CancelledException {


		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append("\r\n\r\n");

		stringBuffer.append(recoverClassesFromRTTI.createParentStringBuffer(recoveredClass));

		stringBuffer.append("\r\n{\r\n");


		// print constructor signature(s)
		stringBuffer.append("constructor(s):\r\n");
		List<Function> constructorList = recoveredClass.getConstructorList();
		Iterator<Function> constructorIterator = constructorList.iterator();
		while (constructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function constructorFunction = constructorIterator.next();
			String functionSignatureString =
				getFunctionSignatureString(constructorFunction, true);

			stringBuffer.append(functionSignatureString);
			stringBuffer.append("\r\n");
		}

		// print destructor signature
		stringBuffer.append("\r\ndestructor(s):\r\n");
		List<Function> destructorList = recoveredClass.getDestructorList();
		Iterator<Function> destructorIterator = destructorList.iterator();
		while (destructorIterator.hasNext()) {
			monitor.checkCanceled();
			Function destructorFunction = destructorIterator.next();
			String functionSignatureString =
				getFunctionSignatureString(destructorFunction, true);
			stringBuffer.append(functionSignatureString);
			stringBuffer.append("\r\n");
		}

		// print const/dest that couldn't be classified correctly
		List<Function> indeterminateList = recoveredClass.getIndeterminateList();
		if (indeterminateList.size() > 0) {
			stringBuffer.append("\r\nindeterminate constructor or destructor function(s):\r\n");
			Iterator<Function> indeterminateIterator = indeterminateList.iterator();
			while (indeterminateIterator.hasNext()) {
				monitor.checkCanceled();
				Function indeterminateFunction = indeterminateIterator.next();
				String functionSignatureString =
					getFunctionSignatureString(indeterminateFunction, true);
				stringBuffer.append(functionSignatureString);
				stringBuffer.append("\r\n");
			}
		}

		// print virtual function signature(s)
		stringBuffer.append("\r\nmember function(s):\r\n");
		List<Function> virtualFunctions = recoveredClass.getAllVirtualFunctions();
		Iterator<Function> vfunctionIter = virtualFunctions.iterator();
		while (vfunctionIter.hasNext()) {
			monitor.checkCanceled();
			Function vfunction = vfunctionIter.next();
			String functionSignatureString =
				getFunctionSignatureString(vfunction, true);
			stringBuffer.append(functionSignatureString);
			stringBuffer.append("\r\n");
		}

		stringBuffer.append("\r\n");
		stringBuffer.append("member data: \r\n");

		// print class member data items
		DataType classMemberDataType = dataTypeManager.getDataType(recoveredClass.getClassPath(),
			recoveredClass.getName() + CLASS_DATA_STRUCT_NAME);

		if (classMemberDataType != null && classMemberDataType instanceof Structure) {

			Structure memberDataStructure = (Structure) classMemberDataType;
			int numDefinedComponents = memberDataStructure.getNumDefinedComponents();

			DataTypeComponent[] definedComponents = memberDataStructure.getDefinedComponents();
			for (int i = 0; i < numDefinedComponents; i++) {
				monitor.checkCanceled();
				stringBuffer.append("\t" + definedComponents[i].getDataType() + " " +
					definedComponents[i].getFieldName() + "\r\n");
			}
		}
		stringBuffer.append("};\r\n");


		// Then recursively process the child classes
		if (recoveredClass.hasChildClass()) {
			List<RecoveredClass> childClasses = recoveredClass.getChildClasses();
			Iterator<RecoveredClass> childClassIterator = childClasses.iterator();
			while (childClassIterator.hasNext()) {
				monitor.checkCanceled();
				stringBuffer.append(createClassDefinitionString(childClassIterator.next()));
			}
		}

		return stringBuffer;
	}



}
