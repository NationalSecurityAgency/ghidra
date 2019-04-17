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
package ghidra.feature.fid.service;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;

import generic.stl.Pair;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.hash.FidHasher;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.framework.Application;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

class FidServiceLibraryIngest {
	private static final int MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS = 12;

	private FidDB fidDb; // The database being populated
	private FidService service;
	private String libraryFamilyName; // Name of the library being created
	private String libraryVersion; // Version string
	private String libraryVariant; // Variant string
	private List<DomainFile> programFiles;
	private Predicate<Pair<Function, FidHashQuad>> functionFilter;
	private LanguageID languageId; // Language for everything in this library
	private List<LibraryRecord> linkLibraries;
	private TaskMonitor monitor;

	private LibraryRecord library = null; // Database record of the library we are creating
	private CompilerSpec compilerSpec = null;
	private Map<FunctionRecord, Set<ChildSymbol>> unresolvedSymbols =
		new HashMap<>();
	private TreeSet<Long> globalUniqueFunction = new TreeSet<>();
	private FidPopulateResult result = null;
	private TreeMap<String, FidPopulateResult.Count> childHistogram =
		new TreeMap<>(); // Counts of child references to function symbols

	private static class FunctionRow {
		public FunctionRecord functionRecord;
		public FidHashQuad hashQuad;
		public String name;
		public long offset;
		public String pathName;
		public boolean hasTerminator;
		public ArrayList<ChildRow> children;

		/**
		 * Creates the template for a function record in the database, but doesn't actually create the record
		 * @param domainFile the domain file of the program
		 * @param function the function
		 * @param name the name
		 * @param hashQuad the hash quad of the function
		 * @param hasTerminator whether the function body contains a terminating flow
		 * @return the new function row
		 */
		public FunctionRow(DomainFile domainFile, Function function, String name,
				FidHashQuad hashQuad, boolean hasTerminator) {
			this.functionRecord = null; // Don't create record yet
			this.hashQuad = hashQuad;
			this.name = name;
			this.offset = function.getEntryPoint().getOffset();
			this.pathName = domainFile.getPathname();
			this.hasTerminator = hasTerminator;
			this.children = null;
		}

		public void commit(FidDB fidDb, LibraryRecord library) {
			functionRecord =
				fidDb.createNewFunction(library, hashQuad, name, offset, pathName, hasTerminator);
		}

		/**
		 * We want a FunctionRecord to be unique up to
		 *   1) The full hash and specific hash of the function
		 *   2) The symbol name
		 *   3) The full hash of any children of the function (or the symbol name if hash not available)
		 * Produce a 64-bit hash incorporating this information
		 * @return the hash
		 */
		public long generateHash() {
			long hash = hashQuad.getSpecificHash();
			hash *= 31;
			hash += hashQuad.getFullHash();
			hash *= 31;
			hash += name.hashCode();
			for (ChildRow childRow : children) {
				if (childRow.toRow != null) {
					hash *= 31;
					hash += childRow.toRow.hashQuad.getFullHash();
				}
				else if (childRow.symbolName != null) {
					hash *= 31;
					hash += childRow.symbolName.hashCode();
				}
			}
			return hash;
		}
	}

	private static class ChildRow implements Comparable<ChildRow> {
		public FunctionRow toRow;
		public String symbolName;
		public Address toAddress;
		public boolean isVeryCommon;

		@Override
		public int compareTo(ChildRow o) {
			if (toRow == null) {
				if (o.toRow != null) {
					return 1; // FunctionRow before (Symbol,Address)
				}
				if (symbolName == null) {
					if (o.symbolName != null) {
						return 1; // Symbol before Address
					}
					return toAddress.compareTo(o.toAddress);
				}
				if (o.symbolName == null) {
					return -1;
				}
				return symbolName.compareTo(o.symbolName);
			}
			if (o.toRow == null) {
				return -1;
			}
			long offset1 = toRow.hashQuad.getSpecificHash();
			long offset2 = o.toRow.hashQuad.getSpecificHash();
			if (offset1 == offset2) {
				return 0;
			}
			return (offset1 < offset2) ? -1 : 1;
		}
	}

	private static class ChildSymbol implements Comparable<ChildSymbol> {
		public String name;
		public FidHashQuad hashQuad; // May be null

		@Override
		public int compareTo(ChildSymbol o) {
			return name.compareTo(o.name);
		}
	}

	/**
	 * @param fidDb the database to modify
	 * @param service the FID service
	 * @param libraryFamilyName the library family name
	 * @param libraryVersion the library version
	 * @param libraryVariant the library variant
	 * @param programFiles the list of program files
	 * @param functionFilter the function filter
	 * @param languageId the Ghidra language id to filter programs by
	 * @param linkLibraries the list of libraries to use for unresolved symbols
	 * @param monitor a task monitor
	 */
	public FidServiceLibraryIngest(FidDB fidDb, FidService service, String libraryFamilyName,
			String libraryVersion, String libraryVariant, List<DomainFile> programFiles,
			Predicate<Pair<Function, FidHashQuad>> functionFilter, LanguageID languageId,
			List<LibraryRecord> linkLibraries, TaskMonitor monitor) {
		this.fidDb = fidDb;
		this.service = service;
		this.libraryFamilyName = libraryFamilyName;
		this.libraryVersion = libraryVersion;
		this.libraryVariant = libraryVariant;
		this.programFiles = programFiles;
		this.functionFilter = functionFilter;
		this.languageId = languageId;
		this.linkLibraries = linkLibraries;
		this.monitor = monitor;
		if (languageId == null) {
			throw new IllegalArgumentException("LanugageID can't be null"); // null used to be allowed, so add special check
		}
	}

	/**
	 * Mark a set of function symbols as "very common" so a match relationship won't be generated with
	 * functions that call it.
	 * @param symbols
	 */
	public void markCommonChildReferences(List<String> symbols) {
		if (symbols == null) {
			return;
		}
		for (String symbol : symbols) {
			FidPopulateResult.Count count = new FidPopulateResult.Count();
			count.count = 0;
			count.isVeryCommon = true;
			childHistogram.put(symbol, count);
		}
	}

	public FidPopulateResult create() throws CancelledException, VersionException, IOException {

		monitor.setMessage("Populating library from programs...");
		monitor.initialize(programFiles.size());
		Object consumer = new Object();
		for (DomainFile programFile : programFiles) {
			monitor.checkCanceled();
			Program program = null;
			try {
				program = (Program) programFile.getDomainObject(consumer, false, false,
					TaskMonitor.DUMMY);
				monitor.incrementProgress(1);
				if (!checkLanguageCompilerSpec(program)) {
					continue;
				}
				languageId = program.getLanguageID();
				compilerSpec = program.getCompilerSpec();

				if (library == null) {
					Language language = program.getLanguage();
					library =
						fidDb.createNewLibrary(libraryFamilyName, libraryVersion, libraryVariant,
							Application.getApplicationVersion(), languageId, language.getVersion(),
							language.getMinorVersion(), compilerSpec.getCompilerSpecID());
					result = new FidPopulateResult(library);
				}

				populateLibraryFromProgram(program);
			}
			finally {
				if (program != null) {
					program.release(consumer);
				}
			}
		}

		resolveNamedRelations();
		if (result != null) {
			result.addChildReferences(500, childHistogram);
		}

		return result;
	}

	/**
	 * Processes a single program, adding it to the library.
	 * @param result the populate result
	 * @param program the program
	 * @throws CancelledException if the user cancels
	 */
	private void populateLibraryFromProgram(Program program) throws CancelledException {

		FidHasher hasher = service.getHasher(program);
		ArrayList<Function> theFunctions = new ArrayList<>();
		Map<Function, FunctionRow> recordMap = new HashMap<>();

		// 1) hash all the functions, create function rows for them
		hashAllTheFunctions(program, hasher, theFunctions, recordMap);

		// 3) add all the forward (child) call relatives
		for (Entry<Function, FunctionRow> entry : recordMap.entrySet()) {
			monitor.checkCanceled();
			Function function = entry.getKey();
			FunctionRow functionRow = entry.getValue();
			if (functionRow != null) {
				functionRow.children = new ArrayList<>();
				addChildRelations(function, hasher, recordMap, functionRow.children);
				Collections.sort(functionRow.children);
				long hash = functionRow.generateHash();
				if (globalUniqueFunction.add(hash)) {
					functionRow.commit(fidDb, library); // Create the database record
				}
				else {
					exclude(program.getDomainFile(), function,
						FidPopulateResult.Disposition.DUPLICATE_INFO);
				}
			}
		}

		for (Entry<Function, FunctionRow> entry : recordMap.entrySet()) {
			monitor.checkCanceled();
			FunctionRow functionRow = entry.getValue();
			FunctionRecord functionRecord = functionRow.functionRecord;
			if (functionRecord == null) {
				continue; // Function exists but was excluded as a duplicate
			}
			for (ChildRow childRow : functionRow.children) {
				if (childRow.isVeryCommon) {
					continue; // So common, don't use parent/child as distinguisher
				}
				if (childRow.toRow == null) {
					if (childRow.symbolName != null) {
						addUnresolvedSymbol(functionRecord, childRow.symbolName, null);
					}
				}
				else if (childRow.toRow.functionRecord == null) { // This child was removed locally as a duplicate
					// We need to convert this to unresolved symbol, but in this case we know the hash
					addUnresolvedSymbol(functionRecord, childRow.toRow.name,
						childRow.toRow.hashQuad);
				}
				else {
					fidDb.createRelation(functionRecord, childRow.toRow.functionRecord,
						RelationType.DIRECT_CALL);
				}
			}
		}
	}

	/**
	 * Hashes all the functions in the program for inserting into the database.
	 * @param result the populate result
	 * @param program the program
	 * @param hasher the FID hasher
	 * @param theFunctions the functions
	 * @param recordMap the map of function to function records
	 * @throws CancelledException if the user cancels
	 */
	private void hashAllTheFunctions(Program program, FidHasher hasher,
			ArrayList<Function> theFunctions, Map<Function, FunctionRow> recordMap)
			throws CancelledException {
		DomainFile domainFile = program.getDomainFile();
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator functions = functionManager.getFunctions(true);

		for (Function function : functions) {
			monitor.checkCanceled();
			if (functionIsExternal(function)) {
				continue;
			}

			theFunctions.add(function);

			String name = null;

			if (function.getSymbol().getSource() == SourceType.DEFAULT) {
				exclude(domainFile, function, FidPopulateResult.Disposition.NO_DEFINED_SYMBOL);
			}
			else {
				name = function.getSymbol().getName();
			}

			FidHashQuad hashQuad = null;
			FunctionRow functionRow = null;

			if (function.isThunk()) {
				if (name != null) {
//					theAdditionalLabels.put(function.getEntryPoint(), nameAndNamespace);
					exclude(domainFile, function, FidPopulateResult.Disposition.IS_THUNK);
				}
			}
			else if (name != null) {
				try {
					hashQuad = hasher.hash(function);
					if (hashQuad == null) {
						exclude(domainFile, function,
							FidPopulateResult.Disposition.FAILS_MINIMUM_SHORTHASH_LENGTH);
						continue;
					}

					if (functionFilter != null &&
						!functionFilter.test(new Pair<>(function, hashQuad))) {
						exclude(domainFile, function,
							FidPopulateResult.Disposition.FAILED_FUNCTION_FILTER);
						continue;
					}

					boolean hasTerminator = findTerminator(function, monitor);

					functionRow =
						new FunctionRow(domainFile, function, name, hashQuad, hasTerminator);
					recordMap.put(function, functionRow);

					result.disposition(domainFile, name, function.getEntryPoint(),
						Disposition.INCLUDED);
				}
				catch (MemoryAccessException e) {
					exclude(domainFile, function,
						FidPopulateResult.Disposition.MEMORY_ACCESS_EXCEPTION);
				}
			}
		}
	}

	/**
	 * Collects the child relations of a function in a ChildRow array.
	 * @param function the function
	 * @param hasher the FID hasher
	 * @param recordMap the map of functions to function rows
	 * @param children accumulates ChildRow objects
	 * @throws CancelledException if the user cancels
	 */
	private void addChildRelations(Function function, FidHasher hasher,
			Map<Function, FunctionRow> recordMap, ArrayList<ChildRow> children)
			throws CancelledException {
		HashSet<Address> alreadyDone = new HashSet<>();
		Program program = function.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager referenceManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		AddressIterator referenceIterator =
			referenceManager.getReferenceSourceIterator(function.getBody(), true);
		for (Address address : referenceIterator) {
			monitor.checkCanceled();
			Instruction instruction = program.getListing().getInstructionAt(address);
			if (instruction != null && instruction.getFlowType().isCall()) {
				Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
				for (Reference reference : referencesFrom) {
					monitor.checkCanceled();
					Address toAddress = reference.getToAddress();
					if (!alreadyDone.contains(toAddress)) {
						Function relation = functionManager.getFunctionContaining(toAddress);
						if (relation != null && relation.isThunk()) {
							relation = relation.getThunkedFunction(true);
						}
						if (relation == null || functionIsExternal(relation)) {
							ChildRow childRow = new ChildRow();
							childRow.toRow = null;
							childRow.symbolName = grabSymbol(symbolTable, toAddress);
							childRow.toAddress = toAddress;
							children.add(childRow);
							searchChildReferenceByName(childRow, childRow.symbolName);
						}
						else {
							FunctionRow relationRow = recordMap.get(relation);
							if (relationRow != null) {
								ChildRow childRow = new ChildRow();
								childRow.toRow = relationRow;
								childRow.symbolName = null;
								childRow.toAddress = toAddress;
								children.add(childRow);
								searchChildReferenceByName(childRow, relationRow.name);
							}
							// if the relation record was null, 99.99% sure that the
							// relation is too small to hash, so it will appear in the
							// additional labels section
						}
						alreadyDone.add(toAddress);
					}
				}
			}
		}
	}

	private static String grabSymbol(SymbolTable symbolTable, Address address) {
		Symbol[] symbols = symbolTable.getSymbols(address);
		if (symbols == null || symbols.length == 0) {
			return null;
		}
		for (Symbol symbol : symbols) {
			if (symbol.isPrimary()) {
				return symbol.getName();
			}
		}
		return null;
	}

	/**
	 * Adds an unresolved symbol (for resolution later).
	 * @param functionRecord the function record
	 * @param symbol is the symbol name
	 */
	private void addUnresolvedSymbol(FunctionRecord functionRecord, String symbol,
			FidHashQuad fidHashQuad) {
		Set<ChildSymbol> set = unresolvedSymbols.get(functionRecord);
		if (set == null) {
			set = new HashSet<>();
			unresolvedSymbols.put(functionRecord, set);
		}
		ChildSymbol childSym = new ChildSymbol();
		childSym.name = symbol;
		childSym.hashQuad = fidHashQuad;
		set.add(childSym);
	}

	/**
	 * Resolves the remembered unresolved symbols, now that we have all the library's symbols created.
	 * @throws CancelledException if the user cancels
	 */
	private void resolveNamedRelations() throws CancelledException {
		for (Entry<FunctionRecord, Set<ChildSymbol>> entry : unresolvedSymbols.entrySet()) {
			monitor.checkCanceled();
			FunctionRecord functionRecord = entry.getKey();
			Set<ChildSymbol> unresolvedForFunction = entry.getValue();
			for (ChildSymbol unresolvedSym : unresolvedForFunction) {
				monitor.checkCanceled();
				boolean handled = handleNamedRelationSearch(library, functionRecord, unresolvedSym,
					RelationType.INTRA_LIBRARY_CALL);
				if (!handled && linkLibraries != null) {
					for (LibraryRecord linkLibrary : linkLibraries) {
						monitor.checkCanceled();
						handled = handleNamedRelationSearch(linkLibrary, functionRecord,
							unresolvedSym, RelationType.INTER_LIBRARY_CALL);
						if (handled) {
							break;
						}
					}
				}
				if (!handled) {
//					FunctionRecord inferiorFunction =
//						controller.obtainDegenerateFunction(library, name, namespace);
//					controller.createRelation(functionRecord, inferiorFunction,
//						RelationType.NAMED_CHILD, 1);
					result.addUnresolvedSymbol(unresolvedSym.name);
				}
			}
		}
	}

	/**
	 * Looks for a terminating flow within a function body, returning whether it was found.
	 * @param function the function
	 * @param monitor a task monitor
	 * @return if a terminating flow was found in the function body
	 * @throws CancelledException if the user cancels
	 */
	private static boolean findTerminator(Function function, TaskMonitor monitor)
			throws CancelledException {
		boolean retFound = false;
		AddressSetView body = function.getBody();
		CodeUnitIterator codeUnitIterator =
			function.getProgram().getListing().getCodeUnits(body, true);
		while (codeUnitIterator.hasNext()) {
			monitor.checkCanceled();
			CodeUnit codeUnit = codeUnitIterator.next();
			if (codeUnit instanceof Instruction) {
				Instruction instruction = (Instruction) codeUnit;
				if (instruction.getFlowType().isTerminal()) {
					retFound = true;
					break;
				}
			}
		}
		return retFound;
	}

	/**
	 * Tries to resolve an ambiguous named relation.  If not too many hashes are found, it will
	 * add them all, because presence of one is a high indicator of match.  If too many are found,
	 * the significance drops and none of the hashes are added (so a potential result isn't diluted).
	 * @param libraryRecord the library to link against
	 * @param functionRecord the function record
	 * @param symbol the symbol to seek
	 * @param relType is the RelationType of the link (INTER_LIBRARY or INTRA_LIBRARY)
	 * @return if at least one relation was added
	 * @throws CancelledException if the user cancels
	 */
	private boolean handleNamedRelationSearch(LibraryRecord libraryRecord,
			FunctionRecord functionRecord, ChildSymbol symbol, RelationType relType)
			throws CancelledException {
		List<FunctionRecord> list = fidDb.findFunctionsByLibraryAndName(libraryRecord, symbol.name);
		HashSet<Long> hashes = new HashSet<>();
		for (FunctionRecord relation : list) {
			monitor.checkCanceled();
			// If we have hash information about the symbol, use it as additional filter
			if (symbol.hashQuad != null &&
				symbol.hashQuad.getFullHash() != relation.getFullHash()) {
				continue;
			}
			hashes.add(relation.getSpecificHash());
		}
		if (hashes.size() == 0 && (!list.isEmpty())) {
			Msg.warn(FidServiceLibraryIngest.class,
				"direct relation " + symbol.name + "lost with hash filter");
		}
		else if (hashes.size() <= MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS) {
			for (FunctionRecord relative : list) {
				monitor.checkCanceled();
				// Continue to use any hash information as filter
				if (symbol.hashQuad != null &&
					symbol.hashQuad.getFullHash() != relative.getFullHash()) {
					continue;
				}
				fidDb.createRelation(functionRecord, relative, relType);
			}
		}
		else {
			Msg.warn(FidServiceLibraryIngest.class,
				"relation " + symbol.name + " unresolved; too many possibilities");
		}
		return !list.isEmpty();
	}

	/**
	 * Make sure all programs have the same language and compiler spec,
	 * otherwise throw and exception or return false based on failOnNewLanguage
	 * @param program the program
	 * @return true if the program passes the filter
	 */
	private boolean checkLanguageCompilerSpec(Program program) {
		if (!languageId.equals(program.getLanguageID())) {
			return false;
		}
		if (compilerSpec != null) {
			if (!compilerSpec.equals(program.getCompilerSpec())) {
				throw new IllegalArgumentException(
					"Program " + program.getName() + " has different compiler spec (" +
						program.getCompilerSpec().getCompilerSpecID() +
						") than already established (" + compilerSpec.getCompilerSpecID() + ")");
			}
		}
		return true;
	}

	/**
	 * Returns whether a function is external.
	 * @param function the function
	 * @return whether the function is external
	 */
	private static boolean functionIsExternal(Function function) {
		if (function.isExternal()) {
			return true;
		}
		Address entryPoint = function.getEntryPoint();
		MemoryBlock block = function.getProgram().getMemory().getBlock(entryPoint);
		if (!block.isInitialized()) {
			return true;
		}
		return false;
	}

	private void exclude(DomainFile domainFile, Function function,
			FidPopulateResult.Disposition reason) {
		result.disposition(domainFile, function.getName(), function.getEntryPoint(), reason);
	}

	private void searchChildReferenceByName(ChildRow row, String name) {
		row.isVeryCommon = false;
		if (name == null) {
			return;
		}
		FidPopulateResult.Count count = childHistogram.get(name);
		if (count != null) {
			count.count += 1;
			row.isVeryCommon = count.isVeryCommon;
		}
		else {
			count = new FidPopulateResult.Count();
			count.count = 1;
			count.isVeryCommon = false;
			childHistogram.put(name, count);
		}
	}
}
