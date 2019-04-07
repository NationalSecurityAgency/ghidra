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
package ghidra.feature.fid.cmd;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.demangler.DemangledObject;
import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.service.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ApplyFidEntriesCommand extends BackgroundCommand {
	public static final String FID_CONFLICT = "FID_conflict:";
	public static final int MAGIC_MULTIPLE_MATCH_LIMIT = 10;
	public static final int MAGIC_MULTIPLE_LIBRARY_LIMIT = 5;
	public static final int MAX_PLATE_COMMENT_LINE_LENGTH = 58;

	private MatchNameAnalysis nameAnalysis = new MatchNameAnalysis();
	private AddressSet affectedLocations = new AddressSet();
	private boolean alwaysApplyFidLabels;
	private float scoreThreshold;
	private float multiNameScoreThreshold;
	private boolean createBookmarksEnabled;

	public ApplyFidEntriesCommand(AddressSetView set, float scoreThreshold, float multiThreshold,
			boolean alwaysApplyFidLabels, boolean createBookmarksEnabled) {
		super("ApplyFidEntriesCommand", true, true, false);
		this.scoreThreshold = scoreThreshold;
		this.multiNameScoreThreshold = multiThreshold;
		this.alwaysApplyFidLabels = alwaysApplyFidLabels;
		this.createBookmarksEnabled = createBookmarksEnabled;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		FidService service = new FidService();

		if (obj instanceof Program) {
			Program program = (Program) obj;

			if (!service.canProcess(program.getLanguage())) {
				return false;
			}

			try (FidQueryService fidQueryService =
				service.openFidQueryService(program.getLanguage(), false)) {

				List<FidSearchResult> processProgram =
					service.processProgram(program, fidQueryService, scoreThreshold, monitor);
				if (processProgram == null) {
					return false;
				}

				for (FidSearchResult entry : processProgram) {
					monitor.checkCanceled();

					monitor.incrementProgress(1);
					if (entry.function.isThunk()) {
						continue;
					}

					if (!entry.matches.isEmpty()) {
						processMatches(entry, program, monitor);
					}
					else {
						Msg.trace(this, "no results for function " + entry.function.getName() +
							" at " + entry.function.getEntryPoint());
					}
				}
			}
			catch (CancelledException e) {
				return false;
			}
			catch (VersionException | IOException e) {
				setStatusMsg(e.getMessage());
				return false;
			}

			return true;
		}
		return false;
	}

	private void processMatches(FidSearchResult result, Program program, TaskMonitor monitor)
			throws CancelledException {
		String bookmarkContents = null;
		String plateCommentContents = null;

		if (result.matches.size() == 0) {
			// nothing to do - eliminate functions above might have removed all possibilities
			return;
		}

		nameAnalysis.analyzeNames(result.matches, program, monitor);
		if (nameAnalysis.getMostOptimisticCount() > 1) { // If we can't narrow down to a single name
			if (nameAnalysis.getOverallScore() < multiNameScoreThreshold) {
				return;
			}
		}
		nameAnalysis.analyzeLibraries(result.matches, MAGIC_MULTIPLE_LIBRARY_LIMIT, monitor);

		String newFunctionName = null;
		if (nameAnalysis.numNames() == 1) {
			newFunctionName = nameAnalysis.getNameIterator().next();
		}

		if (nameAnalysis.numSimilarNames() == 1) { // If all names are the same, up to a difference in '_' prefix
			bookmarkContents = "Library Function - Single Match, ";
			plateCommentContents = "Library Function - Single Match";
		}
		else { // If names are different in some way
			bookmarkContents = "Library Function - Multiple Matches, ";
			plateCommentContents = "Library Function - Multiple Matches";
			if (nameAnalysis.numNames() == 1) {
				plateCommentContents = plateCommentContents + " With Same Base Name";
				bookmarkContents = bookmarkContents + "Same ";
			}
			else {
				plateCommentContents = plateCommentContents + " With Different Base Names";
				bookmarkContents = bookmarkContents + "Different ";
			}
		}
		// multiple matches - TODO: change to show classes vs libraries - libraries with same name don't put "base" name only for class ones

		plateCommentContents = generateComment(plateCommentContents, true, false, monitor);
		bookmarkContents = generateBookmark(bookmarkContents, true, false, monitor);

		applyMarkup(result.function, newFunctionName, plateCommentContents, bookmarkContents,
			monitor);
	}

	private String listNames(TaskMonitor monitor) throws CancelledException {
		StringBuilder buffer = new StringBuilder();

		int counter = 0;

		if (nameAnalysis.numNames() < MAGIC_MULTIPLE_MATCH_LIMIT) {
			buffer.append("Name: ");
			Iterator<String> iterator = nameAnalysis.getNameIterator();
			while (iterator.hasNext()) {
				monitor.checkCanceled();
				if (counter != 0) {
					buffer.append(", ");
				}
				buffer.append(iterator.next());
				counter++;
			}
		}
		else {
			buffer.append("Names: " + nameAnalysis.numSimilarNames() + " - too many to list");
		}

		return buffer.toString();
	}

	private String listLibraries(TaskMonitor monitor) throws CancelledException {
		StringBuilder buffer = new StringBuilder();

		if (nameAnalysis.numLibraries() == 1) {
			buffer.append("Library: ");
		}
		else {
			buffer.append("Libraries: ");
		}
		int counter = 0;

		if (nameAnalysis.numLibraries() < MAGIC_MULTIPLE_LIBRARY_LIMIT) {
			Iterator<String> iterator = nameAnalysis.getLibraryIterator();
			while (iterator.hasNext()) {
				monitor.checkCanceled();
				if (counter != 0) {
					buffer.append(", ");
				}
				buffer.append(iterator.next());
				counter++;
			}
		}
		else {
			buffer.append(nameAnalysis.numLibraries() + " - too many to list");
		}

		return buffer.toString();
	}

	private String generateComment(String header, boolean includeNames, boolean includeNamespaces,
			TaskMonitor monitor) throws CancelledException {
		StringBuilder buffer = new StringBuilder();
		buffer.append(header);

		// append names, class, and library info buffer
		buffer.append("\n");
		buffer.append(listNames(monitor));
		buffer.append("\n");
		buffer.append(listLibraries(monitor));

		return buffer.toString();
	}

	private String generateBookmark(String bookmark, boolean includeNames,
			boolean includeNamespaces, TaskMonitor monitor) throws CancelledException {
		StringBuilder buffer = new StringBuilder();
		if (createBookmarksEnabled) {
			buffer.append(bookmark);

			// append names, class, and library info buffer
			buffer.append(" ");
			buffer.append(listNames(monitor));

			buffer.append(", ");
			buffer.append(listLibraries(monitor));
		}

		return buffer.toString();
	}

	private void applyMarkup(Function function, String newFunctionName, String plateCommentContents,
			String bookmarkContents, TaskMonitor monitor) throws CancelledException {

		// don't need to apply fid unless there are no "good" symbols or the option is set to always do it.
		if (!alwaysApplyFidLabels && hasUserOrImportedSymbols(function)) {
			return;
		}

		int numUniqueLabelNames;

		// single name case ok
		if (newFunctionName != null) {
			addFunctionLabel(function, newFunctionName, monitor);
			numUniqueLabelNames = 1;
		}
		// multiple names
		else {
			numUniqueLabelNames = addFunctionLabelMultipleMatches(function, monitor);
		}
		if (numUniqueLabelNames < MAGIC_MULTIPLE_MATCH_LIMIT) {
			if (plateCommentContents != null && !plateCommentContents.equals("")) {
				function.setComment(plateCommentContents);
			}
			if (bookmarkContents != null && !bookmarkContents.equals("")) {
				function.getProgram().getBookmarkManager().setBookmark(function.getEntryPoint(),
					BookmarkType.ANALYSIS, "Function ID Analyzer", bookmarkContents);
			}
		}
	}

	/**
	 * Returns true if there are symbol names at the function entry point that were either
	 * created by a user or an importer. (i.e trusted)
	 * @param function the function to test for trusted symbols
	 * @return true if there are symbol names at the function entry point that were either
	 */
	private boolean hasUserOrImportedSymbols(Function function) {
		Program program = function.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(function.getEntryPoint());
		for (Symbol symbol : symbols) {
			SourceType sourceType = symbol.getSource();
			if (sourceType == SourceType.USER_DEFINED || sourceType == SourceType.IMPORTED) {
				return true;
			}
		}
		return false;
	}

	private void addFunctionLabel(Function function, String newFunctionName, TaskMonitor monitor)
			throws CancelledException {

		removeConflictSymbols(function, newFunctionName, monitor);

		//now add the unique symbol name to the matched function - could have done this before deduping but would have to check for it and ignore it - easier to do later
		addSymbolToFunction(function, newFunctionName);
	}

	// This is called when a single library match is made. It checks to see if the label of the single match is contained in
	// any "libID_conflict" labels. If it is, that label is removed from the other function(s) since it is no longer a possibility.
	// Also checks those locations to see if there is only one other libID_conflict label left and if so, removes the "libID_conflict"
	// prefix
	private void removeConflictSymbols(Function function, String matchName, TaskMonitor monitor)
			throws CancelledException {

		Program program = function.getProgram();
		SymbolTable symTab = program.getSymbolTable();

		//get all currently created FID functions
		BookmarkManager bkMgr = program.getBookmarkManager();
		Iterator<Bookmark> bkmkIterator = bkMgr.getBookmarksIterator("Function ID Analyzer");

		//iterate over all instances of libID_conflict_<matchName>_<possibly addr> and delete them
		while (bkmkIterator.hasNext()) {
			monitor.checkCanceled();

			Bookmark nextBkmark = bkmkIterator.next();
			Symbol symbols[] = symTab.getSymbols(nextBkmark.getAddress());
			for (Symbol symbol : symbols) {
				monitor.checkCanceled();

				//if the symbol matches prefix+matchName exactly
				//OR if no _ exists immediately after the prefix + matchName part of the found symbol (meaning there is no address following)
				//OR if there is an _ immediately following the prefix+Name AND and address directly following it we can be sure it is a good symbol match and can delete it
				//otherwise it contains extra characters indicating an invalid match and we don't want to delete it
				String name = symbol.getName();

				if (name.startsWith(FID_CONFLICT)) {
					String baseName = name.substring(FID_CONFLICT.length());
					Address symAddr = symbol.getAddress();
					if (baseName.equals(matchName)) {

						symbol.delete();

						// check to see if there is only one symbol left on that function
						// that has a libID_conflict name and if so remove the conflict part
						removeConflictFromSymbolWhenOnlyOneLeft(symTab, symAddr, monitor);
						break;
					}
				}
			}
		}
	}

	//check to see if there is only one symbol left on that function
	// that has a libID_conflict name and if so remove the conflict part
	private void removeConflictFromSymbolWhenOnlyOneLeft(SymbolTable symTab, Address symAddr,
			TaskMonitor monitor) throws CancelledException {

		//First get all symbols at the removed symbol address
		Symbol[] symbols = symTab.getSymbols(symAddr);

		//Next, check to see if there is only one symbol, if it has prefix remove the prefix, otherwise just skip to end
		if (symbols.length == 1) {
			if (symbols[0].getName().startsWith(FID_CONFLICT)) {
				removeConflictFromSymbol(symbols[0].getSource(), symbols[0]);
			}
		}

		// if more than one symbol, check to see if only one has libIDconflict
		else {
			int conflictCount = 0;
			Symbol keepSymbol = null;
			SourceType keepSymbolSource = null;

			for (Symbol symbol : symbols) {
				monitor.checkCanceled();

				if (conflictCount > 1) {
					keepSymbol = null;
					keepSymbolSource = null;
					break;
				}
				if (symbol.getName().startsWith(FID_CONFLICT)) {
					conflictCount++;
					keepSymbol = symbol;
					keepSymbolSource = symbol.getSource();
				}
			}
			if (keepSymbol != null) {
				removeConflictFromSymbol(keepSymbolSource, keepSymbol);
			}

		}
	}

	private void removeConflictFromSymbol(SourceType sourceType, Symbol symbol) {

		String newName = symbol.getName().substring(FID_CONFLICT.length());
		try {
			symbol.setName(newName, sourceType);
		}
		catch (DuplicateNameException e) {
			Msg.warn(SymbolUtilities.class,
				"Duplicate symbol name \"" + newName + "\" at " + symbol.getAddress());
		}
		catch (InvalidInputException e) {
			throw new AssertException(e); // unexpected
		}
	}

	private int addFunctionLabelMultipleMatches(Function function, TaskMonitor monitor)
			throws CancelledException {

		Program program = function.getProgram();
		Set<String> matchNames = nameAnalysis.getAppriateNamesSet();

		if (matchNames.size() >= MAGIC_MULTIPLE_MATCH_LIMIT) {
			return matchNames.size();
		}

		Set<String> unusedNames = getFIDNamesThatDontExistSomewhereElse(program, matchNames);

		for (String baseName : unusedNames) {
			monitor.checkCanceled();
			String functionName = getFunctionNameForBaseName(program, baseName, unusedNames);
			addSymbolToFunction(function, functionName);
		}

		return unusedNames.size();
	}

	/**
	 * Returns the symbol name to use based on if there are multiple conficts for a function
	 * If there is only one matching name, then it is used directly. Otherwise, "FID_conflict:"
	 * is prepended to the name.
	 */
	private String getFunctionNameForBaseName(Program program, String baseName,
			Set<String> unusedNames) {
		if (unusedNames.size() == 1) {
			return baseName;
		}

		DemangledObject demangledObj = NameVersions.demangle(program, baseName);
		if (demangledObj != null) {
			baseName = demangledObj.getName();
		}
		return FID_CONFLICT + baseName;
	}

	/**
	 * Takes a set of FID matching names and returns a subset that includes only names that don't exist
	 * somewhere else in the program.
	 */
	private Set<String> getFIDNamesThatDontExistSomewhereElse(Program program,
			Set<String> matchNames) {

		Set<String> unusedNames = new HashSet<String>();
		for (String name : matchNames) {
			if (!nameExistsSomewhereElse(program.getSymbolTable(), name)) {
				unusedNames.add(name);
			}
		}
		return unusedNames;
	}

	//Check to see if other functions exist with the same baseName or _baseName or __baseName
	private boolean nameExistsSomewhereElse(SymbolTable symTab, String baseName) {

		//I did it this way because doing it with an iterator and wildcard was really really slow
		List<Symbol> globalSymbols = symTab.getLabelOrFunctionSymbols(baseName, null);
		if (!globalSymbols.isEmpty()) {
			return true;
		}

		globalSymbols = symTab.getLabelOrFunctionSymbols("_" + baseName, null);
		if (!globalSymbols.isEmpty()) {
			return true;
		}

		globalSymbols = symTab.getLabelOrFunctionSymbols("__" + baseName, null);
		if (!globalSymbols.isEmpty()) {
			return true;
		}

		return false;

	}

	private void addSymbolToFunction(Function function, String name) {
		SymbolTable symbolTable = function.getProgram().getSymbolTable();
		Address address = function.getEntryPoint();
		try {
			symbolTable.createLabel(address, name, null, SourceType.ANALYSIS);
			affectedLocations.add(address);
		}
		catch (InvalidInputException e) {
			Msg.warn(SymbolUtilities.class, "Invalid symbol name: \"" + name + "\" at " + address);
		}
	}

	public AddressSetView getFIDLocations() {
		return new AddressSetViewAdapter(affectedLocations);
	}

}
