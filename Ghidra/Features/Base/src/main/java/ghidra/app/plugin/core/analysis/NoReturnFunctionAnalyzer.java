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
package ghidra.app.plugin.core.analysis;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

import generic.jar.ResourceFile;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlParseException;

public class NoReturnFunctionAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Non-Returning Functions - Known";
	private static final String DESCRIPTION = "Locates known functions by name, that generally " +
		"do not return (exit, abort, etc) and sets the \"No Return\" flag.";

	private static final String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"If checked, an analysis bookmark will created on each function marked as non-returning.";
	private static final boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	private Set<String> functionNames;

	public NoReturnFunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		// this needs to run before almost all other analyzers,
		// since non-returning functions cause many issues that are slow to fix later.
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before().before().before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return NonReturningFunctionNames.hasDataFiles(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		try {
			loadFunctionNamesIfNeeded(program);
		}
		catch (Exception e) {
			log.appendMsg("Failed to load non-returning function name list: " + e.getMessage());
		}

		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator iterator = symbolTable.getPrimarySymbolIterator(set, true);

		// AddressIterator iterator =
		// symbolTable.getExternalEntryPointIterator();
		while (iterator.hasNext()) {
			Symbol symbol = iterator.next();

			String name = symbol.getName(false);

			// strip leading '_' chars
			int startIndex = 0;
			int nameLength = name.length();
			while (startIndex < nameLength && name.charAt(startIndex) == '_') {
				++startIndex;
			}
			if (startIndex > 0) {
				name = name.substring(startIndex);
			}

			if (!functionNames.contains(name)) {
				continue;
			}

			// if this is an external entry place holder, create the function in the external entry location
			symbol = checkForAssociatedExternalSymbol(symbol);

			if (symbol.isExternal()) {
				ExternalLocation externalLocation =
					program.getExternalManager().getExternalLocation(symbol);
				if (externalLocation != null) {
					Function functionAt = externalLocation.createFunction();
					//Msg.debug(this,
					//	"Setting \"no return\" flag on external function " + symbol.getName(true));
					functionAt.setNoReturn(true);
				}
				continue;
			}

			Address address = symbol.getAddress();
			if (symbol.getSymbolType() == SymbolType.LABEL) {
				if (!SymbolType.FUNCTION.isValidParent(program, symbol.getParentNamespace(),
					address, false)) {
					continue; // skip if parent does not permit function creation
				}
				CreateFunctionCmd fCommand = new CreateFunctionCmd(address);
				fCommand.applyTo(program, monitor);
			}

			Function functionAt = program.getFunctionManager().getFunctionAt(address);
			if (functionAt == null) {
				log.appendMsg("Failed to create \"no return\" function " + symbol.getName(true) +
					" at " + address);
				continue;
			}

			//Msg.debug(this, "Setting \"no return\" flag on function " + symbol.getName(true) +
			//	" at " + address);

			functionAt.setNoReturn(true);

			// disassembled later after all bad functions have been marked

			if (createBookmarksEnabled) {
				program.getBookmarkManager().setBookmark(address, BookmarkType.ANALYSIS,
					"Non-Returning Function", "Non-Returning Function Identified");
			}
		}

		// now that all the functions are set, safe to disassemble
		// should not disassemble here, could be just a pointer, disassemble later
		return true;
	}

	/**
	 * If symbol corresponds to a pointer which references an external symbol return 
	 * the referenced external symbol, otherwise return the symbol provided.</li>
	 * @param symbol - symbol to check for an external reference
	 * @return referenced external symbol or original symbol
	 */
	private Symbol checkForAssociatedExternalSymbol(Symbol symbol) {
		Program program = symbol.getProgram();
		Address addr = symbol.getAddress();
		if (addr.isExternalAddress()) {
			return symbol;
		}

		Data data = program.getListing().getDefinedDataAt(symbol.getAddress());
		if (data == null || !data.isPointer()) {
			return symbol;
		}

		// get the code unit at the location
		// if there is a reference to an external, place the function there.
		Reference[] referencesFrom = program.getReferenceManager().getReferencesFrom(addr);
		for (Reference reference : referencesFrom) {
			if (reference.isExternalReference()) {
				return program.getSymbolTable().getPrimarySymbol(reference.getToAddress());
			}
		}

		return symbol;
	}

	private void loadFunctionNamesIfNeeded(Program program)
			throws FileNotFoundException, IOException, XmlParseException {

		if (functionNames != null) {
			return;
		}

		functionNames = new HashSet<>();

		ResourceFile[] files = NonReturningFunctionNames.findDataFiles(program);
		for (ResourceFile file : files) {

			BufferedReader reader =
				new BufferedReader(new InputStreamReader(file.getInputStream()));
			try {
				while (true) {
					String line = reader.readLine();
					if (line == null) {
						break;
					}
					line = line.trim();
					if (line.length() == 0 || line.charAt(0) == '#') {
						continue;
					}
					int startIndex = 0;
					while (line.charAt(startIndex) == '_') {
						++startIndex;
					}
					if (startIndex != 0) {
						Msg.warn(this, "Ignoring leading '_' chars on no-return name '" + line +
							"' specified in file: " + file.getAbsolutePath());
						line = line.substring(startIndex);
					}
					functionNames.add(line.trim());
				}
			}
			finally {
				reader.close();
			}
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);

	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);
	}
}
