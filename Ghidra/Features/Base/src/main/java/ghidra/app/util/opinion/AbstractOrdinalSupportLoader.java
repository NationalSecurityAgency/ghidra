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
package ghidra.app.util.opinion;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * An abstract {@link Loader} that provides support for programs that link to external libraries
 * with an ordinal mechanism.  Supports caching library lookup information to XML files.
 */
public abstract class AbstractOrdinalSupportLoader extends AbstractLibrarySupportLoader {

	public static final String ORDINAL_LOOKUP_OPTION_NAME = "Perform Library Ordinal Lookup";
	static final boolean ORDINAL_LOOKUP_OPTION_DEFAULT = true;

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		list.add(new Option(ORDINAL_LOOKUP_OPTION_NAME, ORDINAL_LOOKUP_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-ordinalLookup"));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(ORDINAL_LOOKUP_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected boolean shouldSearchAllPaths(List<Option> options) {
		return shouldPerformOrdinalLookup(options);
	}

	@Override
	protected boolean shouldLoadLibrary(String libName, File libFile,
			ByteProvider provider, LoadSpec loadSpec, MessageLog log) throws IOException {

		if (!super.shouldLoadLibrary(libName, libFile, provider, loadSpec, log)) {
			return false;
		}

		int size = loadSpec.getLanguageCompilerSpec().getLanguageDescription().getSize();

		if (!LibraryLookupTable.hasFileAndPathAndTimeStampMatch(libFile, size) &&
			LibraryLookupTable.libraryLookupTableFileExists(libName, size)) {
			log.appendMsg("WARNING! Using existing exports file for " + libName +
				" which may not be an exact match");
		}

		return true;
	}

	@Override
	protected void processLibrary(Program lib, String libName, File libFile,
			ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		int size = loadSpec.getLanguageCompilerSpec().getLanguageDescription().getSize();

		// Create exports file
		if (!LibraryLookupTable.libraryLookupTableFileExists(libName, size) ||
			!LibraryLookupTable.hasFileAndPathAndTimeStampMatch(libFile, size)) {
			try {
				// Need to write correct library exports file (LibrarySymbolTable)
				// for use with related imports
				LibraryLookupTable.createFile(lib, true, monitor);
			}
			catch (IOException e) {
				log.appendMsg("Unable to create exports file for " + libFile);
				Msg.error(this, "Unable to create exports file for " + libFile, e);
			}
		}
	}

	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Project project,
			List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		monitor.initialize(loadedPrograms.size());

		if (shouldPerformOrdinalLookup(options)) {
			for (Loaded<Program> loadedProgram : loadedPrograms) {
				monitor.checkCancelled();
				Program program = loadedProgram.getDomainObject();
				int id = program.startTransaction("Ordinal fixups");
				try {
					applyLibrarySymbols(program, messageLog, monitor);
					applyImports(program, messageLog, monitor);
				}
				finally {
					program.endTransaction(id, true); // More efficient to commit when program will be discarded
				}
			}
		}

		super.postLoadProgramFixups(loadedPrograms, project, options, messageLog, monitor);
	}

	@Override
	protected void postLoadCleanup(boolean success) {
		super.postLoadCleanup(success);
		LibraryLookupTable.cleanup();
	}

	/**
	 * Checks to see if ordinal lookup should be performed
	 * 
	 * @param options a {@link List} of {@link Option}s
	 * @return True if ordinal lookup should be performed; otherwise, false
	 */
	private boolean shouldPerformOrdinalLookup(List<Option> options) {
		return OptionUtils.getOption(ORDINAL_LOOKUP_OPTION_NAME, options,
			ORDINAL_LOOKUP_OPTION_DEFAULT);
	}

	/**
	 * Applies the library symbol table to the {@link Program} being loaded. For example, if you 
	 * load "mfc42.dll", it will create the named symbols along with the ordinals.
	 *
	 * @param program The program being loaded.
	 * @param log The message log.
	 * @param monitor A cancelable task monitor.
	 * @throws CancelledException if the user cancelled the load.
	 */
	private void applyLibrarySymbols(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Applying information..." + program.getName());

		// Check based on the original program name, not on the name I gave this program
		int size = program.getLanguage().getLanguageDescription().getSize();

		LibrarySymbolTable symtab = LibraryLookupTable.getSymbolTable(
			new File(program.getExecutablePath()).getName(), size, log);
		if (symtab == null) {
			// now try based on the name given to the program
			symtab = LibraryLookupTable.getSymbolTable(program.getName(), size, log);
			if (symtab == null) {
				return;
			}
		}
		if (!isVersionMatch(program, symtab, log)) {
			return;
		}

		SymbolIterator iter =
			program.getSymbolTable().getSymbolIterator(SymbolUtilities.ORDINAL_PREFIX + "*", true);
		while (iter.hasNext()) {
			monitor.checkCancelled();
			Symbol ordSym = iter.next();
			if (!ordSym.getAddress().isMemoryAddress()) {
				continue;
			}
			if (!ordSym.getParentNamespace().equals(program.getGlobalNamespace())) {
				continue;
			}
			int ordinal = SymbolUtilities.getOrdinalValue(ordSym.getName());
			LibraryExportedSymbol les = symtab.getSymbol(ordinal);
			if (les == null || les.getName() == null) {
				continue;
			}
			try {
				Symbol nameSym =
					program.getSymbolTable().getGlobalSymbol(les.getName(), ordSym.getAddress());
				if (nameSym == null) {
					String name = les.getName();
					Symbol s = program.getSymbolTable()
							.createLabel(ordSym.getAddress(), name,
								program.getGlobalNamespace(), SourceType.IMPORTED);
					s.setPrimary();
				}
			}
			catch (InvalidInputException e) {
				log.appendMsg("Error creating label named " + les.getName() + " at address " +
					ordSym.getAddress() + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Applies the library symbol table to the imported symbols of the specified
	 * {@link Program}. Symbols may also be demangled (although this could be a mistake).
	 * 
	 * @param program The {@link Program} whose imports should be resolved.
	 * @param log import message log
	 * @param monitor task monitor, if cancelled partial results may exist
	 */
	private void applyImports(Program program, MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Applying imports..." + program.getName());

		ExternalManager em = program.getExternalManager();

		String[] libs = em.getExternalLibraryNames();

		for (String lib : libs) {
			if (monitor.isCancelled()) {
				return;
			}

			int size = program.getLanguage().getLanguageDescription().getSize();

			LibrarySymbolTable symtab = LibraryLookupTable.getSymbolTable(lib, size, log);

			Iterator<ExternalLocation> iter = em.getExternalLocations(lib);
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					return;
				}

				ExternalLocation extLoc = iter.next();

				String symName = extLoc.getLabel();

				// this check belongs here, because we want to demangled even
				// if we do not have a symbol table...
				if (symtab == null) {
					continue;
				}

				// if symbol is imported by ordinal, then see if the
				// library contains a name for that ordinal. if so,
				// then rename the symbol

				LibraryExportedSymbol expSym = symtab.getSymbol(symName);
				if (expSym == null) {
					try {
						int ord = SymbolUtilities.getOrdinalValue(symName);
						if (ord == -1) {
							continue;
						}

						expSym = symtab.getSymbol(ord);

						if (expSym == null) {
							log.appendMsg("Unable to locate symbol [" + symName + "] in [" +
								LibraryLookupTable.getExistingExportsFile(lib, size) +
								"]. Please verify the version is correct.");
							continue;
						}

						extLoc.setLocation(expSym.getName(), extLoc.getAddress(),
							SourceType.IMPORTED);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						log.appendMsg("Error creating label: ", e.getMessage());
					}
				}

				int purgeSize = expSym.getPurge();
				// no purge size for 64-bit programs
				boolean isNot32Bit = size > 32;
				if ((purgeSize == -1 || purgeSize < -1024 || purgeSize > 1024) || isNot32Bit) {
					continue;
				}

				// Create or get external function
				Function extFunc = extLoc.createFunction();

				extFunc.setStackPurgeSize(purgeSize);
				if (expSym.hasNoReturn()) {
					extFunc.setNoReturn(true);
				}
// TODO: This should not be done at time of import and should be done
// by a late running analyzer (e.g., stack analyzer) if no signature
// has been established
//				int stackShift = program.getCompilerSpec().getDefaultCallingConvention().getStackshift();
//				if (stackShift == -1) {
//					stackShift = 0;
//				}

//				int numParams = expSym.getPurge() / 4;
//				if (numParams > 0) {
//					// HACK: assumes specific stack-based x86 convention
//					try {
//						Parameter[] params = new Parameter[numParams];
//						for (int ind = 0; ind < numParams; ind++) {
//							params[ind] = new ParameterImpl(null, Undefined.getUndefinedDataType(4),
//								ind * 4 + stackShift, p);
//						}
//						extFunc.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
//							false, SourceType.ANALYSIS, params);
//					}
//					catch (InvalidInputException | DuplicateNameException e) {
//						log.appendMsg("Error creating label: ", e.getMessage());
//					}
//				}

			}
		}
	}

	private boolean isVersionMatch(DomainObject p, LibrarySymbolTable symtab, MessageLog log) {
		String version = getRidOfVersionAlias(symtab.getVersion());

		Options options = p.getOptions(Program.PROGRAM_INFO);
		String programVersion =
			getRidOfVersionAlias(options.getString("ProductVersion", (String) null));

		if (programVersion == null) {
			return false;
		}

		boolean match = programVersion.equalsIgnoreCase(version);

		if (!match) {
			log.appendMsg("Library version mismatch in .exports file for " + p.getName());
			log.appendMsg("   expected " + programVersion + " but was " + version);
		}
		return match;
	}

	private static String getRidOfVersionAlias(String version) {
		if (version == null) {
			return null;
		}

		int aliasOpenParenPosition = version.indexOf('(');

		if (aliasOpenParenPosition == -1) {
			return version.trim();
		}

		return version.substring(0, aliasOpenParenPosition).trim();
	}

}
