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
package ghidra.program.util;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;

import db.Transaction;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Moves dangling external function symbols found in the {@link Library#UNKNOWN EXTERNAL/UNKNOWN}
 * namespace into the namespace of the external library that publishes a matching symbol.
 * <p>
 * This uses an ordered list of external library names that was attached to the program during
 * import by the Elf or Macho loader (see {@link #REQUIRED_LIBRARY_PROPERTY_PREFIX}).
 * 
 */
public class ExternalSymbolResolver implements Closeable {
	private final static String REQUIRED_LIBRARY_PROPERTY_PREFIX = "Required Library [";

	/**
	 * Gets a program property name to represent the ordered required library of the given index
	 * 
	 * @param libraryIndex The index of the required library
	 * @return A program property name to represent the ordered required library of the given index
	 */
	public static String getRequiredLibraryProperty(int libraryIndex) {
		return String.format("%s %s]", REQUIRED_LIBRARY_PROPERTY_PREFIX,
			StringUtilities.pad("" + libraryIndex, ' ', 4));
	}

	private final ProjectData projectData;
	private final TaskMonitor monitor;
	private final List<ProgramSymbolResolver> programsToFix = new ArrayList<>();
	private final Map<String, Program> loadedPrograms = new HashMap<>();
	private final Map<String, Throwable> problemLibraries = new HashMap<>();

	public ExternalSymbolResolver(ProjectData projectData, TaskMonitor monitor) {
		this.projectData = projectData;
		this.monitor = monitor;
	}

	/**
	 * Queues a program into this session that will be fixed when {@link #fixUnresolvedExternalSymbols()}
	 * is called.
	 * <p>
	 * The program should be fully persisted to the project if using this method, otherwise use
	 * {@link #addProgramToFixup(String, Program)} and specify the pathname the program will 
	 * be saved to.
	 *  
	 * @param program {@link Program} to fix
	 */
	public void addProgramToFixup(Program program) {
		addProgramToFixup(program.getDomainFile().getPathname(), program);
	}

	/**
	 * Queues a program into this session that will be fixed when {@link #fixUnresolvedExternalSymbols()}
	 * is called.
	 *  
	 * @param programPath string project path to the program
	 * @param program {@link Program} to fix
	 */
	public void addProgramToFixup(String programPath, Program program) {
		programsToFix.add(new ProgramSymbolResolver(program, programPath));
		addLoadedProgram(programPath, program);
	}

	/**
	 * Adds an already opened program to this session, allowing it to be used as an external
	 * library without needing to look it up in the current project.
	 * 
	 * @param programPath project path to already opened program
	 * @param program {@link Program}
	 */
	public void addLoadedProgram(String programPath, Program program) {
		if (loadedPrograms.put(programPath, program) == null) {
			program.addConsumer(this);
		}
	}

	/**
	 * Returns true if there was an error encountered when trying to open an external library.
	 * 
	 * @return boolean flag, true if there was a problem opening an external library
	 */
	public boolean hasProblemLibraries() {
		return !problemLibraries.isEmpty();
	}

	@Override
	public void close() {
		for (Program prog : loadedPrograms.values()) {
			prog.release(this);
		}
		programsToFix.clear();
		loadedPrograms.clear();
	}

	/**
	 * Resolves any unresolved external symbols in each program that has been queued up via
	 * {@link #addProgramToFixup(String, Program)}.
	 * 
	 * @throws CancelledException if cancelled
	 */
	public void fixUnresolvedExternalSymbols() throws CancelledException {
		for (ProgramSymbolResolver psr : programsToFix) {
			psr.resolveExternalSymbols();
		}
	}

	/**
	 * Logs information about the libraries and symbols that were found during the fixup.
	 * 
	 * @param logger consumer that will log a string
	 * @param shortSummary boolean flag, if true individual symbol names will be omitted
	 */
	public void logInfo(Consumer<String> logger, boolean shortSummary) {
		for (ProgramSymbolResolver psr : programsToFix) {
			psr.log(logger, shortSummary);
		}
	}

	/**
	 * Fetches a program from a cache of Program instances.  If the requested program
	 * isn't currently in the cache, it will be opened (if possible).
	 * <p>
	 * This cache of programs are pinned by registering a consumer on the program, and will be
	 * released during {@link #close()} of this ExternalSymbolServer instance.
	 * <p>
	 * This cache is shared between all ProgramSymbolResolver instances (that were created
	 * by calling {@link #addProgramToFixup(String, Program)}).
	 * 
	 * @param libPath project path to a library program
	 * @return {@link Program}, or null if not found or other error during opening
	 * @throws CancelledException if cancelled
	 */
	protected Program getLibraryProgram(String libPath) throws CancelledException {
		Program result = loadedPrograms.get(libPath);
		if (result == null && projectData != null && !problemLibraries.containsKey(libPath)) {
			result = openLibraryFile(projectData.getFile(libPath), libPath);

			if (result != null) {
				loadedPrograms.put(libPath, result);
			}
		}
		return result;
	}

	/**
	 * Opens a library binary.
	 * 
	 * @param libDf optional, reference to a the DomainFile that was found in a project.  If null
	 * (meaning a lookup in the project failed to find a matching file), libPath will be used when
	 * creating error strings that reference the problematic file
	 * @param libPath project path for the DomainFile
	 * @return a opened {@link Program}
	 * @throws CancelledException if cancelled
	 */
	protected Program openLibraryFile(DomainFile libDf, String libPath) throws CancelledException {
		try {
			if (libDf == null) {
				throw new IOException("Dangling external path: " + libPath);
			}
			DomainObject libDo = libDf.getDomainObject(this, false, false, monitor);
			if (libDo instanceof Program p) {
				return p;
			}
			libDo.release(this);
			throw new IOException("Referenced external program is not a program: " + libPath);
		}
		catch (IOException | VersionException e) {
			problemLibraries.put(libPath, e);
		}
		return null;
	}

	/**
	 * Represents a program that needs its external symbols to be fixed.
	 */
	private class ProgramSymbolResolver {
		record ExtLibInfo(String name, Library lib, String programPath, Program program,
				List<String> resolvedSymbols, Throwable problem) {
			String getProblemMessage() {
				if (problem instanceof VersionException ve) {
					return getVersionError(ve);
				}
				return problem != null ? problem.getMessage() : "";
			}

			String getLibPath() {
				return programPath != null ? programPath : "missing";
			}

			String getVersionError(VersionException ve) {
				String versionType = switch (ve.getVersionIndicator()) {
					case VersionException.NEWER_VERSION -> " newer";
					case VersionException.OLDER_VERSION -> "n older";
					default -> "n unknown";
				};

				String upgradeMsg = ve.isUpgradable() ? " (upgrade is possible)" : "";

				return "skipped: file was created with a%s version of Ghidra%s"
						.formatted(versionType, upgradeMsg);
			}

		}

		Program program;
		String programPath;
		int externalSymbolCount;
		List<Long> unresolvedExternalFunctionIds;
		List<ExtLibInfo> extLibs = new ArrayList<>();

		private ProgramSymbolResolver(Program program, String programPath) {
			this.program = program;
			this.programPath = programPath;
		}

		private int getResolvedSymbolCount() {
			return externalSymbolCount - unresolvedExternalFunctionIds.size();
		}

		private void log(Consumer<String> logger, boolean shortSummary) {
			boolean changed = unresolvedExternalFunctionIds.size() != externalSymbolCount;
			if (extLibs.isEmpty() && externalSymbolCount == 0) {
				return;
			}
			else if (!changed && !hasSomeLibrariesConfigured()) {
				logger.accept(
					"Resolving External Symbols of [%s] - %d unresolved symbols, no external libraries configured - skipping"
							.formatted(programPath, externalSymbolCount));
				return;
			}

			logger.accept("Resolving External Symbols of [%s]%s".formatted(programPath,
				shortSummary ? " - Summary" : ""));
			logger.accept("\t%d external symbols resolved, %d remain unresolved"
					.formatted(getResolvedSymbolCount(), unresolvedExternalFunctionIds.size()));
			for (ExtLibInfo extLib : extLibs) {
				if (extLib.problem != null) {
					logger.accept("\t[%s] -> %s, %s".formatted(extLib.name, extLib.getLibPath(),
						extLib.getProblemMessage()));
				}
				else if (extLib.programPath != null) {
					logger.accept("\t[%s] -> %s, %d new symbols resolved".formatted(extLib.name,
						extLib.getLibPath(), extLib.resolvedSymbols.size()));
				}
				else {
					logger.accept("\t[%s] -> %s".formatted(extLib.name, extLib.getLibPath()));
				}
				if (!shortSummary) {
					for (String symbolName : extLib.resolvedSymbols) {
						logger.accept("\t\t[%s]".formatted(symbolName));
					}
				}
			}
			if (!shortSummary && changed) {
				if (!unresolvedExternalFunctionIds.isEmpty()) {
					logger.accept("\tUnresolved remaining %d:"
							.formatted(unresolvedExternalFunctionIds.size()));
					SymbolTable symbolTable = program.getSymbolTable();
					for (Long symId : unresolvedExternalFunctionIds) {
						Symbol s = symbolTable.getSymbol(symId);
						logger.accept("\t\t[%s]".formatted(s.getName()));
					}
				}
			}
		}

		private boolean hasSomeLibrariesConfigured() {
			for (ExtLibInfo extLib : extLibs) {
				if (extLib.program != null || extLib.problem != null ||
					extLib.programPath != null) {
					return true;
				}
			}
			return false;
		}

		private void resolveExternalSymbols() throws CancelledException {
			unresolvedExternalFunctionIds = getUnresolvedExternalFunctionIds();
			externalSymbolCount = unresolvedExternalFunctionIds.size();

			if (unresolvedExternalFunctionIds.isEmpty()) {
				return;
			}

			extLibs = getLibsToSearch();

			if (!extLibs.isEmpty()) {
				try (Transaction tx = program.openTransaction("Resolve External Symbols")) {
					for (ExtLibInfo extLib : extLibs) {
						monitor.checkCancelled();
						resolveSymbolsToLibrary(extLib);
					}
				}
			}

		}

		/**
		 * Returns an ordered list of external libraries that need to be searched.
		 * 
		 * @return list of ExtLibInfo elements, each representing an external library dependency
		 * found in the {@link #program}
		 * @throws CancelledException if cancelled
		 */
		private List<ExtLibInfo> getLibsToSearch() throws CancelledException {
			List<ExtLibInfo> result = new ArrayList<>();
			ExternalManager externalManager = program.getExternalManager();
			for (String libName : getOrderedRequiredLibraryNames()) {
				Library lib = externalManager.getExternalLibrary(libName);
				String libPath = lib != null ? lib.getAssociatedProgramPath() : null;
				Program libProg = libPath != null ? getLibraryProgram(libPath) : null;
				Throwable problem =
					libProg == null && libPath != null ? problemLibraries.get(libPath) : null;

				result.add(
					new ExtLibInfo(libName, lib, libPath, libProg, new ArrayList<>(), problem));
			}
			return result;
		}

		/**
		 * Moves unresolved functions from the EXTERNAL/UNKNOWN namespace to the namespace of the 
		 * external library if the extLib publishes a symbol with a matching name.
		 * 
		 * @param extLib  {@link ExtLibInfo} representing an external library
		 * @throws CancelledException if cancelled
		 */
		private void resolveSymbolsToLibrary(ExtLibInfo extLib) throws CancelledException {
			if (extLib.program == null) {
				// can't do anything if the external library doesn't have a valid program associated 
				return;
			}
			ExternalManager externalManager = program.getExternalManager();
			SymbolTable symbolTable = program.getSymbolTable();

			for (Iterator<Long> idIterator = unresolvedExternalFunctionIds.iterator(); idIterator
					.hasNext();) {
				monitor.checkCancelled();
				Symbol s = symbolTable.getSymbol(idIterator.next());
				if (s == null || !s.isExternal() || s.getSymbolType() != SymbolType.FUNCTION) {
					Msg.error(ExternalSymbolResolver.class,
						"Concurrent modification of symbol table while resolving external symbols");
					idIterator.remove();
					continue;
				}

				ExternalLocation extLoc = externalManager.getExternalLocation(s);
				String extLocName =
					Objects.requireNonNullElse(extLoc.getOriginalImportedName(), extLoc.getLabel());
				if (isExportedSymbol(extLib.program, extLocName)) {
					try {
						s.setNamespace(extLib.lib);
						idIterator.remove();
						extLib.resolvedSymbols.add(s.getName());
					}
					catch (DuplicateNameException | InvalidInputException
							| CircularDependencyException e) {
						Msg.error(ExternalSymbolResolver.class,
							"Error setting external symbol namespace for " + extLoc.getLabel(), e);
					}
				}
			}
		}

		/**
		 * Returns a list of all external functions under the EXTERNAL/UNKNOWN library.
		 * 
		 * @return list of func ids that need to be fixed
		 */
		private List<Long> getUnresolvedExternalFunctionIds() {
			List<Long> symbolIds = new ArrayList<>();
			ExternalManager externalManager = program.getExternalManager();
			Library library = externalManager.getExternalLibrary(Library.UNKNOWN);
			if (library != null) {
				for (Symbol s : program.getSymbolTable().getSymbols(library)) {
					if (s.getSymbolType() == SymbolType.FUNCTION &&
						s.getSource() != SourceType.DEFAULT) {
						symbolIds.add(s.getID());
					}
				}
			}
			return symbolIds;
		}

		/**
		 * Returns an ordered list of library names, as specified by the logic/rules of the original
		 * operating system's loader (eg. Elf / MachO dynamic library loading / symbol resolving
		 * rules)
		 *  
		 * @return list of library names, in original order
		 */
		private Collection<String> getOrderedRequiredLibraryNames() {
			TreeMap<Integer, String> orderLibraryMap = new TreeMap<>();
			Options options = program.getOptions(Program.PROGRAM_INFO);
			for (String optionName : options.getOptionNames()) {

				// Legacy programs may have the old "ELF Required Library [" program property, so 
				// we should not assume that the option name starts exactly with 
				// REQUIRED_LIBRARY_PROPERTY_PREFIX.  We must deal with a potential substring at the
				// start of the option name.
				int prefixIndex = optionName.indexOf(REQUIRED_LIBRARY_PROPERTY_PREFIX);
				if (prefixIndex == -1 || !optionName.endsWith("]")) {
					continue;
				}
				String libName = options.getString(optionName, null);
				if (libName == null) {
					continue;
				}
				String indexStr = optionName
						.substring(prefixIndex + REQUIRED_LIBRARY_PROPERTY_PREFIX.length(),
							optionName.length() - 1)
						.trim();
				try {
					orderLibraryMap.put(Integer.parseInt(indexStr), libName.trim());
				}
				catch (NumberFormatException e) {
					Msg.error(ExternalSymbolResolver.class,
						"Program contains invalid property: " + optionName);
				}
			}
			return orderLibraryMap.values();
		}

	}

	/**
	 * Returns true if the specified program publishes a symbol with the specified name.
	 * 
	 * @param program {@link Program}
	 * @param name symbol name
	 * @return true if program publishes a symbol the specified name
	 */
	private static boolean isExportedSymbol(Program program, String name) {

		for (Symbol s : program.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
			if (s.isExternalEntryPoint()) {
				return true;
			}
		}
		return false;
	}

}
